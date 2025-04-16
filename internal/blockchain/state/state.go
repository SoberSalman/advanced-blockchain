// internal/blockchain/state/state.go
package state

import (
	"bytes"
	"compress/zlib"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"sort"
	"sync"
	"time"

	"github.com/SoberSalman/advanced-blockchain/internal/types"
	"github.com/rs/zerolog/log"
)

const (
	// State management constants
	MaxStateSize       = 1024 * 1024 * 100 // 100 MB
	ArchivalThreshold  = 1000              // Number of blocks after which state is archived
	PruningThreshold   = 10000             // Number of blocks after which state is pruned
	CompactionInterval = 100               // How often to compact the state (in blocks)

	// Compression levels
	CompressionNone = 0
	CompressionFast = 1
	CompressionBest = 9

	// State types
	StateTypeFull     = 0
	StateTypeDelta    = 1
	StateTypeArchived = 2
)

// StateManager handles state operations
type StateManager struct {
	states          map[types.Hash]*StateData
	accounts        map[types.Address]*types.Account
	deltaStates     map[types.Hash]*DeltaState
	archivedStates  map[types.Hash]*ArchivedState
	stateRoots      map[uint64]types.Hash // Height -> StateRoot
	latestStateRoot types.Hash
	mu              sync.RWMutex
}

// StateData represents blockchain state data
type StateData struct {
	Root       types.Hash
	Height     uint64
	Timestamp  time.Time
	Accounts   map[types.Address]*types.Account
	ShardRoots map[uint64]types.Hash // ShardID -> StateRoot
	ForestRoot types.Hash
	Compressed bool
}

// DeltaState represents a delta (changes only) state
type DeltaState struct {
	Root             types.Hash
	PreviousRoot     types.Hash
	Height           uint64
	Timestamp        time.Time
	AddedAccounts    map[types.Address]*types.Account
	ModifiedAccounts map[types.Address]*types.Account
	DeletedAccounts  []types.Address
	CompressedData   []byte
}

// ArchivedState represents an archived state
type ArchivedState struct {
	Root             types.Hash
	Height           uint64
	Timestamp        time.Time
	CompressedData   []byte
	CompressionLevel int
	Hash             types.Hash // Hash of compressed data
	MetadataOnly     bool
}

// StateRef represents a reference to a state
type StateRef struct {
	Root       types.Hash
	Height     uint64
	Type       int
	AccessPath []types.Hash // Path to reconstruct state
}

// NewStateManager creates a new state manager
func NewStateManager() *StateManager {
	return &StateManager{
		states:         make(map[types.Hash]*StateData),
		accounts:       make(map[types.Address]*types.Account),
		deltaStates:    make(map[types.Hash]*DeltaState),
		archivedStates: make(map[types.Hash]*ArchivedState),
		stateRoots:     make(map[uint64]types.Hash),
	}
}

// CreateGenesisState creates the genesis state
func (sm *StateManager) CreateGenesisState() (types.Hash, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Create empty genesis state
	genesisState := &StateData{
		Height:     0,
		Timestamp:  time.Now(),
		Accounts:   make(map[types.Address]*types.Account),
		ShardRoots: make(map[uint64]types.Hash),
		ForestRoot: types.Hash{},
		Compressed: false,
	}

	// Calculate state root
	stateRoot, err := sm.calculateStateRoot(genesisState)
	if err != nil {
		return types.Hash{}, err
	}

	genesisState.Root = stateRoot

	// Store state
	sm.states[stateRoot] = genesisState
	sm.stateRoots[0] = stateRoot
	sm.latestStateRoot = stateRoot

	log.Info().
		Str("stateRoot", stateRoot.String()).
		Msg("Genesis state created")

	return stateRoot, nil
}

// UpdateState creates a new state based on previous state and transactions
func (sm *StateManager) UpdateState(
	previousStateRoot types.Hash,
	transactions []types.Transaction,
	height uint64,
) (types.Hash, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Get previous state
	previousState, exists := sm.states[previousStateRoot]
	if !exists {
		// Try to reconstruct from delta or archived states
		reconstructedState, err := sm.reconstructState(previousStateRoot)
		if err != nil {
			return types.Hash{}, errors.New("previous state not found")
		}
		previousState = reconstructedState
	}

	// Create new state data as a copy of previous state
	newState := &StateData{
		Height:     height,
		Timestamp:  time.Now(),
		Accounts:   make(map[types.Address]*types.Account),
		ShardRoots: make(map[uint64]types.Hash),
		ForestRoot: previousState.ForestRoot,
		Compressed: false,
	}

	// Copy accounts from previous state
	for addr, account := range previousState.Accounts {
		// Deep copy account
		newAccount := &types.Account{
			Address:     addr,
			Balance:     new(big.Int).Set(account.Balance),
			Nonce:       account.Nonce,
			StorageRoot: account.StorageRoot,
			CodeHash:    account.CodeHash,
			StorageTrie: make(map[types.Hash][]byte),
		}

		// Copy storage trie
		for key, value := range account.StorageTrie {
			newValue := make([]byte, len(value))
			copy(newValue, value)
			newAccount.StorageTrie[key] = newValue
		}

		newState.Accounts[addr] = newAccount
	}

	// Copy shard roots
	for shardID, root := range previousState.ShardRoots {
		newState.ShardRoots[shardID] = root
	}

	// Track state changes for delta state
	deltaState := &DeltaState{
		PreviousRoot:     previousStateRoot,
		Height:           height,
		Timestamp:        time.Now(),
		AddedAccounts:    make(map[types.Address]*types.Account),
		ModifiedAccounts: make(map[types.Address]*types.Account),
		DeletedAccounts:  make([]types.Address, 0),
	}

	// Apply transactions to the state
	for _, tx := range transactions {
		// Update sender account
		sender, exists := newState.Accounts[tx.From]
		if !exists {
			// Create new sender account if it doesn't exist
			sender = &types.Account{
				Address:     tx.From,
				Balance:     big.NewInt(0),
				Nonce:       0,
				StorageRoot: types.Hash{},
				CodeHash:    types.Hash{},
				StorageTrie: make(map[types.Hash][]byte),
			}
			newState.Accounts[tx.From] = sender
			deltaState.AddedAccounts[tx.From] = sender
		} else {
			// Mark as modified
			deltaState.ModifiedAccounts[tx.From] = sender
		}

		// Increment nonce
		sender.Nonce++

		// Deduct value from sender
		if tx.Value != nil && tx.Value.Sign() > 0 {
			// Check if sender has enough balance
			if sender.Balance.Cmp(tx.Value) < 0 {
				return types.Hash{}, errors.New("insufficient balance")
			}

			sender.Balance.Sub(sender.Balance, tx.Value)
		}

		// Update recipient account
		recipient, exists := newState.Accounts[tx.To]
		if !exists {
			// Create new recipient account
			recipient = &types.Account{
				Address:     tx.To,
				Balance:     big.NewInt(0),
				Nonce:       0,
				StorageRoot: types.Hash{},
				CodeHash:    types.Hash{},
				StorageTrie: make(map[types.Hash][]byte),
			}
			newState.Accounts[tx.To] = recipient
			deltaState.AddedAccounts[tx.To] = recipient
		} else {
			// Mark as modified
			deltaState.ModifiedAccounts[tx.To] = recipient
		}

		// Add value to recipient
		if tx.Value != nil && tx.Value.Sign() > 0 {
			recipient.Balance.Add(recipient.Balance, tx.Value)
		}

		// Handle contract data (if present)
		if len(tx.Data) > 0 {
			// This is simplified; a real implementation would execute contract code
			// For demonstration, we'll store the data in the account's storage
			dataKey := sha256.Sum256(tx.Data)
			recipient.StorageTrie[dataKey] = tx.Data

			// Update storage root
			storageRoot, err := sm.calculateStorageTrie(recipient.StorageTrie)
			if err != nil {
				return types.Hash{}, err
			}
			recipient.StorageRoot = storageRoot
		}
	}

	// Calculate new state root
	stateRoot, err := sm.calculateStateRoot(newState)
	if err != nil {
		return types.Hash{}, err
	}

	newState.Root = stateRoot
	deltaState.Root = stateRoot

	// Store new state
	sm.states[stateRoot] = newState
	sm.stateRoots[height] = stateRoot
	sm.latestStateRoot = stateRoot

	// Store delta state
	sm.deltaStates[stateRoot] = deltaState

	// Check if we need to compact old states
	if height%CompactionInterval == 0 {
		sm.compactOldStates(height)
	}

	log.Info().
		Str("stateRoot", stateRoot.String()).
		Uint64("height", height).
		Int("txCount", len(transactions)).
		Msg("State updated")

	return stateRoot, nil
}

// GetAccount retrieves an account from the current state
func (sm *StateManager) GetAccount(address types.Address) (*types.Account, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	latestState, exists := sm.states[sm.latestStateRoot]
	if !exists {
		return nil, errors.New("latest state not found")
	}

	account, exists := latestState.Accounts[address]
	if !exists {
		return nil, errors.New("account not found")
	}

	// Return a deep copy to prevent concurrent modification
	accountCopy := &types.Account{
		Address:     account.Address,
		Balance:     new(big.Int).Set(account.Balance),
		Nonce:       account.Nonce,
		StorageRoot: account.StorageRoot,
		CodeHash:    account.CodeHash,
		StorageTrie: make(map[types.Hash][]byte),
	}

	// Copy storage trie
	for key, value := range account.StorageTrie {
		newValue := make([]byte, len(value))
		copy(newValue, value)
		accountCopy.StorageTrie[key] = newValue
	}

	return accountCopy, nil
}

// GetAccountAtState retrieves an account from a specific state
func (sm *StateManager) GetAccountAtState(stateRoot types.Hash, address types.Address) (*types.Account, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	state, exists := sm.states[stateRoot]
	if !exists {
		// Try to reconstruct the state
		reconstructedState, err := sm.reconstructState(stateRoot)
		if err != nil {
			return nil, errors.New("state not found")
		}
		state = reconstructedState
	}

	account, exists := state.Accounts[address]
	if !exists {
		return nil, errors.New("account not found in state")
	}

	// Return a deep copy
	accountCopy := &types.Account{
		Address:     account.Address,
		Balance:     new(big.Int).Set(account.Balance),
		Nonce:       account.Nonce,
		StorageRoot: account.StorageRoot,
		CodeHash:    account.CodeHash,
		StorageTrie: make(map[types.Hash][]byte),
	}

	for key, value := range account.StorageTrie {
		newValue := make([]byte, len(value))
		copy(newValue, value)
		accountCopy.StorageTrie[key] = newValue
	}

	return accountCopy, nil
}

// GetStateRoot gets the state root for a specific height
func (sm *StateManager) GetStateRoot(height uint64) (types.Hash, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	stateRoot, exists := sm.stateRoots[height]
	if !exists {
		return types.Hash{}, errors.New("state root not found for height")
	}

	return stateRoot, nil
}

// GetLatestStateRoot gets the latest state root
func (sm *StateManager) GetLatestStateRoot() types.Hash {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	return sm.latestStateRoot
}

// compactOldStates compresses and/or archives old states
func (sm *StateManager) compactOldStates(currentHeight uint64) {
	// Archive states that are beyond the archival threshold
	archivalHeight := uint64(0)
	if currentHeight > ArchivalThreshold {
		archivalHeight = currentHeight - ArchivalThreshold
	}

	// Prune states that are beyond the pruning threshold
	pruningHeight := uint64(0)
	if currentHeight > PruningThreshold {
		pruningHeight = currentHeight - PruningThreshold
	}

	// Process each height
	for height, stateRoot := range sm.stateRoots {
		// Skip current state
		if height == currentHeight {
			continue
		}

		// Archive old states
		if height < archivalHeight {
			// Check if state is not already archived
			if _, exists := sm.archivedStates[stateRoot]; !exists {
				// Get the state
				state, exists := sm.states[stateRoot]
				if exists {
					// Archive the state
					err := sm.archiveState(state)
					if err != nil {
						log.Error().
							Err(err).
							Str("stateRoot", stateRoot.String()).
							Uint64("height", height).
							Msg("Failed to archive state")
						continue
					}

					// If successful, remove the full state to save memory
					delete(sm.states, stateRoot)

					log.Debug().
						Str("stateRoot", stateRoot.String()).
						Uint64("height", height).
						Msg("State archived")
				}
			}
		}

		// Prune very old states
		if height < pruningHeight {
			// Remove delta states to save memory
			delete(sm.deltaStates, stateRoot)

			// For archived states, keep only metadata
			if archivedState, exists := sm.archivedStates[stateRoot]; exists && !archivedState.MetadataOnly {
				// Create metadata-only version
				metadataState := &ArchivedState{
					Root:             archivedState.Root,
					Height:           archivedState.Height,
					Timestamp:        archivedState.Timestamp,
					CompressedData:   nil, // No data
					CompressionLevel: archivedState.CompressionLevel,
					Hash:             archivedState.Hash,
					MetadataOnly:     true,
				}

				sm.archivedStates[stateRoot] = metadataState

				log.Debug().
					Str("stateRoot", stateRoot.String()).
					Uint64("height", height).
					Msg("State pruned to metadata-only")
			}
		}
	}
}

// archiveState archives a state by compressing it
func (sm *StateManager) archiveState(state *StateData) error {
	// Serialize state data
	var stateBuffer bytes.Buffer

	// Write basic state info
	binary.Write(&stateBuffer, binary.BigEndian, state.Height)
	binary.Write(&stateBuffer, binary.BigEndian, state.Timestamp.Unix())

	// Write number of accounts
	binary.Write(&stateBuffer, binary.BigEndian, uint64(len(state.Accounts)))

	// Write each account
	for addr, account := range state.Accounts {
		// Write address
		stateBuffer.Write(addr[:])

		// Write balance
		balanceBytes := account.Balance.Bytes()
		binary.Write(&stateBuffer, binary.BigEndian, uint64(len(balanceBytes)))
		stateBuffer.Write(balanceBytes)

		// Write nonce
		binary.Write(&stateBuffer, binary.BigEndian, account.Nonce)

		// Write storage root
		stateBuffer.Write(account.StorageRoot[:])

		// Write code hash
		stateBuffer.Write(account.CodeHash[:])

		// Write storage trie
		binary.Write(&stateBuffer, binary.BigEndian, uint64(len(account.StorageTrie)))
		for key, value := range account.StorageTrie {
			// Write key
			stateBuffer.Write(key[:])

			// Write value length
			binary.Write(&stateBuffer, binary.BigEndian, uint64(len(value)))

			// Write value
			stateBuffer.Write(value)
		}
	}

	// Write shard roots
	binary.Write(&stateBuffer, binary.BigEndian, uint64(len(state.ShardRoots)))
	for shardID, root := range state.ShardRoots {
		binary.Write(&stateBuffer, binary.BigEndian, shardID)
		stateBuffer.Write(root[:])
	}

	// Write forest root
	stateBuffer.Write(state.ForestRoot[:])

	// Compress the data
	var compressedBuffer bytes.Buffer
	writer, err := zlib.NewWriterLevel(&compressedBuffer, CompressionBest)
	if err != nil {
		return err
	}

	_, err = writer.Write(stateBuffer.Bytes())
	if err != nil {
		return err
	}

	err = writer.Close()
	if err != nil {
		return err
	}

	// Calculate hash of compressed data
	dataHash := sha256.Sum256(compressedBuffer.Bytes())

	// Create archived state
	archivedState := &ArchivedState{
		Root:             state.Root,
		Height:           state.Height,
		Timestamp:        state.Timestamp,
		CompressedData:   compressedBuffer.Bytes(),
		CompressionLevel: CompressionBest,
		Hash:             dataHash,
		MetadataOnly:     false,
	}

	// Store in archived states
	sm.archivedStates[state.Root] = archivedState

	return nil
}

// reconstructState reconstructs a state from delta or archived states
func (sm *StateManager) reconstructState(stateRoot types.Hash) (*StateData, error) {
	// First, check if it's in delta states
	if deltaState, exists := sm.deltaStates[stateRoot]; exists {
		// Get the previous state
		previousState, err := sm.getStateByRoot(deltaState.PreviousRoot)
		if err != nil {
			return nil, err
		}

		// Apply delta changes to create the reconstructed state
		reconstructedState := &StateData{
			Root:       stateRoot,
			Height:     deltaState.Height,
			Timestamp:  deltaState.Timestamp,
			Accounts:   make(map[types.Address]*types.Account),
			ShardRoots: make(map[uint64]types.Hash),
			ForestRoot: previousState.ForestRoot,
			Compressed: false,
		}

		// Copy accounts from previous state
		for addr, account := range previousState.Accounts {
			// Skip accounts that will be deleted
			isDeleted := false
			for _, deletedAddr := range deltaState.DeletedAccounts {
				if addr == deletedAddr {
					isDeleted = true
					break
				}
			}

			if isDeleted {
				continue
			}

			// Check if account is modified in delta
			if modifiedAccount, isModified := deltaState.ModifiedAccounts[addr]; isModified {
				// Use the modified account
				reconstructedState.Accounts[addr] = modifiedAccount
			} else {
				// Deep copy account from previous state
				newAccount := &types.Account{
					Address:     addr,
					Balance:     new(big.Int).Set(account.Balance),
					Nonce:       account.Nonce,
					StorageRoot: account.StorageRoot,
					CodeHash:    account.CodeHash,
					StorageTrie: make(map[types.Hash][]byte),
				}

				// Copy storage trie
				for key, value := range account.StorageTrie {
					newValue := make([]byte, len(value))
					copy(newValue, value)
					newAccount.StorageTrie[key] = newValue
				}

				reconstructedState.Accounts[addr] = newAccount
			}
		}

		// Add new accounts from delta
		for addr, account := range deltaState.AddedAccounts {
			// Deep copy account
			newAccount := &types.Account{
				Address:     addr,
				Balance:     new(big.Int).Set(account.Balance),
				Nonce:       account.Nonce,
				StorageRoot: account.StorageRoot,
				CodeHash:    account.CodeHash,
				StorageTrie: make(map[types.Hash][]byte),
			}

			// Copy storage trie
			for key, value := range account.StorageTrie {
				newValue := make([]byte, len(value))
				copy(newValue, value)
				newAccount.StorageTrie[key] = newValue
			}

			reconstructedState.Accounts[addr] = newAccount
		}

		// Copy shard roots from previous state
		for shardID, root := range previousState.ShardRoots {
			reconstructedState.ShardRoots[shardID] = root
		}

		return reconstructedState, nil
	}

	// Next, check if it's in archived states
	if archivedState, exists := sm.archivedStates[stateRoot]; exists {
		if archivedState.MetadataOnly {
			return nil, errors.New("state has been pruned to metadata-only")
		}

		// Decompress the data
		compressedData := archivedState.CompressedData

		// Verify hash
		dataHash := sha256.Sum256(compressedData)
		if dataHash != archivedState.Hash {
			return nil, errors.New("archived state data is corrupted")
		}

		// Create reader for decompression
		compressedReader := bytes.NewReader(compressedData)
		zlibReader, err := zlib.NewReader(compressedReader)
		if err != nil {
			return nil, err
		}
		defer zlibReader.Close()

		// Read decompressed data
		var decompressedData bytes.Buffer
		_, err = io.Copy(&decompressedData, zlibReader)
		if err != nil {
			return nil, err
		}

		// Deserialize state data
		dataBytes := decompressedData.Bytes()
		reader := bytes.NewReader(dataBytes)

		// Create reconstructed state
		reconstructedState := &StateData{
			Root:       stateRoot,
			Accounts:   make(map[types.Address]*types.Account),
			ShardRoots: make(map[uint64]types.Hash),
			Compressed: false,
		}

		// Read basic state info
		var height uint64
		var timestamp int64
		binary.Read(reader, binary.BigEndian, &height)
		binary.Read(reader, binary.BigEndian, &timestamp)

		reconstructedState.Height = height
		reconstructedState.Timestamp = time.Unix(timestamp, 0)

		// Read accounts
		var accountCount uint64
		binary.Read(reader, binary.BigEndian, &accountCount)

		for i := uint64(0); i < accountCount; i++ {
			// Read address
			var addr types.Address
			reader.Read(addr[:])

			// Read balance
			var balanceSize uint64
			binary.Read(reader, binary.BigEndian, &balanceSize)
			balanceBytes := make([]byte, balanceSize)
			reader.Read(balanceBytes)
			balance := new(big.Int).SetBytes(balanceBytes)

			// Read nonce
			var nonce uint64
			binary.Read(reader, binary.BigEndian, &nonce)

			// Read storage root
			var storageRoot types.Hash
			reader.Read(storageRoot[:])

			// Read code hash
			var codeHash types.Hash
			reader.Read(codeHash[:])

			// Create account
			account := &types.Account{
				Address:     addr,
				Balance:     balance,
				Nonce:       nonce,
				StorageRoot: storageRoot,
				CodeHash:    codeHash,
				StorageTrie: make(map[types.Hash][]byte),
			}

			// Read storage trie
			var storageCount uint64
			binary.Read(reader, binary.BigEndian, &storageCount)

			for j := uint64(0); j < storageCount; j++ {
				// Read key
				var key types.Hash
				reader.Read(key[:])

				// Read value
				var valueSize uint64
				binary.Read(reader, binary.BigEndian, &valueSize)
				value := make([]byte, valueSize)
				reader.Read(value)

				account.StorageTrie[key] = value
			}

			reconstructedState.Accounts[addr] = account
		}

		// Read shard roots
		var shardCount uint64
		binary.Read(reader, binary.BigEndian, &shardCount)

		for i := uint64(0); i < shardCount; i++ {
			var shardID uint64
			binary.Read(reader, binary.BigEndian, &shardID)

			var root types.Hash
			reader.Read(root[:])

			reconstructedState.ShardRoots[shardID] = root
		}

		// Read forest root
		reader.Read(reconstructedState.ForestRoot[:])

		return reconstructedState, nil
	}

	return nil, errors.New("state not found")
}

// getStateByRoot gets a state by its root, trying full states first
func (sm *StateManager) getStateByRoot(stateRoot types.Hash) (*StateData, error) {
	// Check full states
	if state, exists := sm.states[stateRoot]; exists {
		return state, nil
	}

	// Try to reconstruct
	return sm.reconstructState(stateRoot)
}

// calculateStateRoot calculates the Merkle root of a state
func (sm *StateManager) calculateStateRoot(state *StateData) (types.Hash, error) {
	// Create a buffer for all account hashes
	var buffer bytes.Buffer

	// Sort account addresses for deterministic order
	addresses := make([]types.Address, 0, len(state.Accounts))
	for addr := range state.Accounts {
		addresses = append(addresses, addr)
	}
	sort.Slice(addresses, func(i, j int) bool {
		return bytes.Compare(addresses[i][:], addresses[j][:]) < 0
	})

	// Hash each account and add to buffer
	for _, addr := range addresses {
		account := state.Accounts[addr]

		// Create account hash
		var accountBuffer bytes.Buffer
		accountBuffer.Write(addr[:])
		accountBuffer.Write(account.Balance.Bytes())
		binary.Write(&accountBuffer, binary.BigEndian, account.Nonce)
		accountBuffer.Write(account.StorageRoot[:])
		accountBuffer.Write(account.CodeHash[:])

		accountHash := sha256.Sum256(accountBuffer.Bytes())
		buffer.Write(accountHash[:])
	}

	// Hash shard roots
	var shardBuffer bytes.Buffer
	for shardID, root := range state.ShardRoots {
		binary.Write(&shardBuffer, binary.BigEndian, shardID)
		shardBuffer.Write(root[:])
	}
	shardHash := sha256.Sum256(shardBuffer.Bytes())
	buffer.Write(shardHash[:])

	// Add forest root
	buffer.Write(state.ForestRoot[:])

	// Calculate final hash
	stateRoot := sha256.Sum256(buffer.Bytes())

	return stateRoot, nil
}

// calculateStorageTrie calculates the Merkle root of a storage trie
func (sm *StateManager) calculateStorageTrie(storageTrie map[types.Hash][]byte) (types.Hash, error) {
	// Sort keys for deterministic order
	keys := make([]types.Hash, 0, len(storageTrie))
	for key := range storageTrie {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		return bytes.Compare(keys[i][:], keys[j][:]) < 0
	})

	// Hash each key-value pair
	var buffer bytes.Buffer
	for _, key := range keys {
		value := storageTrie[key]

		// Hash key-value pair
		var pairBuffer bytes.Buffer
		pairBuffer.Write(key[:])
		pairBuffer.Write(value)

		pairHash := sha256.Sum256(pairBuffer.Bytes())
		buffer.Write(pairHash[:])
	}

	// If empty, return empty hash
	if len(storageTrie) == 0 {
		return types.Hash{}, nil
	}

	// Calculate final hash
	storageRoot := sha256.Sum256(buffer.Bytes())

	return storageRoot, nil
}

// EstimateStateSize estimates the size of a state in bytes
func (sm *StateManager) EstimateStateSize(stateRoot types.Hash) (int, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	// Check if state exists
	state, exists := sm.states[stateRoot]
	if !exists {
		return 0, errors.New("state not found")
	}

	// Basic state structure size
	size := 100 // Approximate fixed size

	// Account sizes
	for _, account := range state.Accounts {
		// Basic account structure
		accountSize := 128 // Approximate fixed size

		// Balance size
		if account.Balance != nil {
			accountSize += len(account.Balance.Bytes())
		}

		// Storage trie size
		for _, value := range account.StorageTrie {
			accountSize += 32 // Key size
			accountSize += len(value)
		}

		size += accountSize
	}

	// Shard roots size
	size += len(state.ShardRoots) * 40 // ShardID + Root hash

	return size, nil
}

// CompressState compresses a state without archiving it
func (sm *StateManager) CompressState(stateRoot types.Hash) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	state, exists := sm.states[stateRoot]
	if !exists {
		return errors.New("state not found")
	}

	// If already compressed, do nothing
	if state.Compressed {
		return nil
	}

	// Archive the state (creates compressed version)
	err := sm.archiveState(state)
	if err != nil {
		return err
	}

	// Mark as compressed
	state.Compressed = true

	return nil
}

// GetStateStats returns statistics about managed states
func (sm *StateManager) GetStateStats() map[string]int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	stats := make(map[string]int)
	stats["full_states"] = len(sm.states)
	stats["delta_states"] = len(sm.deltaStates)
	stats["archived_states"] = len(sm.archivedStates)

	// Count metadata-only archives
	metadataOnly := 0
	for _, state := range sm.archivedStates {
		if state.MetadataOnly {
			metadataOnly++
		}
	}
	stats["metadata_only"] = metadataOnly

	return stats
}

// PruneState prunes a specific state and its dependencies
func (sm *StateManager) PruneState(stateRoot types.Hash) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Check if state exists
	_, exists := sm.states[stateRoot]
	if !exists {
		return errors.New("state not found")
	}

	// Remove full state
	delete(sm.states, stateRoot)

	// If delta state exists, remove it
	delete(sm.deltaStates, stateRoot)

	// If archived state exists, convert to metadata-only
	if archivedState, exists := sm.archivedStates[stateRoot]; exists && !archivedState.MetadataOnly {
		// Create metadata-only version
		metadataState := &ArchivedState{
			Root:             archivedState.Root,
			Height:           archivedState.Height,
			Timestamp:        archivedState.Timestamp,
			CompressedData:   nil, // No data
			CompressionLevel: archivedState.CompressionLevel,
			Hash:             archivedState.Hash,
			MetadataOnly:     true,
		}

		sm.archivedStates[stateRoot] = metadataState
	}

	return nil
}

// CreateCheckpoint creates a full checkpoint of the current state
func (sm *StateManager) CreateCheckpoint() (types.Hash, error) {
	sm.mu.RLock()
	latestStateRoot := sm.latestStateRoot
	sm.mu.RUnlock()

	// Ensure the latest state is fully saved (not compressed or archived)
	state, exists := sm.states[latestStateRoot]
	if !exists {
		return types.Hash{}, errors.New("latest state not found")
	}

	// If compressed, uncompress
	if state.Compressed {
		// Reconstruct the state
		reconstructedState, err := sm.reconstructState(latestStateRoot)
		if err != nil {
			return types.Hash{}, err
		}

		// Update the states map with full version
		sm.mu.Lock()
		sm.states[latestStateRoot] = reconstructedState
		sm.mu.Unlock()
	}

	return latestStateRoot, nil
}

// RestoreCheckpoint restores the state to a previously created checkpoint
func (sm *StateManager) RestoreCheckpoint(checkpointRoot types.Hash) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Check if checkpoint exists
	_, exists := sm.states[checkpointRoot]
	if !exists {
		// Try to reconstruct
		reconstructedState, err := sm.reconstructState(checkpointRoot)
		if err != nil {
			return errors.New("checkpoint not found")
		}

		// Save reconstructed state
		sm.states[checkpointRoot] = reconstructedState
	}

	// Set as latest state
	sm.latestStateRoot = checkpointRoot

	// Find height for the checkpoint
	height := uint64(0)
	for h, root := range sm.stateRoots {
		if root == checkpointRoot {
			height = h
			break
		}
	}

	log.Info().
		Str("checkpointRoot", checkpointRoot.String()).
		Uint64("height", height).
		Msg("State restored to checkpoint")

	return nil
}

// GetStateHistory gets a list of state references in chronological order
func (sm *StateManager) GetStateHistory(startHeight, endHeight uint64) ([]*StateRef, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	refs := make([]*StateRef, 0)

	// Collect state roots for each height in the range
	for height := startHeight; height <= endHeight; height++ {
		stateRoot, exists := sm.stateRoots[height]
		if !exists {
			continue
		}

		var stateType int
		if _, exists := sm.states[stateRoot]; exists {
			stateType = StateTypeFull
		} else if _, exists := sm.deltaStates[stateRoot]; exists {
			stateType = StateTypeDelta
		} else if archiveState, exists := sm.archivedStates[stateRoot]; exists {
			if archiveState.MetadataOnly {
				stateType = StateTypeArchived | 0x10 // Flag for metadata-only
			} else {
				stateType = StateTypeArchived
			}
		} else {
			continue // Skip unknown state types
		}

		// Create reference
		ref := &StateRef{
			Root:   stateRoot,
			Height: height,
			Type:   stateType,
		}

		// If delta state, add access path
		if stateType == StateTypeDelta {
			if deltaState, exists := sm.deltaStates[stateRoot]; exists {
				// Start with previous root
				path := []types.Hash{deltaState.PreviousRoot}

				// Try to find a path back to a full state
				currentRoot := deltaState.PreviousRoot
				visited := make(map[types.Hash]bool)
				visited[stateRoot] = true

				// Limit path length to avoid cycles
				for i := 0; i < 10; i++ {
					if _, exists := sm.states[currentRoot]; exists {
						// Found a full state
						break
					}

					if visited[currentRoot] {
						// Cycle detected
						break
					}
					visited[currentRoot] = true

					if prevDelta, exists := sm.deltaStates[currentRoot]; exists {
						// Add previous root to path
						path = append(path, prevDelta.PreviousRoot)
						currentRoot = prevDelta.PreviousRoot
					} else {
						// Can't go further
						break
					}
				}

				ref.AccessPath = path
			}
		}

		refs = append(refs, ref)
	}

	// Sort by height
	sort.Slice(refs, func(i, j int) bool {
		return refs[i].Height < refs[j].Height
	})

	return refs, nil
}

// MergeState merges an external state into the current state
func (sm *StateManager) MergeState(externalStateRoot types.Hash, externalState *StateData) (types.Hash, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Get current state
	currentState, exists := sm.states[sm.latestStateRoot]
	if !exists {
		return types.Hash{}, errors.New("current state not found")
	}

	// Create new merged state
	mergedState := &StateData{
		Height:     currentState.Height,
		Timestamp:  time.Now(),
		Accounts:   make(map[types.Address]*types.Account),
		ShardRoots: make(map[uint64]types.Hash),
		ForestRoot: currentState.ForestRoot,
		Compressed: false,
	}

	// Copy accounts from current state
	for addr, account := range currentState.Accounts {
		// Deep copy account
		newAccount := &types.Account{
			Address:     addr,
			Balance:     new(big.Int).Set(account.Balance),
			Nonce:       account.Nonce,
			StorageRoot: account.StorageRoot,
			CodeHash:    account.CodeHash,
			StorageTrie: make(map[types.Hash][]byte),
		}

		// Copy storage trie
		for key, value := range account.StorageTrie {
			newValue := make([]byte, len(value))
			copy(newValue, value)
			newAccount.StorageTrie[key] = newValue
		}

		mergedState.Accounts[addr] = newAccount
	}

	// Merge accounts from external state
	for addr, extAccount := range externalState.Accounts {
		// If account exists in current state, merge
		if currAccount, exists := mergedState.Accounts[addr]; exists {
			// For simplicity, take the higher nonce, sum balances
			if extAccount.Nonce > currAccount.Nonce {
				currAccount.Nonce = extAccount.Nonce
			}

			currAccount.Balance.Add(currAccount.Balance, extAccount.Balance)

			// Merge storage tries (external values override)
			for key, value := range extAccount.StorageTrie {
				newValue := make([]byte, len(value))
				copy(newValue, value)
				currAccount.StorageTrie[key] = newValue
			}

			// Recalculate storage root
			storageRoot, err := sm.calculateStorageTrie(currAccount.StorageTrie)
			if err != nil {
				return types.Hash{}, err
			}
			currAccount.StorageRoot = storageRoot
		} else {
			// Account doesn't exist in current state, add it
			newAccount := &types.Account{
				Address:     addr,
				Balance:     new(big.Int).Set(extAccount.Balance),
				Nonce:       extAccount.Nonce,
				StorageRoot: extAccount.StorageRoot,
				CodeHash:    extAccount.CodeHash,
				StorageTrie: make(map[types.Hash][]byte),
			}

			// Copy storage trie
			for key, value := range extAccount.StorageTrie {
				newValue := make([]byte, len(value))
				copy(newValue, value)
				newAccount.StorageTrie[key] = newValue
			}

			mergedState.Accounts[addr] = newAccount
		}
	}

	// Merge shard roots (external state takes precedence for conflicts)
	for shardID, root := range currentState.ShardRoots {
		mergedState.ShardRoots[shardID] = root
	}

	for shardID, root := range externalState.ShardRoots {
		mergedState.ShardRoots[shardID] = root
	}

	// Calculate merged state root
	mergedStateRoot, err := sm.calculateStateRoot(mergedState)
	if err != nil {
		return types.Hash{}, err
	}

	mergedState.Root = mergedStateRoot

	// Store merged state
	sm.states[mergedStateRoot] = mergedState
	sm.latestStateRoot = mergedStateRoot

	// Create a new height entry for this merged state
	newHeight := currentState.Height + 1
	sm.stateRoots[newHeight] = mergedStateRoot

	log.Info().
		Str("mergedStateRoot", mergedStateRoot.String()).
		Str("currentStateRoot", sm.latestStateRoot.String()).
		Str("externalStateRoot", externalStateRoot.String()).
		Uint64("newHeight", newHeight).
		Msg("States merged successfully")

	return mergedStateRoot, nil
}

// Close cleans up resources
func (sm *StateManager) Close() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Clear maps to free memory
	sm.states = nil
	sm.deltaStates = nil
	sm.archivedStates = nil
	sm.stateRoots = nil
}
