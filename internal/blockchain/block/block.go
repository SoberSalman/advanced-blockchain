// internal/blockchain/block/block.go
package block

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
	"time"

	"github.com/SoberSalman/advanced-blockchain/internal/types"
	"github.com/rs/zerolog/log"
)

const (
	// Block structure constants
	MaxBlockSize        = 1024 * 1024 * 2 // 2 MB
	MaxTransactionCount = 10000
	AccumulatorKeySize  = 32

	// Validation constants
	MinEntropyScore = 0.3
	MaxEntropyScore = 0.9
)

// BlockManager handles advanced block operations
type BlockManager struct {
	blocks       map[types.Hash]*types.Block
	stateRoots   map[types.Hash]types.Hash // BlockHash -> StateRoot
	accumulators map[types.Hash]*Accumulator
	latestBlock  *types.Block
}

// Accumulator represents a cryptographic accumulator for compact state representation
type Accumulator struct {
	Value     []byte
	Elements  map[string]bool
	BlockHash types.Hash
}

// NewBlockManager creates a new block manager
func NewBlockManager() *BlockManager {
	return &BlockManager{
		blocks:       make(map[types.Hash]*types.Block),
		stateRoots:   make(map[types.Hash]types.Hash),
		accumulators: make(map[types.Hash]*Accumulator),
		latestBlock:  nil,
	}
}

// CreateBlock creates a new block
func (bm *BlockManager) CreateBlock(
	height uint64,
	previousHash types.Hash,
	stateRoot types.Hash,
	receiptRoot types.Hash,
	transactions []types.Transaction,
	shardID uint64,
	forestRoot types.Hash,
	consensusData []byte,
	vrfProof []byte,
	zkProofs [][]byte,
) (*types.Block, error) {
	// Validate inputs
	if len(transactions) > MaxTransactionCount {
		return nil, errors.New("too many transactions")
	}

	// Build new block
	block := &types.Block{
		Header: types.Header{
			Version:         1,
			PreviousHash:    previousHash,
			MerkleRoot:      types.Hash{}, // Will be calculated
			StateRoot:       stateRoot,
			ReceiptsRoot:    receiptRoot,
			Timestamp:       time.Now(),
			Height:          height,
			Difficulty:      nil, // Will be determined by consensus
			Nonce:           0,   // Will be determined by consensus
			ShardID:         shardID,
			ForestRoot:      forestRoot,
			ConsensusData:   consensusData,
			VRFProof:        vrfProof,
			ZKProofHash:     types.Hash{}, // Will be calculated
			AccumulatorRoot: types.Hash{}, // Will be calculated
		},
		Transactions: transactions,
		Signature:    nil, // Will be set later
		BFTProof:     nil, // Will be set later
		ShardInfo:    nil, // Will be set later
		ZKProofs:     zkProofs,
		VectorClock:  make(map[uint64]uint64),
		EntropyScore: 0, // Will be calculated
	}

	// Calculate Merkle root
	merkleRoot, err := bm.calculateMerkleRoot(transactions)
	if err != nil {
		return nil, err
	}
	block.Header.MerkleRoot = merkleRoot

	// Calculate ZK proofs hash
	zkProofsHash, err := bm.calculateZKProofsHash(zkProofs)
	if err != nil {
		return nil, err
	}
	block.Header.ZKProofHash = zkProofsHash

	// Create cryptographic accumulator
	accumulator, err := bm.createAccumulator(transactions, stateRoot)
	if err != nil {
		return nil, err
	}
	block.Header.AccumulatorRoot = bm.getAccumulatorHash(accumulator)

	// Calculate entropy score
	entropyScore := bm.calculateEntropyScore(block)
	block.EntropyScore = entropyScore

	// Validate entropy score
	if entropyScore < MinEntropyScore || entropyScore > MaxEntropyScore {
		log.Warn().
			Float64("entropy", entropyScore).
			Uint64("height", height).
			Msg("Block entropy score outside recommended range")
	}

	return block, nil
}

// AddBlock adds a block to the blockchain
func (bm *BlockManager) AddBlock(block *types.Block) error {
	// Calculate block hash
	blockHash, err := bm.CalculateBlockHash(block)
	if err != nil {
		return err
	}

	// Validate block
	if err := bm.ValidateBlock(block); err != nil {
		return err
	}

	// Store block
	bm.blocks[blockHash] = block
	bm.stateRoots[blockHash] = block.Header.StateRoot

	// Store accumulator
	accumulator, err := bm.createAccumulator(block.Transactions, block.Header.StateRoot)
	if err != nil {
		return err
	}
	bm.accumulators[blockHash] = accumulator

	// Update latest block
	if bm.latestBlock == nil || block.Header.Height > bm.latestBlock.Header.Height {
		bm.latestBlock = block
	}

	log.Info().
		Str("blockHash", blockHash.String()).
		Uint64("height", block.Header.Height).
		Int("txCount", len(block.Transactions)).
		Msg("Block added to blockchain")

	return nil
}

// CalculateBlockHash calculates the hash of a block
func (bm *BlockManager) CalculateBlockHash(block *types.Block) (types.Hash, error) {
	// Create header bytes
	var buffer bytes.Buffer

	// Write header fields
	binary.Write(&buffer, binary.BigEndian, block.Header.Version)
	buffer.Write(block.Header.PreviousHash[:])
	buffer.Write(block.Header.MerkleRoot[:])
	buffer.Write(block.Header.StateRoot[:])
	buffer.Write(block.Header.ReceiptsRoot[:])

	// Write timestamp as nanoseconds
	binary.Write(&buffer, binary.BigEndian, block.Header.Timestamp.UnixNano())

	// Write other fields
	binary.Write(&buffer, binary.BigEndian, block.Header.Height)
	if block.Header.Difficulty != nil {
		difficultyBytes := block.Header.Difficulty.Bytes()
		buffer.Write(difficultyBytes)
	}
	binary.Write(&buffer, binary.BigEndian, block.Header.Nonce)
	binary.Write(&buffer, binary.BigEndian, block.Header.ShardID)
	buffer.Write(block.Header.ForestRoot[:])
	buffer.Write(block.Header.ConsensusData)
	buffer.Write(block.Header.VRFProof)
	buffer.Write(block.Header.ZKProofHash[:])
	buffer.Write(block.Header.AccumulatorRoot[:])

	// Calculate hash
	hash := sha256.Sum256(buffer.Bytes())

	return hash, nil
}

// ValidateBlock validates a block
func (bm *BlockManager) ValidateBlock(block *types.Block) error {
	// Validate block size
	blockSize := bm.estimateBlockSize(block)
	if blockSize > MaxBlockSize {
		return errors.New("block exceeds maximum size")
	}

	// Validate transaction count
	if len(block.Transactions) > MaxTransactionCount {
		return errors.New("block contains too many transactions")
	}

	// Validate Merkle root
	calculatedMerkleRoot, err := bm.calculateMerkleRoot(block.Transactions)
	if err != nil {
		return err
	}
	if calculatedMerkleRoot != block.Header.MerkleRoot {
		return errors.New("invalid merkle root")
	}

	// Validate ZK proofs hash
	calculatedZKProofHash, err := bm.calculateZKProofsHash(block.ZKProofs)
	if err != nil {
		return err
	}
	if calculatedZKProofHash != block.Header.ZKProofHash {
		return errors.New("invalid ZK proofs hash")
	}

	// Validate entropy score
	entropyScore := bm.calculateEntropyScore(block)
	if math.Abs(entropyScore-block.EntropyScore) > 0.01 {
		return errors.New("invalid entropy score")
	}

	// Validate previous block (if not genesis)
	if block.Header.Height > 0 {
		if bm.GetBlockByHash(block.Header.PreviousHash) == nil {
			return errors.New("previous block not found")
		}
	}

	return nil
}

// GetBlockByHash retrieves a block by its hash
func (bm *BlockManager) GetBlockByHash(hash types.Hash) *types.Block {
	block, exists := bm.blocks[hash]
	if !exists {
		return nil
	}
	return block
}

// GetBlockByHeight retrieves a block by its height
// Note: This is inefficient for many blocks; in production, use an index
func (bm *BlockManager) GetBlockByHeight(height uint64) *types.Block {
	for _, block := range bm.blocks {
		if block.Header.Height == height {
			return block
		}
	}
	return nil
}

// GetLatestBlock returns the latest block in the chain
func (bm *BlockManager) GetLatestBlock() *types.Block {
	return bm.latestBlock
}

// calculateMerkleRoot calculates the Merkle root of transactions
func (bm *BlockManager) calculateMerkleRoot(transactions []types.Transaction) (types.Hash, error) {
	if len(transactions) == 0 {
		// Empty Merkle root
		return types.Hash{}, nil
	}

	// Calculate transaction hashes
	hashes := make([]types.Hash, len(transactions))
	for i, tx := range transactions {
		// Hash the transaction
		var buffer bytes.Buffer
		buffer.Write(tx.From[:])
		buffer.Write(tx.To[:])
		if tx.Value != nil {
			buffer.Write(tx.Value.Bytes())
		}
		binary.Write(&buffer, binary.BigEndian, tx.Nonce)
		buffer.Write(tx.Data)
		binary.Write(&buffer, binary.BigEndian, tx.Timestamp.UnixNano())
		buffer.Write(tx.Signature)

		txHash := sha256.Sum256(buffer.Bytes())
		hashes[i] = txHash
	}

	// Build Merkle tree
	return bm.buildMerkleRoot(hashes), nil
}

// buildMerkleRoot builds a Merkle root from a list of hashes
func (bm *BlockManager) buildMerkleRoot(hashes []types.Hash) types.Hash {
	if len(hashes) == 0 {
		return types.Hash{}
	}

	if len(hashes) == 1 {
		return hashes[0]
	}

	// If odd number of hashes, duplicate the last one
	if len(hashes)%2 != 0 {
		hashes = append(hashes, hashes[len(hashes)-1])
	}

	// Combine pairs of hashes
	parentHashes := make([]types.Hash, len(hashes)/2)
	for i := 0; i < len(hashes); i += 2 {
		// Combine each pair of hashes
		var buffer bytes.Buffer
		buffer.Write(hashes[i][:])
		buffer.Write(hashes[i+1][:])

		parentHash := sha256.Sum256(buffer.Bytes())
		parentHashes[i/2] = parentHash
	}

	// Recursively build the parent level
	return bm.buildMerkleRoot(parentHashes)
}

// calculateZKProofsHash calculates a hash of all ZK proofs
func (bm *BlockManager) calculateZKProofsHash(zkProofs [][]byte) (types.Hash, error) {
	// If no ZK proofs, return empty hash
	if len(zkProofs) == 0 {
		return types.Hash{}, nil
	}

	// Combine all ZK proofs
	var buffer bytes.Buffer
	for _, proof := range zkProofs {
		proofHash := sha256.Sum256(proof)
		buffer.Write(proofHash[:])
	}

	// Calculate combined hash
	zkProofsHash := sha256.Sum256(buffer.Bytes())

	return zkProofsHash, nil
}

// createAccumulator creates a cryptographic accumulator for the block
func (bm *BlockManager) createAccumulator(transactions []types.Transaction, stateRoot types.Hash) (*Accumulator, error) {
	accumulator := &Accumulator{
		Value:     make([]byte, 32),
		Elements:  make(map[string]bool),
		BlockHash: types.Hash{},
	}

	// Copy state root as initial value
	copy(accumulator.Value, stateRoot[:])

	// Add each transaction to the accumulator
	for _, tx := range transactions {
		// Create a key for the transaction
		var buffer bytes.Buffer
		buffer.Write(tx.From[:])
		buffer.Write(tx.To[:])
		if tx.Value != nil {
			buffer.Write(tx.Value.Bytes())
		}
		binary.Write(&buffer, binary.BigEndian, tx.Nonce)

		// Hash the transaction key
		keyHash := sha256.Sum256(buffer.Bytes())
		keyStr := string(keyHash[:AccumulatorKeySize])

		// Add to accumulator if not already present
		if !accumulator.Elements[keyStr] {
			// Update accumulator value
			newValue := sha256.Sum256(append(accumulator.Value, keyHash[:]...))
			accumulator.Value = newValue[:]
			accumulator.Elements[keyStr] = true
		}
	}

	return accumulator, nil
}

// getAccumulatorHash gets the hash of an accumulator
func (bm *BlockManager) getAccumulatorHash(accumulator *Accumulator) types.Hash {
	if accumulator == nil {
		return types.Hash{}
	}

	// Create hash from accumulator value
	hash := sha256.Sum256(accumulator.Value)
	return hash
}

// VerifyAccumulatorMembership verifies if an element is in the accumulator
func (bm *BlockManager) VerifyAccumulatorMembership(blockHash types.Hash, txHash types.Hash) (bool, error) {
	accumulator, exists := bm.accumulators[blockHash]
	if !exists {
		return false, errors.New("accumulator not found for block")
	}

	// Convert hash to key string
	keyStr := string(txHash[:AccumulatorKeySize])

	// Check if element exists in accumulator
	return accumulator.Elements[keyStr], nil
}

// calculateEntropyScore calculates the entropy score of a block
func (bm *BlockManager) calculateEntropyScore(block *types.Block) float64 {
	if len(block.Transactions) == 0 {
		return 0.0
	}

	// Calculate entropy based on transaction distribution
	addressFreq := make(map[string]int)
	valueFreq := make(map[string]int)

	for _, tx := range block.Transactions {
		// Count address frequencies
		fromKey := string(tx.From[:])
		toKey := string(tx.To[:])
		addressFreq[fromKey]++
		addressFreq[toKey]++

		// Count value frequencies (binned)
		if tx.Value != nil {
			valueKey := tx.Value.String()
			valueFreq[valueKey]++
		}
	}

	// Calculate Shannon entropy for addresses
	addressEntropy := calculateShannonEntropy(addressFreq, len(block.Transactions)*2) // *2 for from+to

	// Calculate Shannon entropy for values
	valueEntropy := calculateShannonEntropy(valueFreq, len(block.Transactions))

	// Weighted combination of entropies
	entropyScore := (addressEntropy*0.7 + valueEntropy*0.3)

	// Normalize to 0-1 range
	// The theoretical maximum entropy is log2(n) where n is number of unique elements
	maxPossibleEntropy := math.Log2(float64(len(block.Transactions) * 2))
	if maxPossibleEntropy > 0 {
		entropyScore = entropyScore / maxPossibleEntropy
	}

	// Cap at 1.0
	if entropyScore > 1.0 {
		entropyScore = 1.0
	}

	return entropyScore
}

// calculateShannonEntropy calculates the Shannon entropy of a frequency distribution
func calculateShannonEntropy(frequencies map[string]int, total int) float64 {
	entropy := 0.0

	for _, count := range frequencies {
		if count == 0 {
			continue
		}

		p := float64(count) / float64(total)
		entropy -= p * math.Log2(p)
	}

	return entropy
}

// estimateBlockSize estimates the size of a block in bytes
func (bm *BlockManager) estimateBlockSize(block *types.Block) int {
	// Header size
	size := 376 // Approximate fixed size of header fields

	// Add variable-sized fields
	if block.Header.Difficulty != nil {
		size += len(block.Header.Difficulty.Bytes())
	}
	size += len(block.Header.ConsensusData)
	size += len(block.Header.VRFProof)

	// Transactions
	for _, tx := range block.Transactions {
		// Basic transaction structure
		txSize := 128 // Approximate fixed size

		// Add variable fields
		if tx.Value != nil {
			txSize += len(tx.Value.Bytes())
		}
		txSize += len(tx.Data)
		txSize += len(tx.Signature)

		size += txSize
	}

	// Signatures and proofs
	size += len(block.Signature)
	size += len(block.BFTProof)

	// ZK proofs
	for _, proof := range block.ZKProofs {
		size += len(proof)
	}

	// Vector clock
	size += len(block.VectorClock) * 16 // Estimated size per entry

	return size
}

// SignBlock signs a block with the provided signature
func (bm *BlockManager) SignBlock(block *types.Block, signature []byte) {
	block.Signature = signature
}

// AddBFTProof adds Byzantine Fault Tolerance proof to a block
func (bm *BlockManager) AddBFTProof(block *types.Block, bftProof []byte) {
	block.BFTProof = bftProof
}

// SetShardInfo sets shard information for a block
func (bm *BlockManager) SetShardInfo(block *types.Block, shardInfo *types.ShardInfo) {
	block.ShardInfo = shardInfo
}

// GetBlocksInRange retrieves blocks within a height range
func (bm *BlockManager) GetBlocksInRange(startHeight, endHeight uint64) []*types.Block {
	var result []*types.Block

	for _, block := range bm.blocks {
		if block.Header.Height >= startHeight && block.Header.Height <= endHeight {
			result = append(result, block)
		}
	}

	// Sort by height (not efficient for many blocks, would use indexed lookup in production)
	for i := 0; i < len(result); i++ {
		for j := i + 1; j < len(result); j++ {
			if result[i].Header.Height > result[j].Header.Height {
				result[i], result[j] = result[j], result[i]
			}
		}
	}

	return result
}

// GetBlockCount returns the number of blocks in the blockchain
func (bm *BlockManager) GetBlockCount() int {
	return len(bm.blocks)
}

// SetVectorClock sets the vector clock for a block
func (bm *BlockManager) SetVectorClock(block *types.Block, vectorClock map[uint64]uint64) {
	block.VectorClock = vectorClock
}
