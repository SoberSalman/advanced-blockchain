//nolint:unused // Ignore unused variable warnings in this file

package conflict

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math"
	"sort"
	"sync"
	"time"

	"github.com/SoberSalman/advanced-blockchain/internal/types"
	"github.com/rs/zerolog/log"
)

const (
	// Conflict resolution states
	ConflictDetected     = 0
	ConflictAnalyzing    = 1
	ConflictResolved     = 2
	ConflictUnresolvable = 3

	// Resolution strategies
	StrategyTimestamp = "timestamp"
	StrategyVector    = "vector"
	StrategyEntropy   = "entropy"
	StrategyConsensus = "consensus"

	// Entropy thresholds
	LowEntropy    = 0.3
	MediumEntropy = 0.6
	HighEntropy   = 0.85

	// Resolution parameters
	MaxRetriesBeforeConsensus = 3
	ConflictTimeout           = 30 * time.Second
)

// ConflictManager handles detection and resolution of conflicts
type ConflictManager struct {
	activeConflicts    map[string]*types.ConflictInfo
	resolvedConflicts  map[string]*types.ConflictInfo
	vectorClocks       map[uint64]map[uint64]uint64 // ShardID -> (NodeID -> Clock)
	strategyStats      map[string]int               // Strategy -> Success count
	mu                 sync.RWMutex
	networkPartitioned bool
}

// NewConflictManager creates a new conflict manager
func NewConflictManager() *ConflictManager {
	return &ConflictManager{
		activeConflicts:    make(map[string]*types.ConflictInfo),
		resolvedConflicts:  make(map[string]*types.ConflictInfo),
		vectorClocks:       make(map[uint64]map[uint64]uint64),
		strategyStats:      make(map[string]int),
		networkPartitioned: false,
	}
}

// DetectConflict checks for conflicts in transactions
func (cm *ConflictManager) DetectConflict(tx1, tx2 types.Transaction) bool {
	// Check if transactions conflict
	// Simple implementation: transactions conflict if they modify the same address
	return bytes.Equal(tx1.To[:], tx2.To[:])
}

// RegisterConflict registers a new conflict
func (cm *ConflictManager) RegisterConflict(txs []types.Transaction, shardIDs []uint64) string {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Generate conflict ID
	var buffer bytes.Buffer
	for i := range txs {
		tx := txs[i] // Use the transaction
		buffer.Write(tx.From[:])
		buffer.Write(tx.To[:])
		buffer.Write(tx.Signature)
	}
	hash := sha256.Sum256(buffer.Bytes())
	conflictID := fmt.Sprintf("%x", hash[:16])

	// Check if conflict already exists
	if _, exists := cm.activeConflicts[conflictID]; exists {
		return conflictID
	}

	// Extract vector clocks for involved shards
	vectorClocks := make([]map[uint64]uint64, 0, len(shardIDs))
	for _, shardID := range shardIDs {
		if clock, exists := cm.vectorClocks[shardID]; exists {
			vectorClocks = append(vectorClocks, clock)
		}
	}

	// Calculate initial entropy score
	entropyScore := cm.calculateEntropyScore(txs)

	// Create conflict info
	conflict := &types.ConflictInfo{
		Transactions:    txs,
		EntropyScore:    entropyScore,
		VectorClocks:    vectorClocks,
		ResolutionState: ConflictDetected,
		ShardIDs:        shardIDs,
	}

	cm.activeConflicts[conflictID] = conflict

	// Start async resolution
	go cm.resolveConflict(conflictID)

	return conflictID
}

// resolveConflict handles the conflict resolution process
func (cm *ConflictManager) resolveConflict(conflictID string) {
	cm.mu.Lock()
	conflict, exists := cm.activeConflicts[conflictID]
	if !exists {
		cm.mu.Unlock()
		return
	}

	// Update state
	conflict.ResolutionState = ConflictAnalyzing
	cm.mu.Unlock()

	// Pick resolution strategy based on conflict characteristics
	strategy := cm.pickResolutionStrategy(conflict)

	log.Info().
		Str("conflictID", conflictID).
		Str("strategy", strategy).
		Float64("entropyScore", conflict.EntropyScore).
		Int("transactionCount", len(conflict.Transactions)).
		Msg("Resolving conflict")

	var resolved bool
	var retries int

	// Try to resolve with selected strategy
	for retries < MaxRetriesBeforeConsensus {
		resolved = cm.applyResolutionStrategy(conflictID, strategy)
		if resolved {
			break
		}

		// If not resolved, try another strategy
		retries++

		// If entropy-based strategy failed, try vector clock
		if strategy == StrategyEntropy {
			strategy = StrategyVector
		} else if strategy == StrategyVector {
			// If vector clock failed, try timestamp
			strategy = StrategyTimestamp
		} else {
			// If all else fails, use consensus
			strategy = StrategyConsensus
			break
		}

		log.Warn().
			Str("conflictID", conflictID).
			Str("newStrategy", strategy).
			Int("retry", retries).
			Msg("Retrying conflict resolution with different strategy")
	}

	// If still not resolved, use consensus as last resort
	if !resolved {
		resolved = cm.applyResolutionStrategy(conflictID, StrategyConsensus)
	}

	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Update conflict state
	conflict, stillExists := cm.activeConflicts[conflictID]
	if !stillExists {
		return // Conflict was resolved elsewhere
	}

	if resolved {
		conflict.ResolutionState = ConflictResolved
		cm.resolvedConflicts[conflictID] = conflict
		delete(cm.activeConflicts, conflictID)

		// Record strategy success
		cm.strategyStats[strategy]++
	} else {
		conflict.ResolutionState = ConflictUnresolvable
		log.Error().
			Str("conflictID", conflictID).
			Msg("Failed to resolve conflict")
	}
}

// pickResolutionStrategy selects the best resolution strategy for a conflict
func (cm *ConflictManager) pickResolutionStrategy(conflict *types.ConflictInfo) string {
	// If network is partitioned, prefer timestamp-based resolution
	if cm.networkPartitioned {
		return StrategyTimestamp
	}

	// If entropy is high, use entropy-based resolution
	if conflict.EntropyScore > HighEntropy {
		return StrategyEntropy
	}

	// Check if vector clocks can establish causality
	if len(conflict.VectorClocks) > 0 {
		hasPartialOrder := cm.checkVectorClockPartialOrder(conflict.VectorClocks)
		if hasPartialOrder {
			return StrategyVector
		}
	}

	// Default to timestamp for simple conflicts
	if conflict.EntropyScore < LowEntropy {
		return StrategyTimestamp
	}

	// Use entropy-based resolution for complex conflicts
	return StrategyEntropy
}

// applyResolutionStrategy applies the selected resolution strategy
func (cm *ConflictManager) applyResolutionStrategy(conflictID, strategy string) bool {
	cm.mu.RLock()
	conflict, exists := cm.activeConflicts[conflictID]
	cm.mu.RUnlock()

	if !exists {
		return false
	}

	switch strategy {
	case StrategyTimestamp:
		return cm.resolveByTimestamp(conflict)
	case StrategyVector:
		return cm.resolveByVectorClock(conflict)
	case StrategyEntropy:
		return cm.resolveByEntropy(conflict)
	case StrategyConsensus:
		return cm.resolveByConsensus(conflict)
	default:
		return false
	}
}

// resolveByTimestamp resolves conflict by picking the transaction with the earliest timestamp
func (cm *ConflictManager) resolveByTimestamp(conflict *types.ConflictInfo) bool {
	if len(conflict.Transactions) <= 1 {
		return true // No real conflict
	}

	// Sort transactions by timestamp
	sort.Slice(conflict.Transactions, func(i, j int) bool {
		return conflict.Transactions[i].Timestamp.Before(conflict.Transactions[j].Timestamp)
	})

	// Keep only the earliest transaction
	cm.mu.Lock()
	conflict.Transactions = conflict.Transactions[:1]
	cm.mu.Unlock()

	return true
}

// resolveByVectorClock resolves conflict using vector clocks to establish causality
func (cm *ConflictManager) resolveByVectorClock(conflict *types.ConflictInfo) bool {
	if len(conflict.Transactions) <= 1 || len(conflict.VectorClocks) == 0 {
		return true // No real conflict or no vector clocks
	}

	// Check for causal relationships between transactions
	// For each transaction pair, check if one happened before the other

	// Create a graph of happens-before relationships
	n := len(conflict.Transactions)
	graph := make([][]bool, n)
	for i := range graph {
		graph[i] = make([]bool, n)
	}

	// Fill in happens-before relationships
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			if i == j {
				continue
			}

			// Check if transaction i happened before j based on vector clocks
			// This is a simplified implementation
			if i < len(conflict.VectorClocks) && j < len(conflict.VectorClocks) {
				happensBefore := cm.vectorHappensBefore(conflict.VectorClocks[i], conflict.VectorClocks[j])
				graph[i][j] = happensBefore
			}
		}
	}

	// Find transactions that are not superseded by any other
	notSuperseded := make([]bool, n)
	for i := range notSuperseded {
		notSuperseded[i] = true
	}

	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			if i != j && graph[j][i] {
				// j happened before i, so i supersedes j
				notSuperseded[j] = false
			}
		}
	}

	// Keep only transactions that are not superseded
	var keptTransactions []types.Transaction
	for i := 0; i < n; i++ {
		if notSuperseded[i] {
			keptTransactions = append(keptTransactions, conflict.Transactions[i])
		}
	}

	// If we didn't resolve to a single transaction, it's a partial failure
	if len(keptTransactions) > 1 {
		// If we reduced the number of transactions, it's a partial success
		if len(keptTransactions) < len(conflict.Transactions) {
			cm.mu.Lock()
			conflict.Transactions = keptTransactions
			cm.mu.Unlock()
			return false // Need further resolution
		}
		return false // No resolution achieved
	}

	// Successfully resolved to one transaction
	cm.mu.Lock()
	conflict.Transactions = keptTransactions
	cm.mu.Unlock()

	return true
}

// resolveByEntropy uses entropy-based analysis to resolve conflicts
func (cm *ConflictManager) resolveByEntropy(conflict *types.ConflictInfo) bool {
	if len(conflict.Transactions) <= 1 {
		return true // No real conflict
	}

	// Calculate transaction entropy contributions
	entropyContributions := make([]float64, len(conflict.Transactions))
	totalEntropy := conflict.EntropyScore

	// For each transaction, calculate how removing it would affect entropy
	for i := range conflict.Transactions {
		// Create a new set of transactions without this one
		reducedSet := make([]types.Transaction, 0, len(conflict.Transactions)-1)
		for j := range conflict.Transactions {
			if i != j {
				reducedSet = append(reducedSet, conflict.Transactions[j])
			}
		}

		// Calculate entropy of reduced set
		reducedEntropy := cm.calculateEntropyScore(reducedSet)

		// Entropy contribution is how much this transaction adds to the total
		entropyContributions[i] = totalEntropy - reducedEntropy
	}

	// Find transaction with highest entropy contribution (most destabilizing)
	maxContribIndex := 0
	maxContrib := entropyContributions[0]
	for i := 1; i < len(entropyContributions); i++ {
		if entropyContributions[i] > maxContrib {
			maxContrib = entropyContributions[i]
			maxContribIndex = i
		}
	}

	// Remove the transaction with highest entropy contribution
	newTransactions := make([]types.Transaction, 0, len(conflict.Transactions)-1)
	for i := range conflict.Transactions {
		if i != maxContribIndex {
			newTransactions = append(newTransactions, conflict.Transactions[i])
		}
	}

	// Update conflict with reduced transaction set
	cm.mu.Lock()
	conflict.Transactions = newTransactions
	conflict.EntropyScore = cm.calculateEntropyScore(newTransactions)
	cm.mu.Unlock()

	// If we still have multiple transactions, we need further resolution
	return len(newTransactions) <= 1
}

// resolveByConsensus uses a consensus mechanism to resolve conflicts
func (cm *ConflictManager) resolveByConsensus(conflict *types.ConflictInfo) bool {
	if len(conflict.Transactions) <= 1 {
		return true // No real conflict
	}

	// In a real implementation, this would initiate a consensus round
	// For simplicity, we'll use a deterministic approach here

	// Hash all transactions and pick the one with lowest hash
	var lowestHashIndex int
	var lowestHash [32]byte

	for i, tx := range conflict.Transactions {
		// Create a hash of the transaction
		var buffer bytes.Buffer
		buffer.Write(tx.From[:])
		buffer.Write(tx.To[:])
		buffer.Write(tx.Data)
		hash := sha256.Sum256(buffer.Bytes())

		if i == 0 || bytes.Compare(hash[:], lowestHash[:]) < 0 {
			lowestHash = hash
			lowestHashIndex = i
		}
	}

	// Keep only the winning transaction
	winningTx := conflict.Transactions[lowestHashIndex]

	cm.mu.Lock()
	conflict.Transactions = []types.Transaction{winningTx}
	cm.mu.Unlock()

	log.Info().
		Str("strategy", StrategyConsensus).
		Int("originalCount", len(conflict.Transactions)).
		Msg("Conflict resolved by consensus")

	return true
}

// calculateEntropyScore calculates the entropy (disorder) in a set of transactions
func (cm *ConflictManager) calculateEntropyScore(txs []types.Transaction) float64 {
	if len(txs) <= 1 {
		return 0.0 // No entropy with 0 or 1 transaction
	}

	// Shannon entropy calculation based on transaction properties
	addressFreq := make(map[string]int)
	valueFreq := make(map[string]int)
	timeFreq := make(map[string]int)

	for i := range txs {
		tx := txs[i] // Access the transaction using index
		// Count address frequencies
		fromKey := fmt.Sprintf("%x", tx.From)
		toKey := fmt.Sprintf("%x", tx.To)
		addressFreq[fromKey]++
		addressFreq[toKey]++

		// Count value frequencies (binned)
		valueKey := fmt.Sprintf("%d", tx.Value.Int64()/1000) // Bin by 1000 units
		valueFreq[valueKey]++

		// Count timestamp frequencies (binned by hour)
		timeKey := tx.Timestamp.Format("2006-01-02-15")
		timeFreq[timeKey]++
	}

	// Calculate entropy for each dimension
	addressEntropy := calculateShannonEntropy(addressFreq, len(txs)*2) // *2 because each tx has 2 addresses
	valueEntropy := calculateShannonEntropy(valueFreq, len(txs))
	timeEntropy := calculateShannonEntropy(timeFreq, len(txs))

	// Combine entropies (weighted average)
	combinedEntropy := (addressEntropy*0.4 + valueEntropy*0.4 + timeEntropy*0.2)

	// Normalize to 0-1 range
	maxEntropy := math.Log2(float64(len(txs)))
	if maxEntropy == 0 {
		return 0
	}

	normalizedEntropy := combinedEntropy / maxEntropy
	return math.Min(1.0, normalizedEntropy) // Cap at 1.0
}

// calculateShannonEntropy calculates Shannon entropy for a frequency distribution
func calculateShannonEntropy(freq map[string]int, total int) float64 {
	entropy := 0.0
	for _, count := range freq {
		if count == 0 {
			continue
		}
		p := float64(count) / float64(total)
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// UpdateVectorClock updates the vector clock for a shard
func (cm *ConflictManager) UpdateVectorClock(shardID, nodeID uint64, clock map[uint64]uint64) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Initialize shard's vector clock if it doesn't exist
	if _, exists := cm.vectorClocks[shardID]; !exists {
		cm.vectorClocks[shardID] = make(map[uint64]uint64)
	}

	// Update with the new clock
	// In a real implementation, this would merge vector clocks properly
	for id, time := range clock {
		current, exists := cm.vectorClocks[shardID][id]
		if !exists || time > current {
			cm.vectorClocks[shardID][id] = time
		}
	}

	// Always update this node's clock
	cm.vectorClocks[shardID][nodeID]++
}

// GetVectorClock gets the current vector clock for a shard
func (cm *ConflictManager) GetVectorClock(shardID uint64) map[uint64]uint64 {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	if clock, exists := cm.vectorClocks[shardID]; exists {
		// Return a copy to prevent concurrent modification
		result := make(map[uint64]uint64)
		for k, v := range clock {
			result[k] = v
		}
		return result
	}

	return make(map[uint64]uint64)
}

// vectorHappensBefore checks if one vector clock happens before another
func (cm *ConflictManager) vectorHappensBefore(vc1, vc2 map[uint64]uint64) bool {
	// v1 happens before v2 if:
	// 1. For all i, v1[i] <= v2[i]
	// 2. There exists at least one j such that v1[j] < v2[j]

	if len(vc1) == 0 || len(vc2) == 0 {
		return false
	}

	atLeastOneSmaller := false

	// Check all elements in vc1
	for id, time1 := range vc1 {
		time2, exists := vc2[id]
		if !exists {
			// If id doesn't exist in vc2, assume 0
			if time1 > 0 {
				return false // vc1[id] > vc2[id] (0)
			}
		} else if time1 > time2 {
			return false // vc1[id] > vc2[id]
		} else if time1 < time2 {
			atLeastOneSmaller = true
		}
	}

	// Check for any ids in vc2 that are not in vc1
	for id, time2 := range vc2 {
		_, exists := vc1[id]
		if !exists && time2 > 0 {
			atLeastOneSmaller = true
		}
	}

	return atLeastOneSmaller
}

// checkVectorClockPartialOrder checks if the vector clocks establish a partial ordering
func (cm *ConflictManager) checkVectorClockPartialOrder(clocks []map[uint64]uint64) bool {
	if len(clocks) <= 1 {
		return true // Trivially ordered
	}

	// Check if any pair of clocks has a happens-before relationship
	for i := 0; i < len(clocks); i++ {
		for j := i + 1; j < len(clocks); j++ {
			if cm.vectorHappensBefore(clocks[i], clocks[j]) || cm.vectorHappensBefore(clocks[j], clocks[i]) {
				return true // Found a happens-before relationship
			}
		}
	}

	return false // No partial ordering found
}

// GetConflictStatus gets the status of a conflict
func (cm *ConflictManager) GetConflictStatus(conflictID string) (uint8, error) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	if conflict, exists := cm.activeConflicts[conflictID]; exists {
		return conflict.ResolutionState, nil
	}

	if conflict, exists := cm.resolvedConflicts[conflictID]; exists {
		return conflict.ResolutionState, nil
	}

	return 0, fmt.Errorf("conflict not found: %s", conflictID)
}

// GetConflictDetails gets detailed information about a conflict
func (cm *ConflictManager) GetConflictDetails(conflictID string) (*types.ConflictInfo, error) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	if conflict, exists := cm.activeConflicts[conflictID]; exists {
		return conflict, nil
	}

	if conflict, exists := cm.resolvedConflicts[conflictID]; exists {
		return conflict, nil
	}

	return nil, fmt.Errorf("conflict not found: %s", conflictID)
}

// GetStrategyStats gets statistics about resolution strategies
func (cm *ConflictManager) GetStrategyStats() map[string]int {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	// Return a copy to prevent concurrent modification
	result := make(map[string]int)
	for k, v := range cm.strategyStats {
		result[k] = v
	}

	return result
}

// SetNetworkPartitioned updates the network partition status
func (cm *ConflictManager) SetNetworkPartitioned(partitioned bool) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	cm.networkPartitioned = partitioned
}

// GetActiveConflictCount gets the number of active conflicts
func (cm *ConflictManager) GetActiveConflictCount() int {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	return len(cm.activeConflicts)
}

// GetResolvedConflictCount gets the number of resolved conflicts
func (cm *ConflictManager) GetResolvedConflictCount() int {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	return len(cm.resolvedConflicts)
}
