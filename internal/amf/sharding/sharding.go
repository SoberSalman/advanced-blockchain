// internal/amf/sharding/sharding.go
package sharding

import (
	"sync"
	"time"

	"github.com/SoberSalman/advanced-blockchain/internal/types"
	"github.com/rs/zerolog/log"
)

const (
	// Thresholds for shard splitting and merging
	MaxShardLoad         = 0.85 // 85% load triggers a split
	MinShardLoad         = 0.25 // 25% load triggers a merge consideration
	MaxShardSize         = 1000 // Maximum number of transactions per shard
	ShardRebalanceWindow = 100  // Number of blocks before rebalancing is allowed
)

// ShardManager handles dynamic sharding operations
type ShardManager struct {
	shards          map[uint64]*Shard
	shardHierarchy  map[uint64][]uint64 // parent -> children mapping
	forestRoot      types.Hash
	lastRebalanced  uint64
	mu              sync.RWMutex
	rebalanceEvents chan RebalanceEvent
}

// Shard represents a shard in the AMF
type Shard struct {
	Info              types.ShardInfo
	Nodes             []string // Node IDs participating in this shard
	StateRoot         types.Hash
	TransactionCount  uint64
	ComputationalLoad float64
	CreationHeight    uint64
	LastUpdated       time.Time
}

// RebalanceEvent represents a shard rebalancing event
type RebalanceEvent struct {
	Type             string // "split" or "merge"
	SourceShardID    uint64
	TargetShardIDs   []uint64
	Height           uint64
	Timestamp        time.Time
	RebalanceMetrics map[string]float64
}

// NewShardManager creates a new shard manager
func NewShardManager() *ShardManager {
	// Create genesis shard
	genesisShard := &Shard{
		Info: types.ShardInfo{
			ID:                0,
			Parent:            0, // Self-referential for genesis
			Children:          []uint64{},
			TransactionCount:  0,
			NodeCount:         0,
			ComputationalLoad: 0,
		},
		Nodes:             []string{},
		StateRoot:         types.Hash{},
		TransactionCount:  0,
		ComputationalLoad: 0,
		CreationHeight:    0,
		LastUpdated:       time.Now(),
	}

	// Initialize shard manager
	sm := &ShardManager{
		shards:          map[uint64]*Shard{0: genesisShard},
		shardHierarchy:  map[uint64][]uint64{0: {}},
		lastRebalanced:  0,
		rebalanceEvents: make(chan RebalanceEvent, 100),
	}

	return sm
}

// GetShard returns a shard by ID
func (sm *ShardManager) GetShard(shardID uint64) (*Shard, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	shard, exists := sm.shards[shardID]
	return shard, exists
}

// UpdateShardLoad updates a shard's computational load
func (sm *ShardManager) UpdateShardLoad(shardID uint64, newLoad float64, txCount uint64) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if shard, exists := sm.shards[shardID]; exists {
		shard.ComputationalLoad = newLoad
		shard.TransactionCount = txCount
		shard.LastUpdated = time.Now()
	}
}

// AddNodeToShard adds a node to a shard
func (sm *ShardManager) AddNodeToShard(nodeID string, shardID uint64) bool {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if shard, exists := sm.shards[shardID]; exists {
		// Check if node already exists in shard
		for _, id := range shard.Nodes {
			if id == nodeID {
				return false // Node already in shard
			}
		}

		shard.Nodes = append(shard.Nodes, nodeID)
		shard.Info.NodeCount = uint64(len(shard.Nodes))
		return true
	}
	return false
}

// RemoveNodeFromShard removes a node from a shard
func (sm *ShardManager) RemoveNodeFromShard(nodeID string, shardID uint64) bool {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if shard, exists := sm.shards[shardID]; exists {
		for i, id := range shard.Nodes {
			if id == nodeID {
				// Remove node by swapping with last element and truncating
				shard.Nodes[i] = shard.Nodes[len(shard.Nodes)-1]
				shard.Nodes = shard.Nodes[:len(shard.Nodes)-1]
				shard.Info.NodeCount = uint64(len(shard.Nodes))
				return true
			}
		}
	}
	return false
}

// CheckShardRebalancing checks if shards need rebalancing and performs it if necessary
func (sm *ShardManager) CheckShardRebalancing(currentHeight uint64) []RebalanceEvent {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Only rebalance if enough blocks have passed since last rebalance
	if currentHeight < sm.lastRebalanced+ShardRebalanceWindow {
		return nil
	}

	var events []RebalanceEvent

	// Check each shard for potential splitting or merging
	for shardID, shard := range sm.shards {
		// Check for split condition
		if shard.ComputationalLoad > MaxShardLoad || shard.TransactionCount > MaxShardSize {
			if event := sm.splitShard(shardID, currentHeight); event != nil {
				events = append(events, *event)
			}
		}

		// Check for merge condition - only for non-genesis shards with siblings
		if shardID != 0 && shard.ComputationalLoad < MinShardLoad {
			if event := sm.considerShardMerge(shardID, currentHeight); event != nil {
				events = append(events, *event)
			}
		}
	}

	if len(events) > 0 {
		sm.lastRebalanced = currentHeight
	}

	return events
}

// splitShard splits a shard into two new shards
func (sm *ShardManager) splitShard(shardID uint64, currentHeight uint64) *RebalanceEvent {
	shard, exists := sm.shards[shardID]
	if !exists {
		return nil
	}

	log.Info().Uint64("shardID", shardID).Msg("Splitting shard")

	// Create two new shards
	newShardID1 := getNextShardID(sm.shards)
	newShardID2 := newShardID1 + 1

	// Distribute nodes between shards (even/odd distribution for simplicity)
	var nodes1, nodes2 []string
	for i, nodeID := range shard.Nodes {
		if i%2 == 0 {
			nodes1 = append(nodes1, nodeID)
		} else {
			nodes2 = append(nodes2, nodeID)
		}
	}

	// Create new shards
	newShard1 := &Shard{
		Info: types.ShardInfo{
			ID:                newShardID1,
			Parent:            shardID,
			Children:          []uint64{},
			StateRootHash:     types.Hash{}, // Will be set after state transfer
			TransactionCount:  shard.TransactionCount / 2,
			NodeCount:         uint64(len(nodes1)),
			ComputationalLoad: shard.ComputationalLoad / 2,
		},
		Nodes:             nodes1,
		StateRoot:         types.Hash{}, // Will be set after state transfer
		TransactionCount:  shard.TransactionCount / 2,
		ComputationalLoad: shard.ComputationalLoad / 2,
		CreationHeight:    currentHeight,
		LastUpdated:       time.Now(),
	}

	newShard2 := &Shard{
		Info: types.ShardInfo{
			ID:                newShardID2,
			Parent:            shardID,
			Children:          []uint64{},
			StateRootHash:     types.Hash{}, // Will be set after state transfer
			TransactionCount:  shard.TransactionCount / 2,
			NodeCount:         uint64(len(nodes2)),
			ComputationalLoad: shard.ComputationalLoad / 2,
		},
		Nodes:             nodes2,
		StateRoot:         types.Hash{}, // Will be set after state transfer
		TransactionCount:  shard.TransactionCount / 2,
		ComputationalLoad: shard.ComputationalLoad / 2,
		CreationHeight:    currentHeight,
		LastUpdated:       time.Now(),
	}

	// Update original shard's children
	shard.Info.Children = append(shard.Info.Children, newShardID1, newShardID2)

	// Update hierarchy
	sm.shardHierarchy[shardID] = append(sm.shardHierarchy[shardID], newShardID1, newShardID2)
	sm.shardHierarchy[newShardID1] = []uint64{}
	sm.shardHierarchy[newShardID2] = []uint64{}

	// Add new shards to manager
	sm.shards[newShardID1] = newShard1
	sm.shards[newShardID2] = newShard2

	// Create rebalance event
	event := RebalanceEvent{
		Type:           "split",
		SourceShardID:  shardID,
		TargetShardIDs: []uint64{newShardID1, newShardID2},
		Height:         currentHeight,
		Timestamp:      time.Now(),
		RebalanceMetrics: map[string]float64{
			"originalLoad": shard.ComputationalLoad,
			"newLoad1":     shard.ComputationalLoad / 2,
			"newLoad2":     shard.ComputationalLoad / 2,
		},
	}

	// Send event to channel
	sm.rebalanceEvents <- event

	return &event
}

// considerShardMerge evaluates if a shard should be merged with siblings
func (sm *ShardManager) considerShardMerge(shardID uint64, currentHeight uint64) *RebalanceEvent {
	shard, exists := sm.shards[shardID]
	if !exists || shard.Info.Parent == 0 {
		return nil // Don't merge if shard doesn't exist or is the genesis shard
	}

	parentID := shard.Info.Parent
	parent, exists := sm.shards[parentID]
	if !exists {
		return nil // Parent doesn't exist
	}

	// Get sibling shards
	var siblings []uint64
	for _, childID := range parent.Info.Children {
		if childID != shardID {
			siblings = append(siblings, childID)
		}
	}

	if len(siblings) == 0 {
		return nil // No siblings to merge with
	}

	// Find best sibling to merge with (the one with lowest load)
	var bestSiblingID uint64
	var bestSiblingLoad float64 = 1.0 // Start with max load

	for _, siblingID := range siblings {
		sibling, exists := sm.shards[siblingID]
		if !exists {
			continue
		}

		if sibling.ComputationalLoad < bestSiblingLoad {
			bestSiblingLoad = sibling.ComputationalLoad
			bestSiblingID = siblingID
		}
	}

	// Check if merge is viable (combined load shouldn't exceed threshold)
	bestSibling, exists := sm.shards[bestSiblingID]
	if !exists {
		return nil
	}

	combinedLoad := shard.ComputationalLoad + bestSibling.ComputationalLoad
	if combinedLoad > MaxShardLoad {
		return nil // Combined load too high, don't merge
	}

	log.Info().
		Uint64("shardID", shardID).
		Uint64("siblingID", bestSiblingID).
		Float64("combinedLoad", combinedLoad).
		Msg("Merging shards")

	// Perform merge
	// Combine nodes
	mergedNodes := append([]string{}, shard.Nodes...)
	mergedNodes = append(mergedNodes, bestSibling.Nodes...)

	// Update sibling shard with merged data
	bestSibling.Nodes = mergedNodes
	bestSibling.Info.NodeCount = uint64(len(mergedNodes))
	bestSibling.TransactionCount += shard.TransactionCount
	bestSibling.ComputationalLoad = combinedLoad
	bestSibling.LastUpdated = time.Now()

	// Update parent's children
	newChildren := []uint64{}
	for _, childID := range parent.Info.Children {
		if childID != shardID {
			newChildren = append(newChildren, childID)
		}
	}
	parent.Info.Children = newChildren

	// Update hierarchy
	delete(sm.shardHierarchy, shardID)
	delete(sm.shards, shardID)

	// Create rebalance event
	event := RebalanceEvent{
		Type:           "merge",
		SourceShardID:  shardID,
		TargetShardIDs: []uint64{bestSiblingID},
		Height:         currentHeight,
		Timestamp:      time.Now(),
		RebalanceMetrics: map[string]float64{
			"originalLoad1": shard.ComputationalLoad,
			"originalLoad2": bestSibling.ComputationalLoad,
			"mergedLoad":    combinedLoad,
		},
	}

	// Send event to channel
	sm.rebalanceEvents <- event

	return &event
}

// GetShardsForTransaction determines which shards a transaction belongs to
func (sm *ShardManager) GetShardsForTransaction(tx types.Transaction) []uint64 {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	// Simple implementation: For a transaction between two accounts,
	// find the shards containing those accounts
	// In a real implementation, this would use account-to-shard mapping

	// Start with genesis shard
	result := []uint64{0}

	// Find leaf shards in the hierarchy (they contain the actual state)
	for shardID, children := range sm.shardHierarchy {
		if len(children) == 0 && shardID != 0 {
			result = append(result, shardID)
		}
	}

	return result
}

// FindShardPath finds the path from root to a specific shard
func (sm *ShardManager) FindShardPath(targetShardID uint64) []uint64 {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if targetShardID == 0 {
		return []uint64{0} // Genesis shard
	}

	path := []uint64{targetShardID}
	current, exists := sm.shards[targetShardID]

	for exists && current.Info.ID != 0 {
		parentID := current.Info.Parent
		path = append([]uint64{parentID}, path...) // Prepend
		current, exists = sm.shards[parentID]
	}

	return path
}

// GetRebalanceEventsChannel returns the channel for rebalance events
func (sm *ShardManager) GetRebalanceEventsChannel() <-chan RebalanceEvent {
	return sm.rebalanceEvents
}

// GetAllShardIDs returns all shard IDs
func (sm *ShardManager) GetAllShardIDs() []uint64 {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	ids := make([]uint64, 0, len(sm.shards))
	for id := range sm.shards {
		ids = append(ids, id)
	}
	return ids
}

// Helper function to get the next available shard ID
func getNextShardID(shards map[uint64]*Shard) uint64 {
	maxID := uint64(0)
	for id := range shards {
		if id > maxID {
			maxID = id
		}
	}
	return maxID + 1
}
