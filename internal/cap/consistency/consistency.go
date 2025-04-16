// internal/cap/consistency/consistency.go
package consistency

import (
	"math"
	"sync"
	"time"

	"github.com/SoberSalman/advanced-blockchain/internal/types"
	"github.com/rs/zerolog/log"
)

const (
	// Consistency levels
	StrongConsistency   = 1.0
	EventualConsistency = 0.1
	CausalConsistency   = 0.5

	// Network health thresholds
	HealthyNetwork  = 0.8
	DegradedNetwork = 0.5
	PoorNetwork     = 0.2

	// Timeout factors
	BaseTimeout          = 500 * time.Millisecond
	MaxTimeout           = 10 * time.Second
	TimeoutBackoffFactor = 1.5

	// Prediction parameters
	PredictionWindowSize = 20   // Number of data points to use for prediction
	PredictionWeight     = 0.75 // Weight of prediction vs current state
)

// ConsistencyOrchestrator manages dynamic consistency adjustments
type ConsistencyOrchestrator struct {
	consistencyLevels   map[uint64]float64 // ShardID -> Consistency level
	networkStats        map[uint64]*NetworkState
	partitionPrediction map[uint64]float64 // ShardID -> Partition probability
	timeoutSettings     map[uint64]time.Duration
	retrySettings       map[uint64]int
	healthMetrics       map[string]float64
	mu                  sync.RWMutex
	updateInterval      time.Duration
	lastUpdated         time.Time
}

// NetworkState tracks network state for a shard
type NetworkState struct {
	LatencyHistory     []time.Duration
	FailureRateHistory []float64
	PartitionHistory   []float64
	NodeCount          uint64
	LastUpdated        time.Time
}

// NewConsistencyOrchestrator creates a new consistency orchestrator
func NewConsistencyOrchestrator() *ConsistencyOrchestrator {
	co := &ConsistencyOrchestrator{
		consistencyLevels:   make(map[uint64]float64),
		networkStats:        make(map[uint64]*NetworkState),
		partitionPrediction: make(map[uint64]float64),
		timeoutSettings:     make(map[uint64]time.Duration),
		retrySettings:       make(map[uint64]int),
		healthMetrics:       make(map[string]float64),
		updateInterval:      30 * time.Second,
		lastUpdated:         time.Now(),
	}

	// Start background monitoring
	go co.monitor()

	return co
}

// monitor periodically updates consistency settings based on network conditions
func (co *ConsistencyOrchestrator) monitor() {
	ticker := time.NewTicker(co.updateInterval)
	defer ticker.Stop()

	for range ticker.C {
		co.mu.Lock()
		co.lastUpdated = time.Now()
		co.mu.Unlock()

		// Update consistency levels for all shards
		co.UpdateAllConsistencyLevels()
	}
}

// RegisterShard initializes consistency management for a shard
func (co *ConsistencyOrchestrator) RegisterShard(shardID uint64) {
	co.mu.Lock()
	defer co.mu.Unlock()

	if _, exists := co.networkStats[shardID]; !exists {
		co.networkStats[shardID] = &NetworkState{
			LatencyHistory:     make([]time.Duration, 0, PredictionWindowSize),
			FailureRateHistory: make([]float64, 0, PredictionWindowSize),
			PartitionHistory:   make([]float64, 0, PredictionWindowSize),
			NodeCount:          0,
			LastUpdated:        time.Now(),
		}

		// Initialize with balanced defaults
		co.consistencyLevels[shardID] = CausalConsistency
		co.partitionPrediction[shardID] = 0.1 // Initial 10% probability
		co.timeoutSettings[shardID] = BaseTimeout
		co.retrySettings[shardID] = 3 // Default 3 retries
	}
}

// UpdateNetworkStats updates network statistics for a shard
func (co *ConsistencyOrchestrator) UpdateNetworkStats(stats types.NetworkStats) {
	co.mu.Lock()
	defer co.mu.Unlock()

	shardID := stats.ShardID

	// Ensure shard is registered
	if _, exists := co.networkStats[shardID]; !exists {
		co.RegisterShard(shardID)
	}

	state := co.networkStats[shardID]

	// Update latency history
	state.LatencyHistory = append(state.LatencyHistory, stats.AverageLatency)
	if len(state.LatencyHistory) > PredictionWindowSize {
		state.LatencyHistory = state.LatencyHistory[1:]
	}

	// Update failure rate history
	state.FailureRateHistory = append(state.FailureRateHistory, stats.MessageFailureRate)
	if len(state.FailureRateHistory) > PredictionWindowSize {
		state.FailureRateHistory = state.FailureRateHistory[1:]
	}

	// Update partition history
	state.PartitionHistory = append(state.PartitionHistory, stats.PartitionProbability)
	if len(state.PartitionHistory) > PredictionWindowSize {
		state.PartitionHistory = state.PartitionHistory[1:]
	}

	state.NodeCount = stats.NodeCount
	state.LastUpdated = time.Now()

	// Update partition prediction
	co.updatePartitionPrediction(shardID)

	// Update timeout and retry settings
	co.updateTimeoutSettings(shardID)

	// Recalculate consistency level
	co.UpdateConsistencyLevel(shardID)
}

// updatePartitionPrediction predicts the probability of network partition
func (co *ConsistencyOrchestrator) updatePartitionPrediction(shardID uint64) {
	state, exists := co.networkStats[shardID]
	if !exists {
		return
	}

	// Simple prediction based on historical data
	// In a real implementation, this would use more sophisticated algorithms

	// Check if we have enough data
	if len(state.PartitionHistory) < 2 {
		co.partitionPrediction[shardID] = 0.1 // Default if not enough data
		return
	}

	// Calculate trend in partition probability
	var trend float64
	for i := 1; i < len(state.PartitionHistory); i++ {
		trend += state.PartitionHistory[i] - state.PartitionHistory[i-1]
	}
	trend /= float64(len(state.PartitionHistory) - 1)

	// Calculate average failure rate
	var avgFailureRate float64
	for _, rate := range state.FailureRateHistory {
		avgFailureRate += rate
	}
	avgFailureRate /= float64(len(state.FailureRateHistory))

	// Factor in latency variance
	var latencyVariance float64
	var avgLatency time.Duration
	for _, latency := range state.LatencyHistory {
		avgLatency += latency
	}
	avgLatency /= time.Duration(len(state.LatencyHistory))

	for _, latency := range state.LatencyHistory {
		diff := float64(latency - avgLatency)
		latencyVariance += diff * diff
	}
	latencyVariance /= float64(len(state.LatencyHistory))
	normalizedVariance := math.Min(1.0, math.Sqrt(latencyVariance)/float64(avgLatency))

	// Combine factors
	currentPartition := state.PartitionHistory[len(state.PartitionHistory)-1]
	predictedIncrease := trend + (avgFailureRate * 0.5) + (normalizedVariance * 0.3)

	// Cap the prediction
	prediction := math.Min(1.0, math.Max(0.0, currentPartition+predictedIncrease))

	// Apply exponential smoothing
	co.partitionPrediction[shardID] = (PredictionWeight * prediction) +
		((1 - PredictionWeight) * co.partitionPrediction[shardID])
}

// updateTimeoutSettings updates timeout and retry settings based on network conditions
func (co *ConsistencyOrchestrator) updateTimeoutSettings(shardID uint64) {
	state, exists := co.networkStats[shardID]
	if !exists {
		return
	}

	// Calculate timeout based on latency statistics
	var avgLatency time.Duration
	if len(state.LatencyHistory) > 0 {
		var sum time.Duration
		for _, latency := range state.LatencyHistory {
			sum += latency
		}
		avgLatency = sum / time.Duration(len(state.LatencyHistory))
	} else {
		avgLatency = 100 * time.Millisecond // Default if no data
	}

	// Calculate standard deviation
	var variance float64
	for _, latency := range state.LatencyHistory {
		diff := float64(latency - avgLatency)
		variance += diff * diff
	}
	variance /= float64(max(1, len(state.LatencyHistory)))
	stdDev := time.Duration(math.Sqrt(variance))

	// Set timeout to average + 2 standard deviations, with minimum of BaseTimeout
	calculatedTimeout := avgLatency + (2 * stdDev)
	if calculatedTimeout < BaseTimeout {
		calculatedTimeout = BaseTimeout
	}

	// Factor in partition probability
	partitionFactor := 1.0 + co.partitionPrediction[shardID]
	adjustedTimeout := time.Duration(float64(calculatedTimeout) * partitionFactor)

	// Cap at maximum timeout
	if adjustedTimeout > MaxTimeout {
		adjustedTimeout = MaxTimeout
	}

	co.timeoutSettings[shardID] = adjustedTimeout

	// Update retry settings
	failureRate := 0.1 // Default
	if len(state.FailureRateHistory) > 0 {
		failureRate = state.FailureRateHistory[len(state.FailureRateHistory)-1]
	}

	// More retries for higher failure rates
	retries := 1 + int(math.Ceil(failureRate*10))
	if retries > 10 {
		retries = 10 // Cap at 10 retries
	}

	co.retrySettings[shardID] = retries
}

// GetConsistencyLevel returns the current consistency level for a shard
func (co *ConsistencyOrchestrator) GetConsistencyLevel(shardID uint64) float64 {
	co.mu.RLock()
	defer co.mu.RUnlock()

	level, exists := co.consistencyLevels[shardID]
	if !exists {
		co.mu.RUnlock()           // Unlock before calling RegisterShard
		co.RegisterShard(shardID) // This will acquire the lock again
		co.mu.RLock()             // Re-acquire read lock
		return co.consistencyLevels[shardID]
	}

	return level
}

// UpdateConsistencyLevel recalculates the consistency level for a shard
func (co *ConsistencyOrchestrator) UpdateConsistencyLevel(shardID uint64) {
	state, exists := co.networkStats[shardID]
	if !exists {
		return
	}

	// Get the predicted partition probability
	partitionProb := co.partitionPrediction[shardID]

	// Get the latest failure rate
	failureRate := 0.0
	if len(state.FailureRateHistory) > 0 {
		failureRate = state.FailureRateHistory[len(state.FailureRateHistory)-1]
	}

	// Calculate network health score (0.0 to 1.0)
	healthScore := 1.0 - ((partitionProb * 0.7) + (failureRate * 0.3))

	// Determine consistency level based on network health
	var newLevel float64

	if healthScore >= HealthyNetwork {
		// Network is healthy, favor consistency
		newLevel = StrongConsistency
	} else if healthScore >= DegradedNetwork {
		// Network is degraded, use causal consistency
		newLevel = CausalConsistency
	} else {
		// Network is poor, favor availability
		newLevel = EventualConsistency
	}

	// Apply the new consistency level
	co.mu.Lock()
	oldLevel := co.consistencyLevels[shardID]
	co.consistencyLevels[shardID] = newLevel
	co.mu.Unlock()

	// Log significant changes
	if math.Abs(newLevel-oldLevel) > 0.2 {
		log.Info().
			Uint64("shardID", shardID).
			Float64("oldLevel", oldLevel).
			Float64("newLevel", newLevel).
			Float64("networkHealth", healthScore).
			Float64("partitionProb", partitionProb).
			Msg("Significant consistency level change")
	}
}

// UpdateAllConsistencyLevels updates consistency levels for all shards
func (co *ConsistencyOrchestrator) UpdateAllConsistencyLevels() {
	co.mu.RLock()
	shardIDs := make([]uint64, 0, len(co.networkStats))
	for shardID := range co.networkStats {
		shardIDs = append(shardIDs, shardID)
	}
	co.mu.RUnlock()

	for _, shardID := range shardIDs {
		co.UpdateConsistencyLevel(shardID)
	}
}

// GetTimeout returns the current timeout setting for a shard
func (co *ConsistencyOrchestrator) GetTimeout(shardID uint64) time.Duration {
	co.mu.RLock()
	defer co.mu.RUnlock()

	timeout, exists := co.timeoutSettings[shardID]
	if !exists {
		return BaseTimeout
	}

	return timeout
}

// GetRetryCount returns the current retry count for a shard
func (co *ConsistencyOrchestrator) GetRetryCount(shardID uint64) int {
	co.mu.RLock()
	defer co.mu.RUnlock()

	retries, exists := co.retrySettings[shardID]
	if !exists {
		return 3 // Default
	}

	return retries
}

// GetPartitionProbability returns the current partition probability for a shard
func (co *ConsistencyOrchestrator) GetPartitionProbability(shardID uint64) float64 {
	co.mu.RLock()
	defer co.mu.RUnlock()

	prob, exists := co.partitionPrediction[shardID]
	if !exists {
		return 0.1 // Default
	}

	return prob
}

// GetAllConsistencyLevels returns all consistency levels
func (co *ConsistencyOrchestrator) GetAllConsistencyLevels() map[uint64]float64 {
	co.mu.RLock()
	defer co.mu.RUnlock()

	result := make(map[uint64]float64)
	for shardID, level := range co.consistencyLevels {
		result[shardID] = level
	}

	return result
}

// GetAllTimeouts returns all timeout settings
func (co *ConsistencyOrchestrator) GetAllTimeouts() map[uint64]time.Duration {
	co.mu.RLock()
	defer co.mu.RUnlock()

	result := make(map[uint64]time.Duration)
	for shardID, timeout := range co.timeoutSettings {
		result[shardID] = timeout
	}

	return result
}

// GetNetworkHealth returns the overall network health
func (co *ConsistencyOrchestrator) GetNetworkHealth() float64 {
	co.mu.RLock()
	defer co.mu.RUnlock()

	if len(co.networkStats) == 0 {
		return 1.0 // Assume healthy if no data
	}

	var totalHealth float64
	for shardID := range co.networkStats {
		partitionProb := co.partitionPrediction[shardID]
		failureRate := 0.0
		if len(co.networkStats[shardID].FailureRateHistory) > 0 {
			failureRate = co.networkStats[shardID].FailureRateHistory[len(co.networkStats[shardID].FailureRateHistory)-1]
		}

		// Calculate health score
		healthScore := 1.0 - ((partitionProb * 0.7) + (failureRate * 0.3))
		totalHealth += healthScore
	}

	return totalHealth / float64(len(co.networkStats))
}

// max helper function for Go versions before 1.21
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
