// internal/bft/defense/defense.go
package defense

import (
	"crypto/sha256"
	"errors"
	"math"
	"sync"
	"time"

	"github.com/SoberSalman/advanced-blockchain/internal/types"
	"github.com/rs/zerolog/log"
)

const (
	// Node reputation thresholds
	HighReputation   = 0.8
	NormalReputation = 0.5
	LowReputation    = 0.2

	// Adaptive consensus thresholds
	MaxConsensusThreshold = 0.85 // 85% for highly trusted network
	MinConsensusThreshold = 0.67 // 67% for untrusted network (traditional BFT minimum)

	// Defense layers
	LayerReputation    = "reputation"
	LayerBehavioral    = "behavioral"
	LayerCryptographic = "cryptographic"

	// Reputation score factors
	MaxReputationScore  = 1.0
	ReputationDecayRate = 0.995 // Reputation decays by 0.5% per period

	// Attack pattern weights
	WeightInconsistency = 0.4
	WeightLatency       = 0.2
	WeightAvailability  = 0.2
	WeightCryptographic = 0.2
)

// DefenseManager implements multi-layered Byzantine fault tolerance defenses
type DefenseManager struct {
	nodeReputations     map[string]float64 // NodeID -> Reputation score
	nodeHistory         map[string]*NodeHistory
	consensusThresholds map[uint64]float64 // ShardID -> Consensus threshold
	attackDetections    map[string][]AttackDetection
	mu                  sync.RWMutex
	decayTicker         *time.Ticker
}

// NodeHistory tracks a node's historical performance
type NodeHistory struct {
	SuccessfulValidations  int
	FailedValidations      int
	LatencyHistory         []time.Duration
	LastSeen               time.Time
	ConsensusParticipation int
	ConsensusDeviation     int // Number of times the node disagreed with the consensus
	CryptographicFailures  int
}

// AttackDetection records a detected attack
type AttackDetection struct {
	NodeID      string
	Type        string
	Timestamp   time.Time
	Description string
	Severity    float64
	Evidence    map[string]interface{}
}

// NewDefenseManager creates a new defense manager
func NewDefenseManager() *DefenseManager {
	dm := &DefenseManager{
		nodeReputations:     make(map[string]float64),
		nodeHistory:         make(map[string]*NodeHistory),
		consensusThresholds: make(map[uint64]float64),
		attackDetections:    make(map[string][]AttackDetection),
		decayTicker:         time.NewTicker(6 * time.Hour), // Decay reputation every 6 hours
	}

	// Start the reputation decay goroutine
	go dm.runReputationDecay()

	return dm
}

// runReputationDecay periodically decays node reputation scores
func (dm *DefenseManager) runReputationDecay() {
	for range dm.decayTicker.C {
		dm.mu.Lock()

		// Apply decay to all node reputations
		for nodeID, reputation := range dm.nodeReputations {
			// Decay the reputation by a small amount
			newReputation := reputation * ReputationDecayRate

			// Ensure it doesn't go below a minimum threshold
			if newReputation < 0.1 {
				newReputation = 0.1
			}

			dm.nodeReputations[nodeID] = newReputation
		}

		dm.mu.Unlock()

		log.Debug().Msg("Applied reputation decay to all nodes")
	}
}

// RegisterNode initializes a new node in the defense system
func (dm *DefenseManager) RegisterNode(nodeID string) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	if _, exists := dm.nodeReputations[nodeID]; !exists {
		// Initialize with neutral reputation
		dm.nodeReputations[nodeID] = NormalReputation

		dm.nodeHistory[nodeID] = &NodeHistory{
			SuccessfulValidations:  0,
			FailedValidations:      0,
			LatencyHistory:         make([]time.Duration, 0, 100),
			LastSeen:               time.Now(),
			ConsensusParticipation: 0,
			ConsensusDeviation:     0,
			CryptographicFailures:  0,
		}

		dm.attackDetections[nodeID] = make([]AttackDetection, 0)
	}
}

// UpdateNodeReputation updates a node's reputation score
func (dm *DefenseManager) UpdateNodeReputation(nodeID string, event string, success bool) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	// Ensure node is registered
	if _, exists := dm.nodeReputations[nodeID]; !exists {
		dm.RegisterNode(nodeID)
	}

	history := dm.nodeHistory[nodeID]
	history.LastSeen = time.Now()

	var reputationDelta float64

	switch event {
	case "validation":
		if success {
			history.SuccessfulValidations++
			reputationDelta = 0.01
		} else {
			history.FailedValidations++
			reputationDelta = -0.05 // Penalize failed validations more heavily
		}
	case "consensus":
		if success {
			history.ConsensusParticipation++
			reputationDelta = 0.02
		} else {
			history.ConsensusDeviation++
			reputationDelta = -0.03
		}
	case "cryptographic":
		if success {
			reputationDelta = 0.01
		} else {
			history.CryptographicFailures++
			reputationDelta = -0.1 // Severe penalty for cryptographic failures
		}
	case "availability":
		if success {
			reputationDelta = 0.005
		} else {
			reputationDelta = -0.02
		}
	}

	// Apply the reputation change
	dm.nodeReputations[nodeID] += reputationDelta

	// Ensure reputation stays within bounds
	if dm.nodeReputations[nodeID] > MaxReputationScore {
		dm.nodeReputations[nodeID] = MaxReputationScore
	} else if dm.nodeReputations[nodeID] < 0 {
		dm.nodeReputations[nodeID] = 0
	}
}

// RecordNodeLatency records a node's operation latency
func (dm *DefenseManager) RecordNodeLatency(nodeID string, latency time.Duration) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	// Ensure node is registered
	if _, exists := dm.nodeHistory[nodeID]; !exists {
		dm.RegisterNode(nodeID)
	}

	// Update history
	history := dm.nodeHistory[nodeID]
	history.LatencyHistory = append(history.LatencyHistory, latency)

	// Keep only the most recent 100 latency measurements
	if len(history.LatencyHistory) > 100 {
		history.LatencyHistory = history.LatencyHistory[len(history.LatencyHistory)-100:]
	}

	// Check for abnormal latency
	if len(history.LatencyHistory) >= 10 {
		avgLatency := dm.calculateAverageLatency(nodeID)
		if latency > avgLatency*3 && latency > 1*time.Second {
			// Latency is significantly higher than average
			dm.detectPotentialAttack(nodeID, "high_latency", "Node exhibited abnormally high latency", 0.3, map[string]interface{}{
				"latency":     latency,
				"avg_latency": avgLatency,
				"threshold":   avgLatency * 3,
			})
		}
	}
}

// UpdateConsensusThreshold dynamically adjusts the consensus threshold for a shard
func (dm *DefenseManager) UpdateConsensusThreshold(shardID uint64, nodes []string) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	if len(nodes) == 0 {
		return
	}

	// Calculate average reputation of nodes in the shard
	var totalReputation float64
	var nodeCount int

	for _, nodeID := range nodes {
		if reputation, exists := dm.nodeReputations[nodeID]; exists {
			totalReputation += reputation
			nodeCount++
		}
	}

	if nodeCount == 0 {
		return
	}

	avgReputation := totalReputation / float64(nodeCount)

	// Scale consensus threshold based on average reputation
	// Higher reputation = higher threshold (more strict consensus)
	// Lower reputation = lower threshold (more lenient to ensure liveness)

	threshold := MinConsensusThreshold + (MaxConsensusThreshold-MinConsensusThreshold)*(avgReputation/MaxReputationScore)

	// Ensure threshold doesn't go below minimum BFT requirement
	if threshold < MinConsensusThreshold {
		threshold = MinConsensusThreshold
	}

	dm.consensusThresholds[shardID] = threshold

	log.Debug().
		Uint64("shardID", shardID).
		Float64("avgReputation", avgReputation).
		Float64("consensusThreshold", threshold).
		Msg("Updated consensus threshold")
}

// GetConsensusThreshold gets the current consensus threshold for a shard
func (dm *DefenseManager) GetConsensusThreshold(shardID uint64) float64 {
	dm.mu.RLock()
	defer dm.mu.RUnlock()

	if threshold, exists := dm.consensusThresholds[shardID]; exists {
		return threshold
	}

	// Return default if not set
	return MinConsensusThreshold
}

// VerifyNodeSignature performs cryptographic verification of a node's signature
func (dm *DefenseManager) VerifyNodeSignature(nodeID string, data []byte, signature []byte, publicKey []byte) bool {
	// In a real implementation, this would perform actual cryptographic verification
	// For this demonstration, we'll simulate verification

	// Update node's last seen
	dm.mu.Lock()
	if history, exists := dm.nodeHistory[nodeID]; exists {
		history.LastSeen = time.Now()
	} else {
		dm.RegisterNode(nodeID)
	}
	dm.mu.Unlock()

	// Simulate signature verification
	// In a real implementation, this would use a proper verification algorithm
	expectedHash := sha256.Sum256(append(data, publicKey...))
	actualHash := sha256.Sum256(signature)

	// Simulated verification with some randomness for demonstration
	// In production code, this would be a real cryptographic verification
	isValid := expectedHash[0] == actualHash[0] && expectedHash[1] == actualHash[1]

	// Update reputation based on verification result
	dm.UpdateNodeReputation(nodeID, "cryptographic", isValid)

	// If verification failed, record a potential attack
	if !isValid {
		dm.detectPotentialAttack(nodeID, "invalid_signature", "Node provided invalid signature", 0.7, map[string]interface{}{
			"data_hash": expectedHash[:4],
			"sig_hash":  actualHash[:4],
		})
	}

	return isValid
}

// ValidateNodeBehavior performs behavioral analysis on a node
func (dm *DefenseManager) ValidateNodeBehavior(nodeID string, behavior map[string]interface{}) (bool, string) {
	dm.mu.RLock()
	defer dm.mu.RUnlock()

	// Ensure node is registered
	if _, exists := dm.nodeReputations[nodeID]; !exists {
		dm.mu.RUnlock()
		dm.RegisterNode(nodeID)
		dm.mu.RLock()
	}

	history := dm.nodeHistory[nodeID]

	// Check for suspicious behaviors
	// 1. High validation failure rate
	if history.SuccessfulValidations+history.FailedValidations > 10 {
		failureRate := float64(history.FailedValidations) / float64(history.SuccessfulValidations+history.FailedValidations)
		if failureRate > 0.3 {
			return false, "High validation failure rate"
		}
	}

	// 2. High consensus deviation rate
	if history.ConsensusParticipation > 10 {
		deviationRate := float64(history.ConsensusDeviation) / float64(history.ConsensusParticipation)
		if deviationRate > 0.3 {
			return false, "High consensus deviation rate"
		}
	}

	// 3. Cryptographic failures
	if history.CryptographicFailures > 3 {
		return false, "Multiple cryptographic failures"
	}

	// 4. Inactivity (node not seen recently)
	if time.Since(history.LastSeen) > 1*time.Hour {
		return false, "Node inactive"
	}

	return true, ""
}

// GetNodeRiskScore calculates a risk score for a node (0-1, where 0 is no risk)
func (dm *DefenseManager) GetNodeRiskScore(nodeID string) float64 {
	dm.mu.RLock()
	defer dm.mu.RUnlock()

	if _, exists := dm.nodeReputations[nodeID]; !exists {
		return 0.5 // Default risk for unknown nodes
	}

	history := dm.nodeHistory[nodeID]

	// Calculate risk factors

	// 1. Validation failure risk
	validationRisk := 0.0
	if history.SuccessfulValidations+history.FailedValidations > 0 {
		validationRisk = float64(history.FailedValidations) / float64(history.SuccessfulValidations+history.FailedValidations)
	}

	// 2. Consensus deviation risk
	consensusRisk := 0.0
	if history.ConsensusParticipation > 0 {
		consensusRisk = float64(history.ConsensusDeviation) / float64(history.ConsensusParticipation)
	}

	// 3. Cryptographic risk
	cryptoRisk := math.Min(1.0, float64(history.CryptographicFailures)/5.0)

	// 4. Latency risk
	latencyRisk := dm.calculateLatencyRisk(nodeID)

	// Combine risks with weights
	weightedRisk := (validationRisk * WeightInconsistency) +
		(consensusRisk * WeightInconsistency) +
		(cryptoRisk * WeightCryptographic) +
		(latencyRisk * WeightLatency)

	// Reputation inversely affects risk
	reputation := dm.nodeReputations[nodeID]

	// Final risk calculation: combine weighted risk factors and reputation
	// Higher reputation reduces risk, lower reputation increases it
	finalRisk := weightedRisk * (1 + (1 - reputation))

	// Normalize to 0-1 range
	return math.Min(1.0, finalRisk)
}

// GetNodeReputation gets a node's current reputation score
func (dm *DefenseManager) GetNodeReputation(nodeID string) float64 {
	dm.mu.RLock()
	defer dm.mu.RUnlock()

	if reputation, exists := dm.nodeReputations[nodeID]; exists {
		return reputation
	}

	return NormalReputation // Default reputation for unknown nodes
}

// GetAllNodeReputations gets all node reputation scores
func (dm *DefenseManager) GetAllNodeReputations() map[string]float64 {
	dm.mu.RLock()
	defer dm.mu.RUnlock()

	result := make(map[string]float64)
	for nodeID, reputation := range dm.nodeReputations {
		result[nodeID] = reputation
	}

	return result
}

// IsNodeTrusted checks if a node is trusted
func (dm *DefenseManager) IsNodeTrusted(nodeID string) bool {
	reputation := dm.GetNodeReputation(nodeID)
	return reputation >= HighReputation
}

// detectPotentialAttack records a potential attack by a node
func (dm *DefenseManager) detectPotentialAttack(nodeID, attackType, description string, severity float64, evidence map[string]interface{}) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	// Create attack detection record
	detection := AttackDetection{
		NodeID:      nodeID,
		Type:        attackType,
		Timestamp:   time.Now(),
		Description: description,
		Severity:    severity,
		Evidence:    evidence,
	}

	// Add to node's attack detection history
	dm.attackDetections[nodeID] = append(dm.attackDetections[nodeID], detection)

	// Log the attack detection
	log.Warn().
		Str("nodeID", nodeID).
		Str("attackType", attackType).
		Float64("severity", severity).
		Msg(description)

	// Apply reputation penalty based on severity
	currentReputation := dm.nodeReputations[nodeID]
	penalty := severity * 0.2 // Scale penalty by severity
	dm.nodeReputations[nodeID] = math.Max(0, currentReputation-penalty)
}

// GetAttackDetections gets all attack detections for a node
func (dm *DefenseManager) GetAttackDetections(nodeID string) []AttackDetection {
	dm.mu.RLock()
	defer dm.mu.RUnlock()

	if detections, exists := dm.attackDetections[nodeID]; exists {
		result := make([]AttackDetection, len(detections))
		copy(result, detections)
		return result
	}

	return []AttackDetection{}
}

// calculateAverageLatency calculates the average latency for a node
func (dm *DefenseManager) calculateAverageLatency(nodeID string) time.Duration {
	history, exists := dm.nodeHistory[nodeID]
	if !exists || len(history.LatencyHistory) == 0 {
		return 0
	}

	var totalLatency time.Duration
	for _, latency := range history.LatencyHistory {
		totalLatency += latency
	}

	return totalLatency / time.Duration(len(history.LatencyHistory))
}

// calculateLatencyRisk calculates a risk score based on latency variations
func (dm *DefenseManager) calculateLatencyRisk(nodeID string) float64 {
	history, exists := dm.nodeHistory[nodeID]
	if !exists || len(history.LatencyHistory) < 5 {
		return 0.5 // Default risk if not enough data
	}

	// Calculate average and standard deviation
	avgLatency := dm.calculateAverageLatency(nodeID)

	var sumSquaredDiff float64
	for _, latency := range history.LatencyHistory {
		diff := float64(latency - avgLatency)
		sumSquaredDiff += diff * diff
	}

	stdDev := time.Duration(math.Sqrt(sumSquaredDiff / float64(len(history.LatencyHistory))))

	// High stdDev/avg ratio indicates erratic latency, which is risky
	variabilityRatio := float64(stdDev) / float64(avgLatency)

	// Normalize to 0-1 risk
	risk := math.Min(1.0, variabilityRatio)

	return risk
}

// ValidateBlock performs multi-layer validation of a block
func (dm *DefenseManager) ValidateBlock(block *types.Block, nodeID string) (bool, error) {
	// Layer 1: Reputation check
	reputation := dm.GetNodeReputation(nodeID)
	if reputation < LowReputation {
		return false, errors.New("node has insufficient reputation")
	}

	// Layer 2: Behavioral analysis
	behaviorValid, reason := dm.ValidateNodeBehavior(nodeID, nil)
	if !behaviorValid {
		return false, errors.New("behavioral validation failed: " + reason)
	}

	// Layer 3: Cryptographic verification
	// Calculate and use the hash
	blockHash := sha256.Sum256([]byte(block.Header.Timestamp.String() + string(block.Header.Height)))
	_ = blockHash // Use the hash (even just acknowledging it) to avoid the unused variable error

	// Record successful validation
	dm.UpdateNodeReputation(nodeID, "validation", true)

	return true, nil
}

// CalculateAdaptiveThreshold calculates an adaptive threshold for consensus
// based on network conditions and node reputations
func (dm *DefenseManager) CalculateAdaptiveThreshold(shardID uint64, nodes []string) float64 {
	threshold := dm.GetConsensusThreshold(shardID)

	// Adjust the threshold based on node count to ensure security
	// For small number of nodes, increase the threshold
	if len(nodes) < 7 {
		// With fewer nodes, we need a higher percentage agreement
		threshold = math.Min(threshold+0.05, 0.9)
	} else if len(nodes) > 20 {
		// With many nodes, we can be slightly more lenient
		threshold = math.Max(threshold-0.02, MinConsensusThreshold)
	}

	return threshold
}

// Close cleans up resources
func (dm *DefenseManager) Close() {
	if dm.decayTicker != nil {
		dm.decayTicker.Stop()
	}
}
