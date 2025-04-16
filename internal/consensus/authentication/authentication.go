// internal/consensus/authentication/authentication.go
package authentication

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

const (
	// Authentication mechanism constants
	MaxChallengeAge     = 5 * time.Minute
	ChallengeLength     = 32
	TrustScoreThreshold = 0.7
	ValidationInterval  = 10 * time.Minute
	SessionTimeout      = 24 * time.Hour
	MaxFailedAttempts   = 5
	FactorWeight        = 0.33 // Weight for each authentication factor

	// Multi-factor constants
	FactorKnowledge  = "knowledge"
	FactorPossession = "possession"
	FactorBehavioral = "behavioral"
)

// AuthManager handles advanced node authentication
type AuthManager struct {
	sessions         map[string]*AuthSession
	nodes            map[string]*NodeAuth
	challenges       map[string]*Challenge
	trustScores      map[string]float64
	validationTimers map[string]*time.Timer
	mu               sync.RWMutex
}

// AuthSession represents an authenticated session
type AuthSession struct {
	NodeID         string
	SessionID      string
	CreatedAt      time.Time
	ExpiresAt      time.Time
	LastActivity   time.Time
	Factors        []string
	ValidationData map[string]interface{}
}

// NodeAuth contains authentication data for a node
type NodeAuth struct {
	NodeID          string
	PublicKey       []byte
	KnowledgeFactor []byte // Hashed secret
	PossessionData  []byte // Device identifier or token hash
	BehavioralData  []byte // Behavioral fingerprint
	FailedAttempts  int
	LastAuth        time.Time
	LastValidation  time.Time
	TrustScore      float64
}

// Challenge represents an authentication challenge
type Challenge struct {
	ChallengeID string
	NodeID      string
	Challenge   []byte
	CreatedAt   time.Time
	ExpiresAt   time.Time
	Factor      string
	Completed   bool
}

// NewAuthManager creates a new authentication manager
func NewAuthManager() *AuthManager {
	return &AuthManager{
		sessions:         make(map[string]*AuthSession),
		nodes:            make(map[string]*NodeAuth),
		challenges:       make(map[string]*Challenge),
		trustScores:      make(map[string]float64),
		validationTimers: make(map[string]*time.Timer),
	}
}

// RegisterNode registers a new node for authentication
func (am *AuthManager) RegisterNode(nodeID string, publicKey, knowledgeFactor, possessionData []byte) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	if _, exists := am.nodes[nodeID]; exists {
		return errors.New("node already registered")
	}

	// Initialize node authentication data
	am.nodes[nodeID] = &NodeAuth{
		NodeID:          nodeID,
		PublicKey:       publicKey,
		KnowledgeFactor: knowledgeFactor, // Should be pre-hashed
		PossessionData:  possessionData,
		BehavioralData:  nil, // Will be built over time
		FailedAttempts:  0,
		LastAuth:        time.Time{}, // Zero time
		LastValidation:  time.Time{},
		TrustScore:      0.5, // Start with neutral trust
	}

	am.trustScores[nodeID] = 0.5

	// Start periodic validation timer
	am.validationTimers[nodeID] = time.AfterFunc(ValidationInterval, func() {
		am.validateNode(nodeID)
	})

	log.Info().
		Str("nodeID", nodeID).
		Msg("Node registered for authentication")

	return nil
}

// InitiateAuthentication starts the authentication process for a node
func (am *AuthManager) InitiateAuthentication(nodeID string) (map[string]string, error) {
	am.mu.Lock()
	defer am.mu.Unlock()

	node, exists := am.nodes[nodeID]
	if !exists {
		return nil, errors.New("node not registered")
	}

	// Check if too many failed attempts
	if node.FailedAttempts >= MaxFailedAttempts {
		// Reset after a day
		if time.Since(node.LastAuth) > 24*time.Hour {
			node.FailedAttempts = 0
		} else {
			return nil, errors.New("too many failed authentication attempts")
		}
	}

	// Generate challenges for each factor
	challenges := make(map[string]string)

	// Knowledge factor challenge
	knowledgeChallenge, err := am.createChallenge(nodeID, FactorKnowledge)
	if err != nil {
		return nil, err
	}
	challenges[FactorKnowledge] = knowledgeChallenge

	// Possession factor challenge
	possessionChallenge, err := am.createChallenge(nodeID, FactorPossession)
	if err != nil {
		return nil, err
	}
	challenges[FactorPossession] = possessionChallenge

	// Behavioral factor challenge (if behavioral data exists)
	if node.BehavioralData != nil {
		behavioralChallenge, err := am.createChallenge(nodeID, FactorBehavioral)
		if err != nil {
			return nil, err
		}
		challenges[FactorBehavioral] = behavioralChallenge
	}

	log.Info().
		Str("nodeID", nodeID).
		Int("challengeCount", len(challenges)).
		Msg("Authentication initiated")

	return challenges, nil
}

// createChallenge creates a new challenge for a specific factor
func (am *AuthManager) createChallenge(nodeID, factor string) (string, error) {
	// Generate random challenge
	challenge := make([]byte, ChallengeLength)
	if _, err := rand.Read(challenge); err != nil {
		return "", err
	}

	// Create unique challenge ID
	challengeHash := sha256.Sum256(append(challenge, []byte(nodeID+factor)...))
	challengeID := fmt.Sprintf("%x", challengeHash[:8])

	// Store challenge
	am.challenges[challengeID] = &Challenge{
		ChallengeID: challengeID,
		NodeID:      nodeID,
		Challenge:   challenge,
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(MaxChallengeAge),
		Factor:      factor,
		Completed:   false,
	}

	return challengeID, nil
}

// VerifyKnowledgeFactor verifies the knowledge factor response
func (am *AuthManager) VerifyKnowledgeFactor(challengeID string, response []byte) (bool, error) {
	am.mu.Lock()
	defer am.mu.Unlock()

	challenge, exists := am.challenges[challengeID]
	if !exists {
		return false, errors.New("challenge not found")
	}

	if challenge.Factor != FactorKnowledge {
		return false, errors.New("invalid challenge type")
	}

	if time.Now().After(challenge.ExpiresAt) {
		return false, errors.New("challenge expired")
	}

	if challenge.Completed {
		return false, errors.New("challenge already completed")
	}

	node, exists := am.nodes[challenge.NodeID]
	if !exists {
		return false, errors.New("node not found")
	}

	// Verify response: In a real system, this would use a proper crypto verification
	// For example, response would be hashed with challenge as salt and compared
	expectedResponse := sha256.Sum256(append(challenge.Challenge, node.KnowledgeFactor...))
	actualResponse := sha256.Sum256(response)

	isValid := compareHashes(expectedResponse[:], actualResponse[:])
	challenge.Completed = true

	// Update trust score for this factor
	if isValid {
		am.adjustTrustScore(node.NodeID, FactorKnowledge, 0.05)
	} else {
		am.adjustTrustScore(node.NodeID, FactorKnowledge, -0.1)
	}

	return isValid, nil
}

// VerifyPossessionFactor verifies the possession factor response
func (am *AuthManager) VerifyPossessionFactor(challengeID string, response []byte) (bool, error) {
	am.mu.Lock()
	defer am.mu.Unlock()

	challenge, exists := am.challenges[challengeID]
	if !exists {
		return false, errors.New("challenge not found")
	}

	if challenge.Factor != FactorPossession {
		return false, errors.New("invalid challenge type")
	}

	if time.Now().After(challenge.ExpiresAt) {
		return false, errors.New("challenge expired")
	}

	if challenge.Completed {
		return false, errors.New("challenge already completed")
	}

	node, exists := am.nodes[challenge.NodeID]
	if !exists {
		return false, errors.New("node not found")
	}

	// Verify possession factor
	// In a real system, this might verify a signed token or hardware response
	expectedResponse := sha256.Sum256(append(challenge.Challenge, node.PossessionData...))
	actualResponse := sha256.Sum256(response)

	isValid := compareHashes(expectedResponse[:], actualResponse[:])
	challenge.Completed = true

	// Update trust score for this factor
	if isValid {
		am.adjustTrustScore(node.NodeID, FactorPossession, 0.05)
	} else {
		am.adjustTrustScore(node.NodeID, FactorPossession, -0.1)
	}

	return isValid, nil
}

// VerifyBehavioralFactor verifies the behavioral factor response
func (am *AuthManager) VerifyBehavioralFactor(challengeID string, behavioralData []byte) (bool, error) {
	am.mu.Lock()
	defer am.mu.Unlock()

	challenge, exists := am.challenges[challengeID]
	if !exists {
		return false, errors.New("challenge not found")
	}

	if challenge.Factor != FactorBehavioral {
		return false, errors.New("invalid challenge type")
	}

	if time.Now().After(challenge.ExpiresAt) {
		return false, errors.New("challenge expired")
	}

	if challenge.Completed {
		return false, errors.New("challenge already completed")
	}

	node, exists := am.nodes[challenge.NodeID]
	if !exists {
		return false, errors.New("node not found")
	}

	// If this is the first behavioral data, just store it and approve
	if node.BehavioralData == nil {
		node.BehavioralData = behavioralData
		challenge.Completed = true

		am.adjustTrustScore(node.NodeID, FactorBehavioral, 0.05)
		return true, nil
	}

	// Verify behavioral fingerprint
	// In a real system, this would use more sophisticated behavioral analysis
	similarityScore := calculateBehavioralSimilarity(node.BehavioralData, behavioralData)
	isValid := similarityScore >= 0.7 // 70% similarity threshold

	// Update behavioral data with new sample (if valid)
	if isValid {
		// Blend the new behavioral data with existing data
		node.BehavioralData = blendBehavioralData(node.BehavioralData, behavioralData)
		am.adjustTrustScore(node.NodeID, FactorBehavioral, 0.05*similarityScore)
	} else {
		am.adjustTrustScore(node.NodeID, FactorBehavioral, -0.1)
	}

	challenge.Completed = true
	return isValid, nil
}

// CompleteAuthentication finalizes the authentication process
func (am *AuthManager) CompleteAuthentication(nodeID string, factorResponses map[string][]byte) (*AuthSession, error) {
	// Get challenges for the node
	am.mu.RLock()
	nodeChallenges := make(map[string]*Challenge)
	for _, challenge := range am.challenges {
		if challenge.NodeID == nodeID && !challenge.Completed && time.Now().Before(challenge.ExpiresAt) {
			nodeChallenges[challenge.Factor] = challenge
		}
	}
	am.mu.RUnlock()

	// Verify each factor
	completedFactors := make([]string, 0)

	for factor, response := range factorResponses {
		challenge, exists := nodeChallenges[factor]
		if !exists {
			continue
		}

		var isValid bool
		var err error

		switch factor {
		case FactorKnowledge:
			isValid, err = am.VerifyKnowledgeFactor(challenge.ChallengeID, response)
		case FactorPossession:
			isValid, err = am.VerifyPossessionFactor(challenge.ChallengeID, response)
		case FactorBehavioral:
			isValid, err = am.VerifyBehavioralFactor(challenge.ChallengeID, response)
		default:
			continue
		}

		if err != nil || !isValid {
			// Failed authentication
			am.mu.Lock()
			node := am.nodes[nodeID]
			node.FailedAttempts++
			node.LastAuth = time.Now()
			am.mu.Unlock()

			log.Warn().
				Str("nodeID", nodeID).
				Str("factor", factor).
				Msg("Authentication factor failed")

			return nil, errors.New("authentication failed: " + factor)
		}

		completedFactors = append(completedFactors, factor)
	}

	// Check if enough factors were verified
	if len(completedFactors) < 2 { // Require at least 2 factors
		return nil, errors.New("insufficient authentication factors verified")
	}

	// Create a new session
	am.mu.Lock()
	defer am.mu.Unlock()

	// Reset failed attempts
	node := am.nodes[nodeID]
	node.FailedAttempts = 0
	node.LastAuth = time.Now()

	// Generate session ID
	sessionRaw := make([]byte, 16)
	if _, err := rand.Read(sessionRaw); err != nil {
		return nil, err
	}
	sessionHash := sha256.Sum256(append(sessionRaw, []byte(nodeID+time.Now().String())...))
	sessionID := fmt.Sprintf("%x", sessionHash[:])

	// Create session
	session := &AuthSession{
		NodeID:         nodeID,
		SessionID:      sessionID,
		CreatedAt:      time.Now(),
		ExpiresAt:      time.Now().Add(SessionTimeout),
		LastActivity:   time.Now(),
		Factors:        completedFactors,
		ValidationData: make(map[string]interface{}),
	}

	// Store session
	am.sessions[sessionID] = session

	log.Info().
		Str("nodeID", nodeID).
		Str("sessionID", sessionID).
		Strs("factors", completedFactors).
		Msg("Authentication completed successfully")

	return session, nil
}

// ValidateSession validates an existing session
func (am *AuthManager) ValidateSession(sessionID string) (bool, error) {
	am.mu.Lock()
	defer am.mu.Unlock()

	session, exists := am.sessions[sessionID]
	if !exists {
		return false, errors.New("session not found")
	}

	// Check if session is expired
	if time.Now().After(session.ExpiresAt) {
		delete(am.sessions, sessionID)
		return false, errors.New("session expired")
	}

	// Update last activity
	session.LastActivity = time.Now()

	return true, nil
}

// ValidateMessage validates a signed message from a node
func (am *AuthManager) ValidateMessage(nodeID string, message, signature []byte) (bool, error) {
	am.mu.RLock()
	defer am.mu.RUnlock()

	node, exists := am.nodes[nodeID]
	if !exists {
		return false, errors.New("node not registered")
	}

	// In a real implementation, this would use proper signature verification
	// For demonstration, we'll use a simplified approach

	// Calculate expected signature (hash of message + public key)
	expectedSig := sha256.Sum256(append(message, node.PublicKey...))

	// Compare with provided signature
	isValid := compareHashes(expectedSig[:], signature)

	// Update trust score based on validation result
	if isValid {
		am.adjustTrustScore(nodeID, "message", 0.01)
	} else {
		am.adjustTrustScore(nodeID, "message", -0.05)
	}

	return isValid, nil
}

// GetTrustScore gets the current trust score for a node
func (am *AuthManager) GetTrustScore(nodeID string) (float64, error) {
	am.mu.RLock()
	defer am.mu.RUnlock()

	score, exists := am.trustScores[nodeID]
	if !exists {
		return 0, errors.New("node not registered")
	}

	return score, nil
}

// IsNodeTrusted checks if a node is trusted
func (am *AuthManager) IsNodeTrusted(nodeID string) bool {
	score, err := am.GetTrustScore(nodeID)
	if err != nil {
		return false
	}

	return score >= TrustScoreThreshold
}

// validateNode performs periodic validation of a node
func (am *AuthManager) validateNode(nodeID string) {
	am.mu.Lock()

	node, exists := am.nodes[nodeID]
	if !exists {
		am.mu.Unlock()
		return
	}

	// Record validation time
	node.LastValidation = time.Now()

	// Reset timer for next validation
	timer, exists := am.validationTimers[nodeID]
	if exists && timer != nil {
		timer.Reset(ValidationInterval)
	}

	am.mu.Unlock()

	// Perform validation checks
	// For example, request a quick possession factor verification
	challengeID, err := am.createChallenge(nodeID, FactorPossession)
	if err != nil {
		log.Error().Err(err).Str("nodeID", nodeID).Msg("Failed to create validation challenge")
		return
	}

	log.Info().
		Str("nodeID", nodeID).
		Str("challengeID", challengeID).
		Msg("Periodic node validation initiated")

	// In a real implementation, this would send the challenge to the node
	// and wait for a response
}

// adjustTrustScore adjusts the trust score for a node
func (am *AuthManager) adjustTrustScore(nodeID, factor string, adjustment float64) {
	node, exists := am.nodes[nodeID]
	if !exists {
		return
	}

	// Apply adjustment with factor-specific weighting
	var weightedAdjustment float64

	switch factor {
	case FactorKnowledge, FactorPossession, FactorBehavioral:
		weightedAdjustment = adjustment * FactorWeight
	case "message":
		weightedAdjustment = adjustment * 0.1 // Lower weight for message validations
	default:
		weightedAdjustment = adjustment * 0.05
	}

	// Update trust score
	node.TrustScore += weightedAdjustment

	// Ensure trust score stays within bounds
	if node.TrustScore > 1.0 {
		node.TrustScore = 1.0
	} else if node.TrustScore < 0.0 {
		node.TrustScore = 0.0
	}

	// Update global map
	am.trustScores[nodeID] = node.TrustScore

	log.Debug().
		Str("nodeID", nodeID).
		Str("factor", factor).
		Float64("adjustment", weightedAdjustment).
		Float64("newScore", node.TrustScore).
		Msg("Trust score adjusted")
}

// compareHashes safely compares two hashes with constant time to prevent timing attacks
func compareHashes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	var result byte
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}

	return result == 0
}

// calculateBehavioralSimilarity calculates similarity between behavioral fingerprints
func calculateBehavioralSimilarity(stored, current []byte) float64 {
	if len(stored) != len(current) {
		// If lengths differ, normalize to smaller length
		minLen := min(len(stored), len(current))
		stored = stored[:minLen]
		current = current[:minLen]
	}

	// Calculate similarity score
	var matchCount int
	for i := 0; i < len(stored); i++ {
		// Count bits that match
		xorResult := stored[i] ^ current[i]
		matchCount += 8 - countBits(xorResult)
	}

	totalBits := len(stored) * 8
	return float64(matchCount) / float64(totalBits)
}

// blendBehavioralData blends old and new behavioral data
func blendBehavioralData(old, new []byte) []byte {
	if len(old) != len(new) {
		// If lengths differ, normalize to smaller length
		minLen := min(len(old), len(new))
		old = old[:minLen]
		new = new[:minLen]
	}

	result := make([]byte, len(old))

	// Blend with weight: 70% old, 30% new
	for i := 0; i < len(old); i++ {
		result[i] = byte(float64(old[i])*0.7 + float64(new[i])*0.3)
	}

	return result
}

// countBits counts the number of 1 bits in a byte
func countBits(b byte) int {
	count := 0
	for i := 0; i < 8; i++ {
		if (b & (1 << i)) != 0 {
			count++
		}
	}
	return count
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Close cleans up resources
func (am *AuthManager) Close() {
	am.mu.Lock()
	defer am.mu.Unlock()

	// Stop all validation timers
	for _, timer := range am.validationTimers {
		if timer != nil {
			timer.Stop()
		}
	}
}
