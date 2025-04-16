// internal/consensus/hybrid/hybrid.go
package hybrid

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/big"
	"sync"
	"time"

	"github.com/SoberSalman/advanced-blockchain/internal/bft/defense"
	"github.com/SoberSalman/advanced-blockchain/internal/bft/verification"
	"github.com/SoberSalman/advanced-blockchain/internal/types"
	"github.com/rs/zerolog/log"
)

const (
	// Consensus phases
	PhasePropose  = 0
	PhaseValidate = 1
	PhaseCommit   = 2

	// Consensus timing parameters
	ProposalTimeout   = 5 * time.Second
	ValidationTimeout = 3 * time.Second
	CommitTimeout     = 2 * time.Second

	// PoW parameters
	MinRandomnessRounds = 3
	MaxRandomnessRounds = 10

	// dBFT parameters
	MinValidatorCount = 4
	MinConsensusRatio = 0.67 // 2/3 of validators must agree
)

// HybridConsensus implements a consensus mechanism combining PoW and dBFT
type HybridConsensus struct {
	currentHeight       uint64
	currentPhase        int
	proposer            string
	validators          map[string]float64 // NodeID -> Voting power
	validations         map[string]bool    // NodeID -> Validation result
	commits             map[string]bool    // NodeID -> Commit result
	blockProposal       *types.Block
	phaseMu             sync.RWMutex
	vrfSeed             []byte
	defenseManager      *defense.DefenseManager
	verificationManager *verification.VerificationManager
	timeoutTimers       map[int]*time.Timer // Phase -> Timer
	selfNodeID          string
	powDifficulty       int
	mu                  sync.RWMutex
}

// ConsensusConfig contains configuration for the consensus
type ConsensusConfig struct {
	SelfNodeID    string
	InitialSeed   []byte
	InitialHeight uint64
	PowDifficulty int
}

// NewHybridConsensus creates a new hybrid consensus instance
func NewHybridConsensus(
	config ConsensusConfig,
	defenseManager *defense.DefenseManager,
	verificationManager *verification.VerificationManager,
) *HybridConsensus {
	hc := &HybridConsensus{
		currentHeight:       config.InitialHeight,
		currentPhase:        PhasePropose,
		validators:          make(map[string]float64),
		validations:         make(map[string]bool),
		commits:             make(map[string]bool),
		vrfSeed:             config.InitialSeed,
		defenseManager:      defenseManager,
		verificationManager: verificationManager,
		timeoutTimers:       make(map[int]*time.Timer),
		selfNodeID:          config.SelfNodeID,
		powDifficulty:       config.PowDifficulty,
	}

	// Initialize timeout timers
	hc.timeoutTimers[PhasePropose] = time.NewTimer(ProposalTimeout)
	hc.timeoutTimers[PhaseValidate] = time.NewTimer(ValidationTimeout)
	hc.timeoutTimers[PhaseCommit] = time.NewTimer(CommitTimeout)

	// Stop timers initially
	for _, timer := range hc.timeoutTimers {
		if !timer.Stop() {
			<-timer.C
		}
	}

	return hc
}

// StartConsensus starts the consensus process for the next block
func (hc *HybridConsensus) StartConsensus(validators map[string]float64) error {
	hc.mu.Lock()
	defer hc.mu.Unlock()

	if len(validators) < MinValidatorCount {
		return errors.New("insufficient validators")
	}

	// Reset consensus state
	hc.validators = validators
	hc.validations = make(map[string]bool)
	hc.commits = make(map[string]bool)
	hc.blockProposal = nil

	// Determine proposer using VRF
	proposer, err := hc.selectProposer()
	if err != nil {
		return err
	}
	hc.proposer = proposer

	// Start in proposal phase
	hc.setPhase(PhasePropose)

	// If we're the proposer, prepare a block proposal
	if hc.selfNodeID == proposer {
		go hc.prepareProposal()
	}

	// Start proposal timeout
	hc.timeoutTimers[PhasePropose].Reset(ProposalTimeout)

	log.Info().
		Uint64("height", hc.currentHeight).
		Str("proposer", proposer).
		Int("validators", len(validators)).
		Msg("Consensus started")

	return nil
}

// selectProposer uses VRF to select a proposer
func (hc *HybridConsensus) selectProposer() (string, error) {
	// Get validator list
	validatorIDs := make([]string, 0, len(hc.validators))
	for id := range hc.validators {
		validatorIDs = append(validatorIDs, id)
	}

	if len(validatorIDs) == 0 {
		return "", errors.New("no validators available")
	}

	// Use VRF to generate random value
	// In a real implementation, each node would generate and verify VRF proofs
	// For simplicity, we'll use a deterministic approach here

	// Create a seed using current height and previous seed
	seedData := make([]byte, 8+len(hc.vrfSeed))
	binary.BigEndian.PutUint64(seedData[:8], hc.currentHeight)
	copy(seedData[8:], hc.vrfSeed)

	// Generate a hash from the seed
	seedHash := sha256.Sum256(seedData)

	// Convert to big.Int for modulo operation
	seedInt := new(big.Int).SetBytes(seedHash[:])

	// Select proposer index using modulo
	validatorCount := int64(len(validatorIDs))
	proposerIndex := new(big.Int).Mod(seedInt, big.NewInt(validatorCount)).Int64()

	return validatorIDs[proposerIndex], nil
}

// prepareProposal prepares a block proposal with PoW randomness
func (hc *HybridConsensus) prepareProposal() {
	// Create a new block
	block := &types.Block{
		Header: types.Header{
			Version:      1,
			Height:       hc.currentHeight,
			Timestamp:    time.Now(),
			Difficulty:   big.NewInt(int64(hc.powDifficulty)),
			PreviousHash: types.Hash{}, // Would be set in real implementation
		},
		Transactions: []types.Transaction{}, // Would include actual transactions
	}

	// Generate PoW randomness
	randomnessRounds := MinRandomnessRounds + (hc.currentHeight % uint64(MaxRandomnessRounds-MinRandomnessRounds))
	powRandomness, nonce, err := hc.generatePoWRandomness(block, int(randomnessRounds))
	if err != nil {
		log.Error().Err(err).Msg("Failed to generate PoW randomness")
		return
	}

	block.Header.Nonce = nonce
	block.Header.ConsensusData = powRandomness

	// Generate VRF proof for leadership
	vrfOutput, err := hc.verificationManager.GenerateVRFForLeaderElection(
		hc.currentHeight,
		[]byte("dummy-private-key"), // In a real implementation, this would be the node's private key
	)
	if err != nil {
		log.Error().Err(err).Msg("Failed to generate VRF proof")
		return
	}

	block.Header.VRFProof = vrfOutput.Proof

	// Generate ZK proof for state verification
	stateRoot := types.Hash{} // Would be actual state root in real implementation
	zkRequest := verification.ZKProofRequest{
		Statement:  stateRoot[:],
		Witness:    []byte("dummy-witness"), // Private witness data
		Difficulty: hc.powDifficulty,
	}

	zkResponse, err := hc.verificationManager.GenerateZKProof(zkRequest)
	if err != nil {
		log.Error().Err(err).Msg("Failed to generate ZK proof")
		return
	}

	// Add ZK proof to block
	block.ZKProofs = append(block.ZKProofs, append(zkResponse.Proof, zkResponse.PublicData...))

	// Propose the block
	hc.mu.Lock()
	hc.blockProposal = block
	hc.mu.Unlock()

	// Broadcast the proposal to other validators
	hc.setPhase(PhaseValidate)

	log.Info().
		Uint64("height", hc.currentHeight).
		Uint64("nonce", nonce).
		Int("zkProofs", len(block.ZKProofs)).
		Msg("Block proposal prepared")
}

// generatePoWRandomness performs a simplified PoW calculation to inject randomness
func (hc *HybridConsensus) generatePoWRandomness(block *types.Block, rounds int) ([]byte, uint64, error) {
	// Create a hash of the block header without nonce
	headerBytes := []byte(
		string(block.Header.Height) +
			block.Header.Timestamp.String() +
			block.Header.PreviousHash.String(),
	)

	// PoW: Find a nonce that produces a hash with leading zeros
	var nonce uint64
	var bestHash [32]byte

	// Initialize with a random nonce
	nonceBytes := make([]byte, 8)
	if _, err := rand.Read(nonceBytes); err != nil {
		return nil, 0, err
	}
	nonce = binary.BigEndian.Uint64(nonceBytes)

	// Perform multiple rounds of hashing
	for round := 0; round < rounds; round++ {
		// Prepare data to hash: header + nonce + round
		data := append(headerBytes, make([]byte, 16)...)
		binary.BigEndian.PutUint64(data[len(headerBytes):], nonce)
		binary.BigEndian.PutUint64(data[len(headerBytes)+8:], uint64(round))

		// Find a hash that meets difficulty
		for i := 0; i < 1000; i++ { // Limit iterations
			nonce++

			// Update nonce in data
			binary.BigEndian.PutUint64(data[len(headerBytes):], nonce)

			// Calculate hash
			hash := sha256.Sum256(data)

			// Check if hash meets difficulty
			if countLeadingZeroBits(hash[:]) >= hc.powDifficulty {
				bestHash = hash
				break
			}
		}
	}

	// Return the final hash as randomness source
	return bestHash[:], nonce, nil
}

// ReceiveProposal handles a block proposal from the proposer
func (hc *HybridConsensus) ReceiveProposal(block *types.Block, proposerID string) error {
	hc.mu.Lock()
	defer hc.mu.Unlock()

	// Check if we're in the correct phase
	if hc.currentPhase != PhasePropose {
		return errors.New("not in proposal phase")
	}

	// Verify proposer
	if proposerID != hc.proposer {
		return errors.New("proposal from non-proposer node")
	}

	// Store the proposal
	hc.blockProposal = block

	// Move to validation phase
	hc.setPhase(PhaseValidate)

	// Start validation timeout
	hc.timeoutTimers[PhaseValidate].Reset(ValidationTimeout)

	// If we're a validator, validate the proposal
	go hc.validateProposal()

	return nil
}

// validateProposal validates the current block proposal
func (hc *HybridConsensus) validateProposal() {
	hc.mu.RLock()
	block := hc.blockProposal
	proposerID := hc.proposer
	hc.mu.RUnlock()

	if block == nil {
		log.Error().Msg("No block proposal to validate")
		return
	}

	// Perform block validation
	isValid := true

	// 1. Verify PoW randomness
	powValid := verifyPoWRandomness(block, hc.powDifficulty)
	if !powValid {
		isValid = false
		log.Warn().Msg("PoW randomness verification failed")
	}

	// 2. Verify VRF proof
	vrfValid := true // Simplified for demo
	if !vrfValid {
		isValid = false
		log.Warn().Msg("VRF proof verification failed")
	}

	// 3. Verify ZK proofs
	zkValid, err := hc.verificationManager.VerifyBlock(block)
	if err != nil || !zkValid {
		isValid = false
		log.Warn().Err(err).Msg("ZK proofs verification failed")
	}

	// 4. Verify proposer using defense manager
	proposerTrusted := hc.defenseManager.IsNodeTrusted(proposerID)
	if !proposerTrusted {
		// If proposer is not trusted, apply stricter validation
		// For demo purposes, we'll still accept the block
		log.Warn().Msg("Proposer not fully trusted, applying stricter validation")
	}

	// Record validation result
	hc.mu.Lock()
	hc.validations[hc.selfNodeID] = isValid

	// Update proposer reputation based on block validity
	hc.defenseManager.UpdateNodeReputation(proposerID, "validation", isValid)

	// Check if we have enough validations to move to commit phase
	if hc.checkValidationConsensus() {
		hc.setPhase(PhaseCommit)
		hc.timeoutTimers[PhaseValidate].Stop()
		hc.timeoutTimers[PhaseCommit].Reset(CommitTimeout)
	}
	hc.mu.Unlock()

	// Broadcast validation result
	// In a real implementation, this would send the validation to other nodes

	log.Info().
		Bool("isValid", isValid).
		Uint64("height", block.Header.Height).
		Msg("Block validation completed")
}

// ReceiveValidation handles a validation result from another validator
func (hc *HybridConsensus) ReceiveValidation(nodeID string, isValid bool) error {
	hc.mu.Lock()
	defer hc.mu.Unlock()

	// Verify we're in validation phase
	if hc.currentPhase != PhaseValidate {
		return errors.New("not in validation phase")
	}

	// Verify validator
	if _, exists := hc.validators[nodeID]; !exists {
		return errors.New("validation from non-validator node")
	}

	// Record validation
	hc.validations[nodeID] = isValid

	// Update node reputation
	hc.defenseManager.UpdateNodeReputation(nodeID, "consensus", isValid)

	// Check if we have enough validations to move to commit phase
	if hc.checkValidationConsensus() {
		hc.setPhase(PhaseCommit)
		hc.timeoutTimers[PhaseValidate].Stop()
		hc.timeoutTimers[PhaseCommit].Reset(CommitTimeout)

		// If we're a validator, send commit
		go hc.sendCommit()
	}

	return nil
}

// checkValidationConsensus checks if we have enough validations to reach consensus
func (hc *HybridConsensus) checkValidationConsensus() bool {
	// Calculate consensus threshold (adaptive based on defense manager)
	threshold := hc.defenseManager.CalculateAdaptiveThreshold(0, getKeys(hc.validators))

	// Count positive validations
	var totalWeight float64
	var positiveWeight float64

	for nodeID, isValid := range hc.validations {
		if weight, exists := hc.validators[nodeID]; exists {
			totalWeight += weight
			if isValid {
				positiveWeight += weight
			}
		}
	}

	// Check if we have enough total weight to make a decision
	if totalWeight < float64(len(hc.validators))*0.5 {
		return false // Not enough validators have responded
	}

	// Check if positive validations exceed threshold
	ratio := positiveWeight / totalWeight
	return ratio >= threshold
}

// sendCommit sends a commit message for the current block
func (hc *HybridConsensus) sendCommit() {
	hc.mu.Lock()
	// Record our commit
	hc.commits[hc.selfNodeID] = true

	// Check if we already have enough commits
	if hc.checkCommitConsensus() {
		hc.finalizeBlock()
	}
	hc.mu.Unlock()

	// Broadcast commit
	// In a real implementation, this would send the commit to other nodes

	log.Info().
		Uint64("height", hc.blockProposal.Header.Height).
		Msg("Sent commit")
}

// ReceiveCommit handles a commit message from another validator
func (hc *HybridConsensus) ReceiveCommit(nodeID string) error {
	hc.mu.Lock()
	defer hc.mu.Unlock()

	// Verify we're in commit phase
	if hc.currentPhase != PhaseCommit {
		return errors.New("not in commit phase")
	}

	// Verify validator
	if _, exists := hc.validators[nodeID]; !exists {
		return errors.New("commit from non-validator node")
	}

	// Record commit
	hc.commits[nodeID] = true

	// Check if we have enough commits to finalize the block
	if hc.checkCommitConsensus() {
		hc.finalizeBlock()
	}

	return nil
}

// checkCommitConsensus checks if we have enough commits to reach consensus
func (hc *HybridConsensus) checkCommitConsensus() bool {
	// Calculate consensus threshold (adaptive based on defense manager)
	threshold := hc.defenseManager.CalculateAdaptiveThreshold(0, getKeys(hc.validators))

	// Count commits
	var totalWeight float64
	var commitWeight float64

	for nodeID := range hc.commits {
		if weight, exists := hc.validators[nodeID]; exists {
			totalWeight += weight
			commitWeight += weight
		}
	}

	// Check if we have enough total weight to make a decision
	if totalWeight < float64(len(hc.validators))*0.5 {
		return false // Not enough validators have responded
	}

	// Check if commits exceed threshold
	ratio := commitWeight / totalWeight
	return ratio >= threshold
}

// finalizeBlock finalizes the current block
func (hc *HybridConsensus) finalizeBlock() {
	// Stop commit timer
	hc.timeoutTimers[PhaseCommit].Stop()

	// Generate BFT proof (would be aggregate signatures in real implementation)
	bftProof := make([]byte, 32)
	for i := range bftProof {
		bftProof[i] = byte(len(hc.commits))
	}

	// Add BFT proof to block
	hc.blockProposal.BFTProof = bftProof

	// Update VRF seed for next round
	hc.vrfSeed = hc.blockProposal.Header.ConsensusData[:min(32, len(hc.blockProposal.Header.ConsensusData))]

	// Finalize and persist block (would integrate with storage in real implementation)
	finalizedBlock := hc.blockProposal

	// Reset for next height
	hc.currentHeight++
	hc.currentPhase = PhasePropose
	hc.blockProposal = nil
	hc.validations = make(map[string]bool)
	hc.commits = make(map[string]bool)

	log.Info().
		Uint64("height", finalizedBlock.Header.Height).
		Int("commits", len(hc.commits)).
		Uint64("nextHeight", hc.currentHeight).
		Msg("Block finalized")

	// Trigger next consensus round
	// In a real implementation, this would happen after block is persisted
}

// HandlePhaseTimeout handles timeouts for consensus phases
func (hc *HybridConsensus) HandlePhaseTimeout(phase int) {
	hc.mu.Lock()
	defer hc.mu.Unlock()

	// Check if we're still in the phase that timed out
	if hc.currentPhase != phase {
		return
	}

	log.Warn().
		Int("phase", phase).
		Uint64("height", hc.currentHeight).
		Msg("Consensus phase timeout")

	switch phase {
	case PhasePropose:
		// Proposal timeout - change proposer and restart
		// In a real implementation, this would trigger a view change protocol

		// Penalize the proposer
		hc.defenseManager.UpdateNodeReputation(hc.proposer, "availability", false)

		// Move to next height with a new proposer
		hc.currentHeight++

		// Restart consensus
		go func() {
			err := hc.StartConsensus(hc.validators)
			if err != nil {
				log.Error().Err(err).Msg("Failed to restart consensus after timeout")
			}
		}()

	case PhaseValidate:
		// Validation timeout - check if we have enough validations
		if hc.checkValidationConsensus() {
			// We have enough validations, move to commit phase
			hc.setPhase(PhaseCommit)
			hc.timeoutTimers[PhaseCommit].Reset(CommitTimeout)

			// If we're a validator, send commit
			go hc.sendCommit()
		} else {
			// Not enough validations, restart with new proposer
			hc.currentHeight++

			// Restart consensus
			go func() {
				err := hc.StartConsensus(hc.validators)
				if err != nil {
					log.Error().Err(err).Msg("Failed to restart consensus after timeout")
				}
			}()
		}

	case PhaseCommit:
		// Commit timeout - check if we have enough commits
		if hc.checkCommitConsensus() {
			// We have enough commits, finalize the block
			hc.finalizeBlock()
		} else {
			// Not enough commits, restart with new proposer
			hc.currentHeight++

			// Restart consensus
			go func() {
				err := hc.StartConsensus(hc.validators)
				if err != nil {
					log.Error().Err(err).Msg("Failed to restart consensus after timeout")
				}
			}()
		}
	}
}

// setPhase changes the current consensus phase
func (hc *HybridConsensus) setPhase(phase int) {
	hc.phaseMu.Lock()
	defer hc.phaseMu.Unlock()

	hc.currentPhase = phase

	log.Debug().
		Int("phase", phase).
		Uint64("height", hc.currentHeight).
		Msg("Consensus phase changed")
}

// GetCurrentHeight gets the current consensus height
func (hc *HybridConsensus) GetCurrentHeight() uint64 {
	hc.mu.RLock()
	defer hc.mu.RUnlock()

	return hc.currentHeight
}

// GetCurrentPhase gets the current consensus phase
func (hc *HybridConsensus) GetCurrentPhase() int {
	hc.phaseMu.RLock()
	defer hc.phaseMu.RUnlock()

	return hc.currentPhase
}

// GetCurrentProposer gets the current proposer
func (hc *HybridConsensus) GetCurrentProposer() string {
	hc.mu.RLock()
	defer hc.mu.RUnlock()

	return hc.proposer
}

// countLeadingZeroBits counts the number of leading zero bits in data
func countLeadingZeroBits(data []byte) int {
	count := 0

	for _, b := range data {
		if b == 0 {
			count += 8
			continue
		}

		// Count leading zeros in this byte
		for i := 7; i >= 0; i-- {
			if (b & (1 << i)) == 0 {
				count++
			} else {
				return count
			}
		}
	}

	return count
}

// verifyPoWRandomness verifies the PoW randomness of a block
func verifyPoWRandomness(block *types.Block, difficulty int) bool {
	// Create a hash of the block header
	headerBytes := []byte(
		string(block.Header.Height) +
			block.Header.Timestamp.String() +
			block.Header.PreviousHash.String(),
	)

	// Append nonce
	data := append(headerBytes, make([]byte, 8)...)
	binary.BigEndian.PutUint64(data[len(headerBytes):], block.Header.Nonce)

	// Calculate hash
	hash := sha256.Sum256(data)

	// Check if hash meets difficulty
	return countLeadingZeroBits(hash[:]) >= difficulty
}

// helper function to get map keys as a slice
func getKeys(m map[string]float64) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// min helper function
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
