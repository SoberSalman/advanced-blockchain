// internal/types/types.go
package types

import (
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"time"
)

// Hash represents a 32-byte hash
type Hash [32]byte

// NewHash creates a new Hash from a byte slice
func NewHash(data []byte) Hash {
	return sha256.Sum256(data)
}

// String returns the hash as a hexadecimal string
func (h Hash) String() string {
	return hex.EncodeToString(h[:])
}

// Address represents a 20-byte address
type Address [20]byte

// String returns the address as a hexadecimal string
func (a Address) String() string {
	return hex.EncodeToString(a[:])
}

// Transaction represents a blockchain transaction
type Transaction struct {
	From      Address
	To        Address
	Value     *big.Int
	Nonce     uint64
	Data      []byte
	Timestamp time.Time
	Signature []byte
}

// Header represents a block header
type Header struct {
	Version         uint64
	PreviousHash    Hash
	MerkleRoot      Hash
	StateRoot       Hash
	ReceiptsRoot    Hash
	Timestamp       time.Time
	Height          uint64
	Difficulty      *big.Int
	Nonce           uint64
	ShardID         uint64
	ForestRoot      Hash   // Root of the Adaptive Merkle Forest
	ConsensusData   []byte // Consensus specific data
	VRFProof        []byte // Verifiable Random Function proof
	ZKProofHash     Hash   // Hash of zero-knowledge proofs
	AccumulatorRoot Hash   // Root of cryptographic accumulator
}

// Block represents a full block
type Block struct {
	Header       Header
	Transactions []Transaction
	Signature    []byte            // Block proposer's signature
	BFTProof     []byte            // Byzantine Fault Tolerance proof
	ShardInfo    *ShardInfo        // Information about the shard this block belongs to
	ZKProofs     [][]byte          // Zero-knowledge proofs for state verification
	VectorClock  map[uint64]uint64 // Vector clock for causal consistency
	EntropyScore float64           // Entropy-based validation score
}

// ShardInfo contains information about a shard
type ShardInfo struct {
	ID                uint64
	Parent            uint64
	Children          []uint64
	StateRootHash     Hash
	TransactionCount  uint64
	NodeCount         uint64
	ComputationalLoad float64
}

// Node represents a network node
type Node struct {
	ID              string
	Address         Address
	PublicKey       []byte
	TrustScore      float64
	ReputationScore float64
	LastSeen        time.Time
	ShardIDs        []uint64 // Shards this node participates in
	Capabilities    uint32   // Bitfield of node capabilities
	VectorClock     map[uint64]uint64
}

// ForestNode represents a node in the Adaptive Merkle Forest
type ForestNode struct {
	Hash      Hash
	ShardID   uint64
	Children  []Hash
	Timestamp time.Time
	Height    uint64
	Metadata  map[string]interface{}
}

// State represents the blockchain state
type State struct {
	Accounts       map[Address]*Account
	ShardStructure map[uint64]*ShardInfo
	ForestRoot     Hash
	Height         uint64
	Timestamp      time.Time
}

// Account represents an account in the state
type Account struct {
	Address     Address
	Balance     *big.Int
	Nonce       uint64
	StorageRoot Hash
	CodeHash    Hash
	StorageTrie map[Hash][]byte
}

// ConsensusState tracks the consensus state
type ConsensusState struct {
	CurrentHeight   uint64
	CurrentProposer string
	Validators      map[string]float64 // NodeID -> Voting power
	VRFSeed         []byte
	ThresholdValue  float64
	VectorClock     map[uint64]uint64
	Timestamp       time.Time
}

// MerkleProof represents a proof in the Adaptive Merkle Forest
type MerkleProof struct {
	Root        Hash
	Leaf        Hash
	Siblings    []Hash
	Path        []byte
	ShardID     uint64
	Compression uint8  // Compression level used
	AMQProof    []byte // Approximate Membership Query proof
}

// NetworkStats represents network statistics for CAP optimization
type NetworkStats struct {
	PartitionProbability float64
	AverageLatency       time.Duration
	NodeCount            uint64
	MessageFailureRate   float64
	ConsistencyLevel     float64
	ShardSyncStatus      map[uint64]time.Time
}

// ConflictInfo represents information about a conflict
type ConflictInfo struct {
	Transactions    []Transaction
	EntropyScore    float64
	VectorClocks    []map[uint64]uint64
	ResolutionState uint8
	ShardIDs        []uint64
}
