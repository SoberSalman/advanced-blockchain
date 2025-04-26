// internal/network/p2p/node.go
package p2p

import (
	"context"
	"fmt"

	"github.com/rs/zerolog/log"
)

// Config contains configuration for the P2P node
type Config struct {
	NodeID         string
	ListenAddr     string
	BootstrapNodes []string
}

// Node represents a P2P network node
type Node struct {
	config     Config
	isRunning  bool
	ctx        context.Context
	cancelFunc context.CancelFunc
}

// NewNode creates a new P2P node
func NewNode(ctx context.Context, config Config) (*Node, error) {
	// Create a derived context that can be canceled when the node stops
	nodeCtx, cancelFunc := context.WithCancel(ctx)

	node := &Node{
		config:     config,
		isRunning:  false,
		ctx:        nodeCtx,
		cancelFunc: cancelFunc,
	}

	return node, nil
}

// Start starts the P2P node
func (n *Node) Start(ctx context.Context) error {
	if n.isRunning {
		return fmt.Errorf("node already running")
	}

	log.Info().
		Str("nodeID", n.config.NodeID).
		Str("listenAddr", n.config.ListenAddr).
		Msg("Starting P2P node")

	// In a real implementation, this would initialize the P2P network
	// For this demo, we'll just set the running flag
	n.isRunning = true

	// Simulate bootstrapping with bootstrap nodes
	if len(n.config.BootstrapNodes) > 0 {
		log.Info().
			Strs("bootstrapNodes", n.config.BootstrapNodes).
			Msg("Connecting to bootstrap nodes")
	}

	return nil
}

// Stop stops the P2P node
func (n *Node) Stop() error {
	if !n.isRunning {
		return nil
	}

	log.Info().Msg("Stopping P2P node")

	// Cancel the node context to signal all operations to stop
	n.cancelFunc()

	n.isRunning = false
	return nil
}

// Broadcast broadcasts a message to the network
func (n *Node) Broadcast(topic string, data []byte) error {
	if !n.isRunning {
		return fmt.Errorf("node not running")
	}

	log.Debug().
		Str("topic", topic).
		Int("dataSize", len(data)).
		Msg("Broadcasting message")

	// In a real implementation, this would publish to the P2P network
	return nil
}

// Subscribe subscribes to messages on a topic
func (n *Node) Subscribe(topic string) (<-chan []byte, error) {
	if !n.isRunning {
		return nil, fmt.Errorf("node not running")
	}

	log.Debug().
		Str("topic", topic).
		Msg("Subscribing to topic")

	// Create a channel for messages
	msgChan := make(chan []byte, 100)

	// In a real implementation, this would set up a subscription
	// For this demo, we'll just return the channel

	return msgChan, nil
}

// GetPeerCount returns the number of connected peers
func (n *Node) GetPeerCount() int {
	// In a real implementation, this would return the actual peer count
	return 0
}

// GetNodeID returns the node's ID
func (n *Node) GetNodeID() string {
	return n.config.NodeID
}

// IsRunning returns whether the node is running
func (n *Node) IsRunning() bool {
	return n.isRunning
}
