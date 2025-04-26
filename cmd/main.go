// cmd/main.go
package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/SoberSalman/advanced-blockchain/internal/amf/sharding"
	"github.com/SoberSalman/advanced-blockchain/internal/amf/synchronization"
	"github.com/SoberSalman/advanced-blockchain/internal/amf/verification"
	"github.com/SoberSalman/advanced-blockchain/internal/api"
	"github.com/SoberSalman/advanced-blockchain/internal/bft/defense"
	bftVerification "github.com/SoberSalman/advanced-blockchain/internal/bft/verification"
	"github.com/SoberSalman/advanced-blockchain/internal/blockchain/block"
	"github.com/SoberSalman/advanced-blockchain/internal/blockchain/state"
	"github.com/SoberSalman/advanced-blockchain/internal/cap/conflict"
	"github.com/SoberSalman/advanced-blockchain/internal/cap/consistency"
	"github.com/SoberSalman/advanced-blockchain/internal/consensus/authentication"
	"github.com/SoberSalman/advanced-blockchain/internal/consensus/hybrid"
	"github.com/SoberSalman/advanced-blockchain/internal/dashboard"
	"github.com/SoberSalman/advanced-blockchain/internal/network/p2p"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type Config struct {
	LogLevel         string
	NodeID           string
	ListenAddr       string
	BootstrapNodes   []string
	DataDir          string
	ShardID          uint64
	ValidatorEnabled bool
	MinerEnabled     bool
	PoWDifficulty    int
	ConsensusTimeout time.Duration
	APIPort          int
	EnableDashboard  bool
}

func main() {
	// Parse command line flags
	config := parseFlags()

	// Configure logging
	setupLogging(config.LogLevel)

	// Log startup info
	log.Info().
		Str("nodeID", config.NodeID).
		Str("listenAddr", config.ListenAddr).
		Uint64("shardID", config.ShardID).
		Bool("validator", config.ValidatorEnabled).
		Bool("miner", config.MinerEnabled).
		Msg("Starting advanced blockchain node")

	// Create context that can be canceled on shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize system components
	components, err := initializeComponents(ctx, config)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to initialize blockchain components")
	}

	// Start API server if enabled
	if config.APIPort > 0 {
		apiServer := api.NewAPIServer(components, config)
		apiServer.Start(config.APIPort)
		log.Info().Int("port", config.APIPort).Msg("API server started")
	}

	// Start dashboard if enabled
	if config.EnableDashboard {
		dashboardPort := config.APIPort + 1
		dashboardServer := dashboard.NewDashboardServer(components, config, config.APIPort)
		dashboardServer.Start(dashboardPort)
		log.Info().Int("port", dashboardPort).Msg("Dashboard started")
	}

	// Setup shutdown handler
	shutdownCh := setupSignalHandler()

	// Start main node operations
	log.Info().Msg("Node started successfully")

	// Block until shutdown signal received
	<-shutdownCh
	log.Info().Msg("Shutdown signal received, stopping node...")

	// Shutdown gracefully
	cancel() // Cancel context to signal all components to stop

	// Give components time to shut down gracefully
	time.Sleep(2 * time.Second)

	log.Info().Msg("Node shutdown complete")
}

func parseFlags() *Config {
	config := &Config{}

	flag.StringVar(&config.LogLevel, "log-level", "info", "Logging level (debug, info, warn, error)")
	flag.StringVar(&config.NodeID, "node-id", "", "Unique node identifier")
	flag.StringVar(&config.ListenAddr, "listen", ":9000", "Listen address for P2P communication")
	flag.StringVar(&config.DataDir, "datadir", "./data", "Data directory for blockchain data")
	flag.Uint64Var(&config.ShardID, "shard", 0, "Shard ID to participate in")
	flag.BoolVar(&config.ValidatorEnabled, "validator", false, "Enable validator mode")
	flag.BoolVar(&config.MinerEnabled, "miner", false, "Enable miner mode")
	flag.IntVar(&config.PoWDifficulty, "difficulty", 4, "PoW difficulty level")
	flag.IntVar(&config.APIPort, "api-port", 8545, "API server port")
	flag.BoolVar(&config.EnableDashboard, "dashboard", false, "Enable web dashboard")

	// Parse bootstrap nodes as a comma-separated list
	var bootstrapNodesStr string
	flag.StringVar(&bootstrapNodesStr, "bootstrap", "", "Comma-separated list of bootstrap nodes")

	flag.DurationVar(&config.ConsensusTimeout, "consensus-timeout", 30*time.Second, "Consensus timeout")

	flag.Parse()

	// Generate random node ID if not provided
	if config.NodeID == "" {
		config.NodeID = generateRandomNodeID()
		log.Info().Str("nodeID", config.NodeID).Msg("Generated random node ID")
	}

	// Parse bootstrap nodes
	if bootstrapNodesStr != "" {
		config.BootstrapNodes = parseBootstrapNodes(bootstrapNodesStr)
	}

	return config
}

func setupLogging(logLevel string) {
	// Configure zerolog
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	// Set log level
	switch logLevel {
	case "debug":
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	case "info":
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	case "warn":
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	case "error":
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	default:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}

	// Output to console
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
}

func initializeComponents(ctx context.Context, config *Config) (*SystemComponents, error) {
	components := &SystemComponents{}

	// Initialize AMF components
	components.ShardManager = sharding.NewShardManager()
	components.ProofVerifier = verification.NewProofVerifier()
	components.SyncManager = synchronization.NewSyncManager()

	// Initialize BFT components
	components.DefenseManager = defense.NewDefenseManager()
	components.VerificationManager = bftVerification.NewVerificationManager()

	// Initialize CAP components
	components.ConsistencyOrchestrator = consistency.NewConsistencyOrchestrator()
	components.ConflictManager = conflict.NewConflictManager()

	// Initialize Consensus components
	components.AuthManager = authentication.NewAuthManager()

	// Initialize blockchain components
	components.BlockManager = block.NewBlockManager()
	components.StateManager = state.NewStateManager()

	// Initialize P2P network
	p2pConfig := p2p.Config{
		NodeID:         config.NodeID,
		ListenAddr:     config.ListenAddr,
		BootstrapNodes: config.BootstrapNodes,
	}

	p2pNode, err := p2p.NewNode(ctx, p2pConfig)
	if err != nil {
		return nil, err
	}
	components.P2PNode = p2pNode

	// Start P2P node
	err = p2pNode.Start(ctx)
	if err != nil {
		return nil, err
	}

	// Initialize hybrid consensus engine
	consensusConfig := hybrid.ConsensusConfig{
		SelfNodeID:    config.NodeID,
		InitialSeed:   []byte(config.NodeID), // Simple seed for demonstration
		InitialHeight: 0,
		PowDifficulty: config.PoWDifficulty,
	}

	components.ConsensusEngine = hybrid.NewHybridConsensus(
		consensusConfig,
		components.DefenseManager,
		components.VerificationManager,
	)

	// Initialize genesis state
	_, err = components.StateManager.CreateGenesisState()
	if err != nil {
		return nil, err
	}

	// Start necessary background processes
	// In a full implementation, there would be more initialization here

	return components, nil
}

func setupSignalHandler() <-chan struct{} {
	shutdownCh := make(chan struct{})
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-signalCh
		close(shutdownCh)
	}()

	return shutdownCh
}

// Helper functions

func generateRandomNodeID() string {
	// Simple implementation for demonstration
	// In a real system, this would use a more sophisticated approach
	return time.Now().Format("20060102150405.000000000")
}

func parseBootstrapNodes(bootstrapNodesStr string) []string {
	// Simple implementation - parse comma-separated bootstrap nodes
	// You can improve this to properly parse comma-separated addresses
	if bootstrapNodesStr == "" {
		return []string{}
	}
	return []string{bootstrapNodesStr}
}
