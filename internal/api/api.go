// internal/api/api.go
package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"
)

// APIServer handles HTTP API requests
type APIServer struct {
	components interface{} // Change to *SystemComponents when available
	config     interface{} // Change to *Config when available
	startTime  time.Time
}

// NewAPIServer creates a new API server instance
func NewAPIServer(components interface{}, config interface{}) *APIServer {
	return &APIServer{
		components: components,
		config:     config,
		startTime:  time.Now(),
	}
}

// Start begins the API server
func (s *APIServer) Start(port int) {
	mux := http.NewServeMux()

	// API endpoints
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/blocks", s.handleBlocks)
	mux.HandleFunc("/api/transactions", s.handleTransactions)
	mux.HandleFunc("/api/network", s.handleNetworkStatus)

	addr := fmt.Sprintf(":%d", port)
	log.Info().Int("port", port).Msg("Starting API server")

	go func() {
		if err := http.ListenAndServe(addr, mux); err != nil {
			log.Error().Err(err).Msg("API server failed")
		}
	}()
}

func (s *APIServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	// For now, return mock data. In a real implementation, get data from components
	status := map[string]interface{}{
		"node_id":        "20250426145152.199000632",
		"height":         42,
		"shard_id":       0,
		"peer_count":     5,
		"uptime":         time.Since(s.startTime).String(),
		"is_validator":   true,
		"is_miner":       true,
		"network_health": 0.95,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func (s *APIServer) handleBlocks(w http.ResponseWriter, r *http.Request) {
	// Mock block data
	blocks := []map[string]interface{}{
		{
			"height":    42,
			"hash":      "0xa3f8b2c1d4e5f6a7b8c9d0e1f2a3b4c5",
			"timestamp": time.Now().Add(-10 * time.Minute),
			"txCount":   15,
			"shardID":   0,
		},
		{
			"height":    41,
			"hash":      "0xb2c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7",
			"timestamp": time.Now().Add(-20 * time.Minute),
			"txCount":   12,
			"shardID":   0,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(blocks)
}

func (s *APIServer) handleTransactions(w http.ResponseWriter, r *http.Request) {
	// Mock transaction data
	transactions := []map[string]interface{}{
		{
			"hash":      "0xa3f8b2c1",
			"from":      "0x1234...5678",
			"to":        "0xabcd...ef12",
			"amount":    "10.5",
			"timestamp": time.Now().Add(-5 * time.Minute),
		},
		{
			"hash":      "0xb2c1d4e5",
			"from":      "0xabcd...ef12",
			"to":        "0x5678...1234",
			"amount":    "5.2",
			"timestamp": time.Now().Add(-2 * time.Minute),
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(transactions)
}

func (s *APIServer) handleNetworkStatus(w http.ResponseWriter, r *http.Request) {
	networkStatus := map[string]interface{}{
		"peer_count":         5,
		"network_health":     0.95,
		"active_conflicts":   2,
		"resolved_conflicts": 10,
		"consensus_height":   42,
		"is_synchronized":    true,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(networkStatus)
}
