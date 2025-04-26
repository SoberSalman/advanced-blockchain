// internal/dashboard/dashboard.go
package dashboard

import (
	"fmt"
	"net/http"

	"github.com/rs/zerolog/log"
)

// DashboardServer handles the web dashboard
type DashboardServer struct {
	components interface{} // Change to *SystemComponents when available
	config     interface{} // Change to *Config when available
	apiPort    int
}

// NewDashboardServer creates a new dashboard server
func NewDashboardServer(components interface{}, config interface{}, apiPort int) *DashboardServer {
	return &DashboardServer{
		components: components,
		config:     config,
		apiPort:    apiPort,
	}
}

// Start starts the dashboard server
func (s *DashboardServer) Start(port int) {
	mux := http.NewServeMux()

	// Dashboard routes
	mux.HandleFunc("/", s.serveDashboard)

	addr := fmt.Sprintf(":%d", port)
	log.Info().Int("port", port).Msg("Starting dashboard server")

	go func() {
		if err := http.ListenAndServe(addr, mux); err != nil {
			log.Error().Err(err).Msg("Dashboard server failed")
		}
	}()
}

func (s *DashboardServer) serveDashboard(w http.ResponseWriter, r *http.Request) {
	dashboardHTML := `
<!DOCTYPE html>
<html>
<head>
    <title>Advanced Blockchain Dashboard</title>
    <style>
        body { 
            font-family: Arial, sans-serif; 
            margin: 0; 
            padding: 20px; 
            background: #f0f2f5; 
        }
        .container { 
            max-width: 1200px; 
            margin: 0 auto; 
        }
        .header { 
            background: white; 
            padding: 20px; 
            border-radius: 8px; 
            margin-bottom: 20px; 
            box-shadow: 0 2px 4px rgba(0,0,0,0.1); 
        }
        .grid { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); 
            gap: 20px; 
        }
        .card { 
            background: white; 
            border-radius: 8px; 
            padding: 20px; 
            box-shadow: 0 2px 4px rgba(0,0,0,0.1); 
        }
        .card h2 { 
            margin-top: 0; 
            font-size: 18px; 
            color: #333; 
        }
        .stat-value { 
            font-size: 32px; 
            font-weight: bold; 
            color: #3498db; 
            margin: 10px 0; 
        }
        table { 
            width: 100%; 
            border-collapse: collapse; 
            margin-top: 10px; 
        }
        th, td { 
            padding: 10px; 
            text-align: left; 
            border-bottom: 1px solid #ddd; 
        }
        th { 
            background: #f8f9fa; 
        }
        .status-indicator { 
            display: inline-block; 
            width: 10px; 
            height: 10px; 
            border-radius: 50%; 
            margin-right: 5px; 
        }
        .status-good { background: #2ecc71; }
        .status-warning { background: #f39c12; }
        .status-error { background: #e74c3c; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Advanced Blockchain Dashboard</h1>
            <div>
                <span class="status-indicator status-good"></span>
                <span id="connection-status">Connected</span>
            </div>
        </div>

        <div class="grid">
            <div class="card">
                <h2>Node Information</h2>
                <div class="stat-value" id="node-id">Loading...</div>
                <div><strong>Height:</strong> <span id="chain-height">0</span></div>
                <div><strong>Shard:</strong> <span id="shard-id">0</span></div>
                <div><strong>Peers:</strong> <span id="peer-count">0</span></div>
                <div><strong>Uptime:</strong> <span id="uptime">0s</span></div>
            </div>

            <div class="card">
                <h2>Network Health</h2>
                <div class="stat-value" id="network-health">0%</div>
                <div>Active Conflicts: <span id="active-conflicts">0</span></div>
                <div>Resolved Conflicts: <span id="resolved-conflicts">0</span></div>
            </div>

            <div class="card">
                <h2>Consensus Status</h2>
                <div class="stat-value" id="consensus-height">0</div>
                <div>Validator: <span id="is-validator">false</span></div>
                <div>Miner: <span id="is-miner">false</span></div>
            </div>
        </div>

        <div class="card">
            <h2>Recent Blocks</h2>
            <table>
                <thead>
                    <tr>
                        <th>Height</th>
                        <th>Hash</th>
                        <th>Timestamp</th>
                        <th>Transactions</th>
                    </tr>
                </thead>
                <tbody id="blocks-table">
                    <!-- Blocks will be populated here -->
                </tbody>
            </table>
        </div>

        <div class="card">
            <h2>Recent Transactions</h2>
            <table>
                <thead>
                    <tr>
                        <th>Hash</th>
                        <th>From</th>
                        <th>To</th>
                        <th>Amount</th>
                        <th>Timestamp</th>
                    </tr>
                </thead>
                <tbody id="transactions-table">
                    <!-- Transactions will be populated here -->
                </tbody>
            </table>
        </div>
    </div>

    <script>
        const apiPort = ` + fmt.Sprintf("%d", s.apiPort) + `;
        
        function updateDashboard() {
            // Fetch node status
            fetch('http://localhost:' + apiPort + '/api/status')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('node-id').textContent = data.node_id.substring(0, 8) + '...';
                    document.getElementById('chain-height').textContent = data.height;
                    document.getElementById('shard-id').textContent = data.shard_id;
                    document.getElementById('peer-count').textContent = data.peer_count;
                    document.getElementById('uptime').textContent = data.uptime;
                    document.getElementById('network-health').textContent = (data.network_health * 100).toFixed(1) + '%';
                    document.getElementById('is-validator').textContent = data.is_validator;
                    document.getElementById('is-miner').textContent = data.is_miner;
                });

            // Fetch network status
            fetch('http://localhost:' + apiPort + '/api/network')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('active-conflicts').textContent = data.active_conflicts;
                    document.getElementById('resolved-conflicts').textContent = data.resolved_conflicts;
                    document.getElementById('consensus-height').textContent = data.consensus_height;
                });

            // Fetch blocks
            fetch('http://localhost:' + apiPort + '/api/blocks')
                .then(response => response.json())
                .then(blocks => {
                    const tbody = document.getElementById('blocks-table');
                    tbody.innerHTML = '';
                    blocks.forEach(block => {
                        const row = '<tr>' +
                            '<td>' + block.height + '</td>' +
                            '<td>' + block.hash.substring(0, 10) + '...</td>' +
                            '<td>' + new Date(block.timestamp).toLocaleTimeString() + '</td>' +
                            '<td>' + block.txCount + '</td>' +
                            '</tr>';
                        tbody.innerHTML += row;
                    });
                });

            // Fetch transactions
            fetch('http://localhost:' + apiPort + '/api/transactions')
                .then(response => response.json())
                .then(transactions => {
                    const tbody = document.getElementById('transactions-table');
                    tbody.innerHTML = '';
                    transactions.forEach(tx => {
                        const row = '<tr>' +
                            '<td>' + tx.hash + '</td>' +
                            '<td>' + tx.from + '</td>' +
                            '<td>' + tx.to + '</td>' +
                            '<td>' + tx.amount + '</td>' +
                            '<td>' + new Date(tx.timestamp).toLocaleTimeString() + '</td>' +
                            '</tr>';
                        tbody.innerHTML += row;
                    });
                });
        }

        // Update dashboard every 5 seconds
        updateDashboard();
        setInterval(updateDashboard, 5000);
    </script>
</body>
</html>
`
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(dashboardHTML))
}
