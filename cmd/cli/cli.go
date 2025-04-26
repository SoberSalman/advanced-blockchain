// cmd/cli/cli.go
package main

import (
	"bufio"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/SoberSalman/advanced-blockchain/internal/types"
)

type CLI struct {
	nodeAddress string
	scanner     *bufio.Scanner
}

func NewCLI(nodeAddress string) *CLI {
	return &CLI{
		nodeAddress: nodeAddress,
		scanner:     bufio.NewScanner(os.Stdin),
	}
}

func (cli *CLI) Run() {
	fmt.Println("Advanced Blockchain CLI")
	fmt.Println("-------------------------------")
	fmt.Println("Commands:")
	fmt.Println("  send <from> <to> <amount> - Send transaction")
	fmt.Println("  balance <address>         - Check account balance")
	fmt.Println("  status                    - Check node status")
	fmt.Println("  exit                      - Exit CLI")
	fmt.Println("-------------------------------")

	for {
		fmt.Print("> ")
		cli.scanner.Scan()
		line := cli.scanner.Text()

		if line == "exit" {
			break
		}

		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}

		switch parts[0] {
		case "send":
			if len(parts) != 4 {
				fmt.Println("Usage: send <from> <to> <amount>")
				continue
			}
			cli.sendTransaction(parts[1], parts[2], parts[3])

		case "balance":
			if len(parts) != 2 {
				fmt.Println("Usage: balance <address>")
				continue
			}
			cli.getBalance(parts[1])

		case "status":
			cli.getStatus()

		default:
			fmt.Println("Unknown command:", parts[0])
		}
	}
}

func (cli *CLI) sendTransaction(from, to, amount string) {
	fmt.Printf("Sending %s from %s to %s...\n", amount, from, to)

	// Create transaction
	tx := types.Transaction{
		From:      stringToAddress(from),
		To:        stringToAddress(to),
		Value:     new(big.Int),
		Nonce:     uint64(time.Now().UnixNano()),
		Timestamp: time.Now(),
		Data:      []byte{},
		Signature: []byte("demo-signature"), // In real implementation, sign properly
	}

	tx.Value.SetString(amount, 10)

	// In a real implementation, this would send to the network
	fmt.Printf("Transaction sent! Hash: %x\n", tx.Signature[:8])
}

func (cli *CLI) getBalance(address string) {
	// In a real implementation, this would query the node
	fmt.Printf("Balance of %s: 1000\n", address)
}

func (cli *CLI) getStatus() {
	// In a real implementation, this would query the node
	fmt.Println("Node status:")
	fmt.Println("  Height: 42")
	fmt.Println("  Shard: 0")
	fmt.Println("  Peers: 5")
	fmt.Println("  Validator: true")
}

func stringToAddress(s string) types.Address {
	var addr types.Address
	// Simple conversion for demo
	copy(addr[:], []byte(s))
	return addr
}

func main() {
	nodeAddress := flag.String("node", "http://localhost:8545", "Node address")
	flag.Parse()

	cli := NewCLI(*nodeAddress)
	cli.Run()
}
