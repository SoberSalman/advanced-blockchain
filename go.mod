// go.mod
module github.com/SoberSalman/advanced-blockchain

go 1.18

require github.com/rs/zerolog v1.29.0

require (
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.16 // indirect
	golang.org/x/sys v0.7.0 // indirect
)

// Remove the problematic tss-lib dependency
// github.com/bnb-chain/tss-lib v1.6.0
