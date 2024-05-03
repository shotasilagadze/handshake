package main

import (
	"fmt"
	"os"
	"strconv"

	"handshake/checker"
	"handshake/common"
	"handshake/peer"
)

func main() {
	// Check if there are exactly two command-line arguments
	if len(os.Args) != 4 {
		fmt.Println("Incorrect parameters! usage: main 35.175.179.123:18333 70016")
		os.Exit(1)
	}

	param2 := os.Args[3]

	// Verify that the second parameter is a number
	protocolVersion, err := strconv.Atoi(param2)
	if err != nil {
		fmt.Println("Second parameter must be a number")
		os.Exit(1)
	}

	// Switch statement based on the network parameter value
	var network common.BitcoinNet
	switch os.Args[1] {
	case "main":
		network = common.MainNet
	case "sim":
		network = common.SimNet
	default:
		fmt.Println("network must be either 'main' or 'sim' for mainnet and simnet correspondingly")
		os.Exit(1)
	}

	// send necessary messages to peer to perform handshake
	conn, err := peer.Handshake(os.Args[2], network, uint32(protocolVersion))
	if err != nil {
		fmt.Println("Handshake failed: ", err.Error())
		os.Exit(1)
	}

	// we intentionally skip the next message in the tcp call stack to expect verack message directly
	err = checker.ReadMessageWithEncodingN(*conn, uint32(protocolVersion), network)
	if err != nil {
		fmt.Println("reading intermediary message before verack failed: ", err.Error())
		os.Exit(1)
	}

	// verify that verack message is received marking handshake successful
	err = checker.WaitToFinishNegotiation(*conn, uint32(protocolVersion), network)
	if err != nil {
		fmt.Println("verack message not received for the handshake: ", err.Error())
		os.Exit(1)
	}

	fmt.Println("Handshake was successful!")
	return
}
