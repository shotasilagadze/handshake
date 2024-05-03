package peer

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"handshake/checker"
	"handshake/common"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/peer"
)

const ProtocolVersion = 70016

func init() {

}

// simply mocks remote peer
func mockRemotePeer() (*net.Listener, error) {
	// Configure peer to act as a simnet node that offers no services.
	peerCfg := &peer.Config{
		UserAgentName:    "peer",  // User agent name to advertise.
		UserAgentVersion: "1.0.0", // User agent version to advertise.
		ChainParams:      &chaincfg.SimNetParams,
		TrickleInterval:  time.Second * 10,
		AllowSelfConns:   true,
	}

	// Accept connections on the simnet port.
	listener, err := net.Listen("tcp", "127.0.0.1:18555")
	if err != nil {
		return nil, err
	}
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Printf("Accept: error %v\n", err)
			return
		}

		// Create and start the inbound peer.
		p := peer.NewInboundPeer(peerCfg)
		p.AssociateConnection(conn)
	}()

	return &listener, nil
}

func TestHandshakeSuccess(t *testing.T) {
	var listener *net.Listener
	var err error
	listener, err = mockRemotePeer()
	if err != nil {
		t.Fatalf("couldn't mock remote peer %+v", err)
	}
	defer (*listener).Close()

	conn, err := Handshake("127.0.0.1:18555", common.SimNet, ProtocolVersion)
	if err != nil {
		t.Fatalf("handshake failed: %+v", err)
	}

	err = checker.ReadMessageWithEncodingN(*conn, ProtocolVersion, common.SimNet)
	if err != nil {
		t.Fatalf("reading intermediary message before verack failed: %+v", err)
	}

	err = checker.WaitToFinishNegotiation(*conn, ProtocolVersion, common.SimNet)
	if err != nil {
		t.Fatalf("verack message not received for the handshake: %+v", err)
	}
}

func TestHandshakeIncorrectIpt(t *testing.T) {
	var listener *net.Listener
	var err error
	listener, err = mockRemotePeer()
	if err != nil {
		t.Fatalf("couldn't mock remote peer %+v", err)
	}

	defer (*listener).Close()

	timeout := time.After(time.Second) // Define the timeout duration

	// Channel to receive signal when the function call completes
	done := make(chan struct{})

	// Run the function call in a separate goroutine
	go func() {
		_, err = Handshake("127.0.0.2:18555", common.SimNet, ProtocolVersion)
		if err == nil {
			t.Errorf("handshake should hang for a while because of the incorrect address")
		}
		close(done)
	}()

	// Wait for either the function call to complete or the timeout to occur
	select {
	case <-done:
		t.Error("Function should hang because of incorrect address")
	case <-timeout:
	}
}

func TestHandshakeIncorrectPort(t *testing.T) {
	var listener *net.Listener
	var err error
	listener, err = mockRemotePeer()
	if err != nil {
		t.Fatalf("couldn't mock remote peer %+v", err)
	}

	defer (*listener).Close()

	_, err = Handshake("127.0.0.1:123", common.SimNet, ProtocolVersion)
	if err == nil {
		t.Errorf("handshake should fail because of the incorrect port")
	}

	if !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("connection refusal was expected but received the error %+v", err)
	}
}

func TestHandshakeIncorrectProtocol(t *testing.T) {
	var listener *net.Listener
	var err error
	listener, err = mockRemotePeer()
	if err != nil {
		t.Fatalf("couldn't mock remote peer %+v", err)
	}
	defer (*listener).Close()

	conn, err := Handshake("127.0.0.1:18555", common.SimNet, 123)
	if err != nil {
		t.Fatalf("handshake failed: %+v", err)
	}

	err = checker.ReadMessageWithEncodingN(*conn, ProtocolVersion, common.SimNet)
	if err == nil {
		t.Fatalf("call should have failed because of the incorrect protocol")
	}

	if !strings.Contains(err.Error(), "connection reset by peer") {
		t.Errorf("connection should have been reset because of the incorrect protocol")
	}
}

func TestHandshakeIncorrectNetwork(t *testing.T) {
	var listener *net.Listener
	var err error
	listener, err = mockRemotePeer()
	if err != nil {
		t.Fatalf("couldn't mock remote peer %+v", err)
	}
	defer (*listener).Close()

	conn, err := Handshake("127.0.0.1:18555", common.MainNet, ProtocolVersion)
	if err != nil {
		t.Fatalf("handshake failed: %+v", err)
	}

	err = checker.ReadMessageWithEncodingN(*conn, ProtocolVersion, common.SimNet)
	if err == nil {
		t.Fatalf("call should have failed because of the incorrect network parameter")
	}

	if !strings.Contains(err.Error(), "connection reset by peer") {
		t.Errorf("connection should have been reset because of the incorrect network parameter")
	}
}

func TestHandshakeIncorrectAddressTimeout(t *testing.T) {
	var listener *net.Listener
	var err error
	listener, err = mockRemotePeer()
	if err != nil {
		t.Fatalf("couldn't mock remote peer %+v", err)
	}
	defer (*listener).Close()

	_, err = Handshake("127.32.21.1:18555", common.SimNet, ProtocolVersion)
	if err == nil {
		t.Fatalf("handshake should have failed with timeout")
	}

	if !strings.Contains(err.Error(), "i/o timeout") {
		t.Errorf("connection should have been timed out")
	}
}
