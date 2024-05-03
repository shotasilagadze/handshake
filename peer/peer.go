package peer

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"time"

	"handshake/common"
	"handshake/message"
)

// HandshakeRetries to retry handshake after failure
const HandshakeRetries = 3

// DefaultUserAgent for wire in the stack
const DefaultUserAgent = "/btcwire:0.5.0/"

// LatestEncoding is the most recently specified encoding for the Bitcoin protocol
var LatestEncoding = message.WitnessEncoding

// Handshake simply retries handshake to consider network flakiness
func Handshake(peerAddress string, network common.BitcoinNet, protocolVersion uint32) (*net.Conn, error) {
	var err error
	var conn *net.Conn
	for i := 0; i < HandshakeRetries; i++ {
		conn, err = handshake(peerAddress, network, protocolVersion)
		if err != nil {
			fmt.Println(err.Error())
			continue
		}

		return conn, nil
	}

	return nil, errors.New(fmt.Sprintf("handshake failed after %d retries with the error %s", HandshakeRetries, err.Error()))
}

// handshake tipically follows the following steps:
//
//  1. We send our version.
//  2. Remote peer sends their version.
//  3. We send sendaddrv2 if their version is >= 70016.
//  4. We send our verack.
//  5. We wait to receive sendaddrv2 or verack, skipping unknown messages
//  6. If sendaddrv2 was received, wait for receipt of verack.
//
// for the assignment purpose we skipp sendaddrv2 related checks/functionality
// and simply send needed messages to perform handshake and establish connection.
// For this reason we skip receiving acknowledgements. With tests we will verify
// that the handshake succeeds by checking verack message. Obviously this function
// is not correct/production ready but I believe for our purposes this should suffice.
// Receiving acknowledgements will be checked in tests.
func handshake(peerAddress string, network common.BitcoinNet, protocolVersion uint32) (*net.Conn, error) {
	// validate address
	pattern := `^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+$`
	regex := regexp.MustCompile(pattern)
	if !regex.MatchString(peerAddress) {
		return nil, errors.New("incorrect peer address format")
	}

	// Create a Dialer with timeout
	dialer := &net.Dialer{
		Timeout:   1 * time.Second, // Set the timeout to 1 seconds
		KeepAlive: 0,
	}

	// Dial with the Dialer
	conn, err := dialer.Dial("tcp", peerAddress)
	if err != nil {
		return nil, err
	}

	// Set a deadline for writes
	err = conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
	if err != nil {
		return nil, err
	}

	ip, port, err := net.SplitHostPort(peerAddress)
	if err != nil {
		conn.Close()
		return nil, err
	}

	// Convert port string to uint16
	portUint64, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		conn.Close()
		return nil, err
	}

	// construct version message to initiate handshake
	localVerMsg := &message.MsgVersion{
		ProtocolVersion: int32(protocolVersion),
		Services:        0,
		Timestamp:       time.Unix(time.Now().Unix(), 0),
		AddrYou: common.NetAddress{
			Timestamp: time.Now(),
			Services:  0x0,
			IP:        net.ParseIP(ip),
			Port:      uint16(portUint64),
		},
		AddrMe:         common.NetAddress{},
		Nonce:          1,
		UserAgent:      DefaultUserAgent,
		LastBlock:      0,
		DisableRelayTx: false,
	}

	// 1. We send our version
	err = message.WriteMessageWithEncodingN(conn, localVerMsg, protocolVersion, network, LatestEncoding)
	if err != nil {
		conn.Close()
		return nil, err
	}

	// 4. We send our verack.
	// At this point we skipped receiving the corresponding version
	// message from the peer, assumed it was valid and acceptable and
	// now return verack message to let peer know everything went ok
	err = message.WriteMessageWithEncodingN(conn, &message.MsgVerAck{}, protocolVersion, network, LatestEncoding)
	if err != nil {
		conn.Close()
		return nil, err
	}

	return &conn, nil
}
