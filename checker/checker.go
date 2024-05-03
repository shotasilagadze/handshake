package checker

import (
	"errors"
	"io"
	"net"
	"time"

	"handshake/common"

	"github.com/btcsuite/btcd/wire"
)

// we use this to simply skip the next message in tcp stack
func ReadMessageWithEncodingN(r io.Reader, protocolVersion uint32, network common.BitcoinNet) error {
	_, _, _, err := wire.ReadMessageWithEncodingN(r, protocolVersion, wire.BitcoinNet(network), wire.LatestEncoding)
	return err
}

func readMessage(conn net.Conn, protocolVersion uint32, network common.BitcoinNet) (wire.Message, []byte, error) {
	_, msg, buf, err := wire.ReadMessageWithEncodingN(conn,
		protocolVersion, wire.BitcoinNet(network), wire.LatestEncoding)
	return msg, buf, err
}

func WaitToFinishNegotiation(conn net.Conn, protocolVersion uint32, network common.BitcoinNet) error {
	verack := make(chan error)

	go func(verack chan error) {
		for {
			remoteMsg, _, err := readMessage(conn, protocolVersion, network)
			if err == wire.ErrUnknownMessage {
				continue
			} else if err != nil {
				verack <- err
			}

			switch remoteMsg.(type) {
			case *wire.MsgSendAddrV2:
				// skip MsgSendAddrV2 message
				continue
			case *wire.MsgVerAck:
				verack <- nil
			default:
				// This is triggered if the peer sends, for example, a
				// GETDATA message during this negotiation.
				verack <- wire.ErrInvalidHandshake
			}
		}
	}(verack)

	select {
	case err := <-verack:
		return err
	case <-time.After(1 * time.Second):
		return errors.New("ack message not received in time")
	}
}
