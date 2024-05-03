package message

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"

	"handshake/common"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

type MessageEncoding uint32

type Message interface {
	BtcEncode(io.Writer, uint32, MessageEncoding) error
	Command() string
}

// messageHeader defines the header structure for all bitcoin protocol messages.
type messageHeader struct {
	magic    common.BitcoinNet // 4 bytes
	command  string            // 12 bytes
	length   uint32            // 4 bytes
	checksum [4]byte           // 4 bytes
}

var binarySerializer common.BinaryFreeList = make(chan []byte, binaryFreeListMaxItems)

const (
	// WitnessEncoding encodes all messages other than transaction messages
	// using the default Bitcoin wire protocol specification.
	WitnessEncoding = MessageEncoding(2)

	// CommandSize is the fixed size of all commands in the common bitcoin message
	// header.  Shorter commands must be zero padded.
	CommandSize = 12

	// MessageHeaderSize is the number of bytes in a bitcoin message header.
	// Bitcoin network (magic) 4 bytes + command 12 bytes + payload length 4 bytes +
	// checksum 4 bytes.
	MessageHeaderSize = 24

	binaryFreeListMaxItems = 1024
)

func WriteMessageWithEncodingN(w io.Writer, msg Message, pver uint32,
	btcnet common.BitcoinNet, encoding MessageEncoding) error {

	// Enforce max command size.
	var command [CommandSize]byte
	cmd := msg.Command()
	if len(cmd) > CommandSize {
		str := fmt.Sprintf("command [%s] is too long [max %v]",
			cmd, CommandSize)
		return errors.New(str)
	}
	copy(command[:], []byte(cmd))

	// Encode the message payload.
	var bw bytes.Buffer
	err := msg.BtcEncode(&bw, pver, encoding)
	if err != nil {
		return err
	}
	payload := bw.Bytes()
	lenp := len(payload)

	// Create header for the message.
	hdr := messageHeader{}
	hdr.magic = btcnet
	hdr.command = cmd
	hdr.length = uint32(lenp)
	copy(hdr.checksum[:], chainhash.DoubleHashB(payload)[0:4])

	// Encode the header for the message.  This is done to a buffer
	// rather than directly to the writer since writeElements doesn't
	// return the number of bytes written.
	hw := bytes.NewBuffer(make([]byte, 0, MessageHeaderSize))

	writeElements(hw, hdr.magic, command, hdr.length, hdr.checksum)
	// Write header.
	_, err = w.Write(hw.Bytes())
	if err != nil {
		return err
	}

	// Only write the payload if there is one, e.g., verack messages don't
	// have one.
	if len(payload) > 0 {
		_, err = w.Write(payload)
	}

	return err
}

// writeElement writes the little endian representation of element to w.
func writeElement(w io.Writer, element interface{}) error {
	// Attempt to write the element based on the concrete type via fast
	// type assertions first.
	switch e := element.(type) {
	case int32:
		err := binarySerializer.PutUint32(w, binary.LittleEndian, uint32(e))
		if err != nil {
			return err
		}
		return nil

	case uint32:
		err := binarySerializer.PutUint32(w, binary.LittleEndian, e)
		if err != nil {
			return err
		}
		return nil

	case int64:
		err := binarySerializer.PutUint64(w, binary.LittleEndian, uint64(e))
		if err != nil {
			return err
		}
		return nil

	case uint64:
		err := binarySerializer.PutUint64(w, binary.LittleEndian, e)
		if err != nil {
			return err
		}
		return nil

	case bool:
		var err error
		if e {
			err = binarySerializer.PutUint8(w, 0x01)
		} else {
			err = binarySerializer.PutUint8(w, 0x00)
		}
		if err != nil {
			return err
		}
		return nil

	// Message header checksum.
	case [4]byte:
		_, err := w.Write(e[:])
		if err != nil {
			return err
		}
		return nil

	// Message header command.
	case [CommandSize]uint8:
		_, err := w.Write(e[:])
		if err != nil {
			return err
		}
		return nil

	// IP address.
	case [16]byte:
		_, err := w.Write(e[:])
		if err != nil {
			return err
		}
		return nil

	case *chainhash.Hash:
		_, err := w.Write(e[:])
		if err != nil {
			return err
		}
		return nil

	case common.ServiceFlag:
		err := binarySerializer.PutUint64(w, binary.LittleEndian, uint64(e))
		if err != nil {
			return err
		}
		return nil

	case common.InvType:
		err := binarySerializer.PutUint32(w, binary.LittleEndian, uint32(e))
		if err != nil {
			return err
		}
		return nil

	case common.BitcoinNet:
		err := binarySerializer.PutUint32(w, binary.LittleEndian, uint32(e))
		if err != nil {
			return err
		}
		return nil

	case common.BloomUpdateType:
		err := binarySerializer.PutUint8(w, uint8(e))
		if err != nil {
			return err
		}
		return nil

	case common.RejectCode:
		err := binarySerializer.PutUint8(w, uint8(e))
		if err != nil {
			return err
		}
		return nil
	}
	return binary.Write(w, binary.LittleEndian, element)
}

// writeElements writes multiple items to w.  It is equivalent to multiple
// calls to writeElement.
func writeElements(w io.Writer, elements ...interface{}) error {
	for _, element := range elements {
		err := writeElement(w, element)
		if err != nil {
			return err
		}
	}
	return nil
}

func writeNetAddressBuf(w io.Writer, pver uint32, na *common.NetAddress, ts bool, buf []byte) error {
	binary.LittleEndian.PutUint64(buf, uint64(na.Services))
	if _, err := w.Write(buf); err != nil {
		return err
	}

	// Ensure to always write 16 bytes even if the ip is nil.
	var ip [16]byte
	if na.IP != nil {
		copy(ip[:], na.IP.To16())
	}
	if _, err := w.Write(ip[:]); err != nil {
		return err
	}

	// Sigh.  Bitcoin protocol mixes little and big endian.
	binary.BigEndian.PutUint16(buf[:2], na.Port)
	_, err := w.Write(buf[:2])

	return err
}

// WriteVarIntBuf serializes val to w using a variable number of bytes depending
// on its value using a preallocated scratch buffer.
func WriteVarIntBuf(w io.Writer, pver uint32, val uint64, buf []byte) error {
	switch {
	case val < 0xfd:
		buf[0] = uint8(val)
		_, err := w.Write(buf[:1])
		return err

	case val <= math.MaxUint16:
		buf[0] = 0xfd
		binary.LittleEndian.PutUint16(buf[1:3], uint16(val))
		_, err := w.Write(buf[:3])
		return err

	case val <= math.MaxUint32:
		buf[0] = 0xfe
		binary.LittleEndian.PutUint32(buf[1:5], uint32(val))
		_, err := w.Write(buf[:5])
		return err

	default:
		buf[0] = 0xff
		if _, err := w.Write(buf[:1]); err != nil {
			return err
		}

		binary.LittleEndian.PutUint64(buf, val)
		_, err := w.Write(buf)
		return err
	}
}

func writeVarStringBuf(w io.Writer, pver uint32, str string, buf []byte) error {
	err := WriteVarIntBuf(w, pver, uint64(len(str)), buf)
	if err != nil {
		return err
	}

	_, err = w.Write([]byte(str))
	return err
}

// writeNetAddress serializes a NetAddress to w depending on the protocol
// version and whether or not the timestamp is included per ts.
func writeNetAddress(w io.Writer, pver uint32, na *common.NetAddress, ts bool) error {
	buf := binarySerializer.Borrow()
	defer binarySerializer.Return(buf)
	err := writeNetAddressBuf(w, pver, na, ts, buf)

	return err
}

// WriteVarString serializes str to w as a variable length integer containing
// the length of the string followed by the bytes that represent the string
// itself.
func WriteVarString(w io.Writer, pver uint32, str string) error {
	buf := binarySerializer.Borrow()
	defer binarySerializer.Return(buf)

	err := writeVarStringBuf(w, pver, str, buf)
	return err
}
