package hkontroller

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/shabunin/hkontroller/chacha20poly1305"
	"github.com/shabunin/hkontroller/hkdf"
	"io"
	"sync"
)

type session struct {
	encryptKey [32]byte
	decryptKey [32]byte

	encryptCount uint64
	decryptCount uint64
	dmu          sync.Mutex
}

func newControllerSession(shared [32]byte, d *Device) (*session, error) {
	salt := []byte("Control-Salt")
	in := []byte("Control-Read-Encryption-Key")
	out := []byte("Control-Write-Encryption-Key")

	s := &session{}
	var err error
	s.encryptKey, err = hkdf.Sha512(shared[:], salt, out)
	s.encryptCount = 0
	if err != nil {
		return nil, err
	}

	s.decryptKey, err = hkdf.Sha512(shared[:], salt, in)
	s.decryptCount = 0
	if err != nil {
		return nil, err
	}

	return s, err
}

// Encrypt return the encrypted data by splitting it into packets
// [ length (2 bytes)] [ data ] [ auth (16 bytes)]
func (s *session) Encrypt(r io.Reader) (io.Reader, error) {
	packets := packetsFromBytes(r)
	var buf bytes.Buffer
	for _, p := range packets {
		var nonce [8]byte
		binary.LittleEndian.PutUint64(nonce[:], s.encryptCount)

		bLength := make([]byte, 2)
		binary.LittleEndian.PutUint16(bLength, uint16(p.length))

		encrypted, mac, err := chacha20poly1305.EncryptAndSeal(s.encryptKey[:], nonce[:], p.value, bLength[:])
		if err != nil {
			return nil, err
		}

		buf.Write(bLength[:])
		buf.Write(encrypted)
		buf.Write(mac[:])

		s.encryptCount += 1
	}

	return &buf, nil
}

// Decrypt reads and decrypts single packet.
// Message may span several packets, they are joined by reader of the stream.
func (s *session) Decrypt(r io.Reader) (*bytes.Buffer, error) {
	s.dmu.Lock()
	defer s.dmu.Unlock()

	var length uint16
	if err := binary.Read(r, binary.LittleEndian, &length); err != nil {
		return nil, err
	}

	var b = make([]byte, length)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}

	var mac [16]byte
	if _, err := io.ReadFull(r, mac[:]); err != nil {
		return nil, err
	}

	var nonce [8]byte
	binary.LittleEndian.PutUint64(nonce[:], s.decryptCount)
	s.decryptCount += 1

	lengthBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(lengthBytes, length)

	decrypted, err := chacha20poly1305.DecryptAndVerify(s.decryptKey[:], nonce[:], b, mac, lengthBytes)
	if err != nil {
		// Counter is out of sync, e.g. accessory that sends events from several
		// threads without lock encrypted packets in one order, but wrote them in
		// another. Following packets can't be trusted, connection has to be closed.
		return nil, fmt.Errorf("decrypting packet %d failed: %w", s.decryptCount-1, err)
	}

	return bytes.NewBuffer(decrypted), nil
}

const (
	// packetLengthMax is the max length of encrypted packets
	packetLengthMax = 0x400
)

type packet struct {
	length int
	value  []byte
}

// packetsWithSizeFromBytes returns lv (tlv without t(ype)) packets
func packetsWithSizeFromBytes(length int, r io.Reader) []packet {
	var packets []packet
	for {
		var value = make([]byte, length)
		n, err := r.Read(value)
		if n == 0 {
			break
		}

		if n > length {
			panic("Invalid length")
		}

		p := packet{length: n, value: value[:n]}
		packets = append(packets, p)

		if n < length || err == io.EOF {
			break
		}
	}

	return packets
}

// packetsFromBytes returns packets with length packetLengthMax
func packetsFromBytes(r io.Reader) []packet {
	return packetsWithSizeFromBytes(packetLengthMax, r)
}
