package curve25519

import (
	"crypto/rand"

	"golang.org/x/crypto/curve25519"
)

func GenerateKeyPair() (public, private [32]byte) {
	rand.Read(private[:])
	pub, err := curve25519.X25519(private[:], curve25519.Basepoint)
	if err != nil {
		// only fails for low order points, never for the base point
		panic(err)
	}
	copy(public[:], pub)
	return
}

// SharedSecret returns a Curve25519 shared secret derived from privateKey and otherPublicKey.
// It fails when otherPublicKey is a low order point, the secret would be all zeros then.
func SharedSecret(privateKey, otherPublicKey [32]byte) ([32]byte, error) {
	var k [32]byte
	s, err := curve25519.X25519(privateKey[:], otherPublicKey[:])
	if err != nil {
		return k, err
	}
	copy(k[:], s)
	return k, nil
}
