package hkontroller

import (
	"crypto/ed25519"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
)

func deleteFieldFromDict(val *map[string]interface{}, field string) {
	for k, v := range *val {
		if k == field {
			delete(*val, k)
		} else {
			deleteFieldFromInterface(&v, field)
		}
	}
}

func deleteFieldFromArray(val *[]interface{}, field string) {
	for _, v := range *val {
		deleteFieldFromInterface(&v, field)
	}
}

func deleteFieldFromInterface(val *interface{}, field string) {
	v := *val

	if dict, ok := v.(map[string]interface{}); ok == true {
		deleteFieldFromDict(&dict, field)
	}

	if array, ok := v.([]interface{}); ok == true {
		deleteFieldFromArray(&array, field)
	}
}

// generateKeyPair generates random public and private key pair.
// Seed is read from crypto/rand, so it has full 256 bits of entropy.
func generateKeyPair() (KeyPair, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return KeyPair{}, err
	}
	return KeyPair{public, private}, nil
}

func GenerateKeyPair() (KeyPair, error) {
	return generateKeyPair()
}

// mac48Address returns a MAC-48-like address from the argument string
func mac48Address(input string) string {
	h := md5.New()
	h.Write([]byte(input))
	result := h.Sum(nil)

	var c []string
	c = append(c, toHex(result[0]))
	c = append(c, toHex(result[1]))
	c = append(c, toHex(result[2]))
	c = append(c, toHex(result[3]))
	c = append(c, toHex(result[4]))
	c = append(c, toHex(result[5]))

	// setup id needs the mac address in upper case
	return strings.ToUpper(strings.Join(c, ":"))
}

func toHex(b byte) string {
	return hex.EncodeToString([]byte{b})
}

// splitMac splits encrypted data of pairing message into message and 16 byte MAC.
func splitMac(data []byte) ([]byte, [16]byte, error) {
	var mac [16]byte
	if len(data) < len(mac) {
		return nil, mac, errors.New("encrypted data is too short")
	}
	message := data[:len(data)-len(mac)]
	copy(mac[:], data[len(message):])
	return message, mac, nil
}
