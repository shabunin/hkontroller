package hkontroller

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/shabunin/hkontroller/chacha20poly1305"
	"github.com/shabunin/hkontroller/curve25519"
	"github.com/shabunin/hkontroller/ed25519"
	"github.com/shabunin/hkontroller/hkdf"
	"github.com/shabunin/hkontroller/tlv8"
	"io"
)

type pairVerifyM1Payload struct {
	Method    byte   `tlv8:"0"`
	State     byte   `tlv8:"6"`
	PublicKey []byte `tlv8:"3"`
}
type pairVerifyM3RawPayload struct {
	Identifier string `tlv8:"1"`
	Signature  []byte `tlv8:"10"`
}
type pairVerifyM3EncPayload struct {
	State         byte   `tlv8:"6"`
	EncryptedData []byte `tlv8:"5"`
}

// PairVerify establishes encrypted session with paired device.
func (d *Device) PairVerify() error {
	d.pairMu.Lock()
	defer d.pairMu.Unlock()

	if !d.IsPaired() {
		return errors.New("pair device before verifying")
	}
	if d.IsVerified() {
		d.close(errors.New("reconnect"))
	}
	if !d.isConnected() {
		err := d.connect()
		if err != nil {
			return err
		}
	}
	cc := d.conn()
	if cc == nil {
		return errConnClosed
	}

	localPublic, localPrivate := curve25519.GenerateKeyPair()

	m1 := pairVerifyM1Payload{
		Method:    0,
		State:     M1,
		PublicKey: localPublic[:],
	}
	b, err := tlv8.Marshal(m1)
	if err != nil {
		return &PairVerifyError{"M1", err}
	}

	// send req
	response, err := d.doPost("/pair-verify", HTTPContentTypePairingTLV8, bytes.NewReader(b))
	if err != nil {
		return &PairVerifyError{"M1", err}
	}
	res := response.Body
	defer res.Close()
	all, err := io.ReadAll(res)
	if err != nil {
		return &PairVerifyError{"M2", err}
	}
	m2 := pairSetupPayload{}
	err = tlv8.Unmarshal(all, &m2)
	if err != nil {
		return &PairVerifyError{"M2", err}
	}
	if m2.State != M2 {
		return &PairVerifyError{"M2", fmt.Errorf("unexpected state %x, expected: %x", m2.State, M2)}
	}
	if m2.PublicKey == nil || m2.EncryptedData == nil || m2.Error != 0x00 {
		return &PairVerifyError{"M2", TlvErrorFromCode(m2.Error)}
	}
	if len(m2.PublicKey) != 32 {
		return &PairVerifyError{"M2", errors.New("wrong remote localPublic key length")}
	}
	remotePubk := [32]byte{}
	copy(remotePubk[:], m2.PublicKey)

	sharedKey := curve25519.SharedSecret(localPrivate, remotePubk)

	encKey, err := hkdf.Sha512(
		sharedKey[:],
		[]byte("Pair-Verify-Encrypt-Salt"),
		[]byte("Pair-Verify-Encrypt-Info"),
	)
	if err != nil {
		return &PairVerifyError{"M2", err}
	}

	message, mac, err := splitMac(m2.EncryptedData)
	if err != nil {
		return &PairVerifyError{"M2", err}
	}

	decryptedBytes, err := chacha20poly1305.DecryptAndVerify(
		encKey[:],
		[]byte("PV-Msg02"),
		message,
		mac,
		nil,
	)
	if err != nil {
		return &PairVerifyError{"M2", err}
	}
	m2dec := pairSetupPayload{}
	err = tlv8.UnmarshalReader(bytes.NewReader(decryptedBytes), &m2dec)
	if err != nil {
		return &PairVerifyError{"M2", err}
	}
	if m2dec.Signature == nil {
		return &PairVerifyError{"M2", errors.New("no signature from accessory")}
	}
	// m2.Signature
	// Validate signature
	var material []byte
	material = append(material, remotePubk[:]...)
	material = append(material, m2dec.Identifier...)
	material = append(material, localPublic[:]...)

	ltpk := d.GetPairingInfo().PublicKey

	sigValid := ed25519.ValidateSignature(ltpk, material, m2dec.Signature)
	if !sigValid {
		return &PairVerifyError{"M2", errors.New("signature invalid")}
	}

	// ----- M3 ------

	material = []byte{}
	material = append(material, localPublic[:]...)
	material = append(material, d.controllerId...)
	material = append(material, remotePubk[:]...)

	signature, err := ed25519.Signature(d.controllerLTSK, material)
	if err != nil {
		return &PairVerifyError{"M3", err}
	}

	m3raw := pairVerifyM3RawPayload{
		Signature:  signature,
		Identifier: d.controllerId,
	}
	m3bytes, err := tlv8.Marshal(m3raw)
	if err != nil {
		return &PairVerifyError{"M3", err}
	}

	encryptedBytes, mac, err := chacha20poly1305.EncryptAndSeal(
		encKey[:],
		[]byte("PV-Msg03"),
		m3bytes,
		nil,
	)
	if err != nil {
		return &PairVerifyError{"M3", err}
	}

	m5enc := pairVerifyM3EncPayload{
		State:         M3,
		EncryptedData: append(encryptedBytes, mac[:]...),
	}
	b, err = tlv8.Marshal(m5enc)
	if err != nil {
		return &PairVerifyError{"M3", err}
	}

	response, err = d.doPost("/pair-verify", HTTPContentTypePairingTLV8, bytes.NewReader(b))
	if err != nil {
		return &PairVerifyError{"M4", err}
	}
	res = response.Body

	defer res.Close()
	all, err = io.ReadAll(res)
	if err != nil {
		return &PairVerifyError{"M4", err}
	}
	m4 := pairSetupPayload{}
	err = tlv8.Unmarshal(all, &m4)
	if err != nil {
		return &PairVerifyError{"M4", err}
	}

	if m4.Error != 0x00 {
		return &PairVerifyError{"M4", TlvErrorFromCode(m4.Error)}
	}

	ss, err := newControllerSession(sharedKey, d)
	if err != nil {
		return &PairVerifyError{"M4", err}
	}
	if err := d.setVerified(cc, ss); err != nil {
		return &PairVerifyError{"M4", err}
	}

	return nil
}
