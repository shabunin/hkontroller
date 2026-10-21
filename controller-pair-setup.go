package hkontroller

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/shabunin/hkontroller/chacha20poly1305"
	"github.com/shabunin/hkontroller/ed25519"
	"github.com/shabunin/hkontroller/hkdf"
	"github.com/shabunin/hkontroller/tlv8"
	"io"
	"net/http"
)

type pairSetupM1Payload struct {
	Method byte `tlv8:"0"`
	State  byte `tlv8:"6"`
}
type pairSetupM3Payload struct {
	PublicKey []byte `tlv8:"3"`
	Proof     []byte `tlv8:"4"`
	State     byte   `tlv8:"6"`
}
type pairSetupM5RawPayload struct {
	Identifier string `tlv8:"1"`
	PublicKey  []byte `tlv8:"3"`
	Signature  []byte `tlv8:"10"`
}
type pairSetupM5EncPayload struct {
	Method        byte   `tlv8:"0"`
	State         byte   `tlv8:"6"`
	EncryptedData []byte `tlv8:"5"`
}

func (d *Device) pairSetupM1(pin string) (*pairSetupClientSession, error) {

	m1 := pairSetupM1Payload{
		State:  M1,
		Method: MethodPair,
	}
	b, err := tlv8.Marshal(m1)
	if err != nil {
		return nil, &PairSetupError{"M1", err}
	}

	resp, err := d.doPost("/pair-setup", HTTPContentTypePairingTLV8, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &PairSetupError{"M1", fmt.Errorf("invalid status code %v", resp.StatusCode)}
	}
	res := resp.Body
	defer res.Close()
	all, err := io.ReadAll(res)
	if err != nil {
		return nil, &PairSetupError{"M1", err}
	}
	m2 := pairSetupPayload{}
	err = tlv8.Unmarshal(all, &m2)
	if err != nil {
		return nil, &PairSetupError{"M1", err}
	}

	if m2.State != M2 {
		return nil, &PairSetupError{"M2", fmt.Errorf("unexpected state %x, expected: %x", m2.State, M2)}
	}
	if err := pairingError(m2); err != nil {
		return nil, &PairSetupError{"M2", err}
	}
	if len(m2.Salt) == 0 || len(m2.PublicKey) == 0 {
		return nil, &PairSetupError{"M2", errors.New("no salt or public key")}
	}

	clientSession, err := newPairSetupClientSession(m2.Salt, m2.PublicKey, pin)
	if err != nil {
		return nil, &PairSetupError{"M2", err}
	}

	return clientSession, nil
}

func (d *Device) pairSetupM3(clientSession *pairSetupClientSession) error {

	// m3
	m3 := pairSetupM3Payload{
		State:     M3,
		PublicKey: clientSession.PublicKey,
		Proof:     clientSession.Proof,
	}
	b, err := tlv8.Marshal(m3)
	if err != nil {
		return &PairSetupError{"M3", err}
	}

	resp, err := d.doPost("/pair-setup", HTTPContentTypePairingTLV8, bytes.NewReader(b))
	if err != nil {
		return &PairSetupError{"M3", err}
	}
	if resp.StatusCode != http.StatusOK {
		return &PairSetupError{"M3", fmt.Errorf("invalid status code %v", resp.StatusCode)}
	}
	res := resp.Body
	defer res.Close()
	all, err := io.ReadAll(res)
	if err != nil {
		return &PairSetupError{"M3", err}
	}
	m4 := pairSetupPayload{}
	err = tlv8.Unmarshal(all, &m4)
	if err != nil {
		return &PairSetupError{"M3", err}
	}

	if m4.State != M4 {
		return &PairSetupError{"M4", fmt.Errorf("unexpected state %x, expected: %x", m4.State, M4)}
	}
	// e.g. wrong setup code
	if err := pairingError(m4); err != nil {
		return &PairSetupError{"M4", err}
	}
	serverProofValid := clientSession.session.VerifyServerAuthenticator(m4.Proof)
	if !serverProofValid {
		return &PairSetupError{"M4", errors.New("server proof is not valid")}
	}

	return nil
}

func (d *Device) pairSetupM5(clientSession *pairSetupClientSession) error {

	err := clientSession.SetupEncryptionKey(
		[]byte("Pair-Setup-Encrypt-Salt"),
		[]byte("Pair-Setup-Encrypt-Info"),
	)
	if err != nil {
		return &PairSetupError{"M5", err}
	}

	hash, err := hkdf.Sha512(
		clientSession.SessionKey,
		[]byte("Pair-Setup-Controller-Sign-Salt"),
		[]byte("Pair-Setup-Controller-Sign-Info"),
	)
	if err != nil {
		return &PairSetupError{"M5", err}
	}

	var material []byte
	material = append(material, hash[:]...)
	material = append(material, d.controllerId...)
	material = append(material, d.controllerLTPK...)

	signature, err := ed25519.Signature(d.controllerLTSK, material)
	if err != nil {
		return &PairSetupError{"M5", err}
	}

	m5raw := pairSetupM5RawPayload{
		Identifier: d.controllerId,
		PublicKey:  d.controllerLTPK,
		Signature:  signature,
	}
	b, err := tlv8.Marshal(m5raw)
	if err != nil {
		return &PairSetupError{"M5", err}
	}

	encryptedBytes, tag, err := chacha20poly1305.EncryptAndSeal(
		clientSession.EncryptionKey[:],
		[]byte("PS-Msg05"),
		b,
		nil,
	)
	if err != nil {
		return &PairSetupError{"M5", err}
	}

	encData := append(encryptedBytes, tag[:]...)
	m5enc := pairSetupM5EncPayload{
		Method:        0,
		State:         M5,
		EncryptedData: encData,
	}
	b, err = tlv8.Marshal(m5enc)
	if err != nil {
		return &PairSetupError{"M5", err}
	}
	resp, err := d.doPost("/pair-setup", HTTPContentTypePairingTLV8, bytes.NewReader(b))
	if err != nil {
		return &PairSetupError{"M5", err}
	}
	if resp.StatusCode != http.StatusOK {
		return &PairSetupError{"M6", fmt.Errorf("invalid status code %v", resp.StatusCode)}
	}
	res := resp.Body
	defer res.Close()
	all, err := io.ReadAll(res)
	if err != nil {
		return &PairSetupError{"M6", err}
	}
	m6enc := pairSetupPayload{}
	err = tlv8.Unmarshal(all, &m6enc)
	if err != nil {
		return &PairSetupError{"M6", err}
	}
	if err := pairingError(m6enc); err != nil {
		return &PairSetupError{"M6", err}
	}

	message, mac, err := splitMac(m6enc.EncryptedData)
	if err != nil {
		return &PairSetupError{"M6", err}
	}

	decrypted, err := chacha20poly1305.DecryptAndVerify(
		clientSession.EncryptionKey[:],
		[]byte("PS-Msg06"),
		message,
		mac,
		nil,
	)
	if err != nil {
		return &PairSetupError{"M6", err}
	}

	m6dec := pairSetupPayload{}
	err = tlv8.UnmarshalReader(bytes.NewReader(decrypted), &m6dec)
	if err != nil {
		return &PairSetupError{"M6", err}
	}

	//log.Println("m6dec.State = ", m6dec.State) somehow it's state is 0
	//if m6dec.State != M6 {
	//	return errors.New("expected state M6")
	//}
	if err := pairingError(m6dec); err != nil {
		return &PairSetupError{"M6", err}
	}

	accessoryId := m6dec.Identifier
	accessorySignature := m6dec.Signature
	accessoryLTPK := m6dec.PublicKey

	hash, err = hkdf.Sha512(
		clientSession.SessionKey,
		[]byte("Pair-Setup-Accessory-Sign-Salt"),
		[]byte("Pair-Setup-Accessory-Sign-Info"),
	)
	if err != nil {
		return &PairSetupError{"M6", err}
	}

	accessoryInfo := hash[:]
	accessoryInfo = append(accessoryInfo, accessoryId...)
	accessoryInfo = append(accessoryInfo, accessoryLTPK...)

	valid := ed25519.ValidateSignature(accessoryLTPK, accessoryInfo, accessorySignature)
	if !valid {
		return &PairSetupError{"M6", errors.New("m6 signature is not valid")}
	}

	d.mu.Lock()
	d.pairing.Name = d.currentNameLocked()
	d.pairing.Id = accessoryId
	d.pairing.PublicKey = accessoryLTPK
	d.mu.Unlock()

	return nil
}

func (d *Device) PairSetup(pin string) error {
	d.pairMu.Lock()
	defer d.pairMu.Unlock()

	if !d.isConnected() {
		err := d.connect()
		if err != nil {
			return err
		}
	}

	clientSession, err := d.pairSetupM1(pin)
	if err != nil {
		return err
	}
	err = d.pairSetupM3(clientSession)
	if err != nil {
		return err
	}
	err = d.pairSetupM5(clientSession)
	if err != nil {
		return err
	}
	d.mu.Lock()
	d.paired = true
	d.verified = false
	d.notifyStateChanged()
	d.mu.Unlock()
	if d.ctrl != nil {
		d.ctrl.onPaired(d)
	}
	return nil
}
