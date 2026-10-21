package hkontroller

import (
	"bytes"
	"fmt"
	"io"
	"net/http"

	"github.com/shabunin/hkontroller/tlv8"
)

type pairAddReqPayload struct {
	State       byte   `tlv8:"6"`
	Method      byte   `tlv8:"0"`
	Identifier  string `tlv8:"1"`
	PublicKey   []byte `tlv8:"3"`
	Permissions byte   `tlv8:"11"`
}

// PairAdd serves to pair another controller.
func (d *Device) PairAdd(p Pairing) error {

	pl := pairAddReqPayload{
		State:       M1,
		Method:      MethodAddPairing,
		Identifier:  p.Id,
		PublicKey:   p.PublicKey,
		Permissions: p.Permission,
	}
	return d.postPairings(pl)
}

// postPairings sends add or remove pairing request and checks response:
// state M2, or state and error, e.g. ErrNotAdmin.
func (d *Device) postPairings(pl interface{}) error {
	b, err := tlv8.Marshal(pl)
	if err != nil {
		return err
	}

	resp, err := d.doPost("/pairings", HTTPContentTypePairingTLV8, bytes.NewReader(b))
	if err != nil {
		return err
	}
	res := resp.Body
	defer res.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("invalid status code %v", resp.StatusCode)
	}
	all, err := io.ReadAll(res)
	if err != nil {
		return err
	}
	m2 := pairSetupPayload{}
	if err := tlv8.Unmarshal(all, &m2); err != nil {
		return err
	}
	if m2.State != M2 {
		return fmt.Errorf("unexpected state %x, expected: %x", m2.State, M2)
	}
	return pairingsError(pairingError(m2))
}
