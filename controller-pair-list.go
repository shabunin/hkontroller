package hkontroller

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/shabunin/hkontroller/tlv8"
)

type pairListReqPayload struct {
	Method byte `tlv8:"0"`
	State  byte `tlv8:"6"`
}
type pairingPayload struct {
	Identifier string `tlv8:"1"`
	PublicKey  []byte `tlv8:"3"`
	Permission byte   `tlv8:"11"`
}

// ListPairings should list all controllers of device.
func (d *Device) ListPairings() ([]Pairing, error) {

	pl := pairListReqPayload{
		State:  M1,
		Method: MethodListPairings,
	}
	b, err := tlv8.Marshal(pl)
	if err != nil {
		return nil, err
	}

	resp, err := d.doPost("/pairings", HTTPContentTypePairingTLV8, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("invalid status code %v", resp.StatusCode)
	}
	res := resp.Body
	defer res.Close()
	all, err := io.ReadAll(res)
	if err != nil {
		return nil, err
	}
	pp, err := parsePairings(all)
	return pp, pairingsError(err)
}

// parsePairings parses list pairings response: state, then pairings
// separated by 0xff item, or state and error.
func parsePairings(b []byte) ([]Pairing, error) {
	var result []Pairing
	var pp Pairing
	var state byte
	for len(b) > 0 {
		if len(b) < 2 || len(b) < 2+int(b[1]) {
			return nil, errors.New("truncated response")
		}
		tag, val := b[0], b[2:2+int(b[1])]
		b = b[2+len(val):]

		switch tag {
		case 6:
			if len(val) > 0 {
				state = val[0]
			}
		case 7:
			if len(val) > 0 {
				return nil, TlvErrorFromCode(val[0])
			}
		case 1:
			pp.Id = string(val)
		case 3:
			pp.PublicKey = append([]byte(nil), val...)
		case 11:
			if len(val) > 0 {
				pp.Permission = val[0]
			}
		case 0xff:
			result = append(result, pp)
			pp = Pairing{}
		}
	}
	if state != M2 {
		return nil, fmt.Errorf("unexpected state %x, expected: %x", state, M2)
	}
	if pp.Id != "" {
		result = append(result, pp)
	}
	return result, nil
}
