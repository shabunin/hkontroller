package hkontroller

import (
	"errors"
	"github.com/shabunin/hkontroller/log"
)

type pairRemoveReqPayload struct {
	State      byte   `tlv8:"6"`
	Method     byte   `tlv8:"0"`
	Identifier string `tlv8:"1"`
}

func (d *Device) PairRemove(controllerId string) error {

	pl := pairRemoveReqPayload{
		State:      M1,
		Method:     MethodDeletePairing,
		Identifier: controllerId,
	}
	return d.postPairings(pl)
}

// Unpair removes pairing of this controller from accessory, then forgets it.
// If request fails, pairing is kept, so it can be retried: accessory would
// stay paired with controller that doesn't know it anymore.
// See ForgetPairing for accessory that was reset or is gone.
func (d *Device) Unpair() error {
	log.Debug.Println("d.Unpair()")

	if err := d.PairRemove(d.controllerId); err != nil {
		return err
	}
	d.ForgetPairing()
	return nil
}

// ForgetPairing forgets pairing without asking accessory,
// e.g. it was reset to factory settings or doesn't exist anymore.
func (d *Device) ForgetPairing() {
	if d.ctrl != nil {
		d.ctrl.onUnpaired(d)
		return
	}
	d.setPairing(Pairing{}, false)
	d.close(errors.New("device unpaired"))
}
