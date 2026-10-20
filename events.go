package hkontroller

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/shabunin/hkontroller/log"
)

// CharacteristicUpdate is sent to subscribers when accessory reports characteristic value change.
type CharacteristicUpdate struct {
	Aid   uint64
	Iid   uint64
	Value interface{}
}

// eventBufferSize is how many events may be queued for a subscriber
// that is not reading. Further events are dropped, so a slow subscriber
// never blocks connection.
const eventBufferSize = 16

// anyId matches every accessory or characteristic id in subscription scope.
const anyId = -1

type eventSub struct {
	aid int64
	iid int64
	ch  chan CharacteristicUpdate
}

func (s *eventSub) covers(aid uint64, iid uint64) bool {
	return (s.aid == anyId || uint64(s.aid) == aid) &&
		(s.iid == anyId || uint64(s.iid) == iid)
}

// within reports if subscription scope is inside of aid/iid scope.
func (s *eventSub) within(aid int64, iid int64) bool {
	return (aid == anyId || s.aid == aid) && (iid == anyId || s.iid == iid)
}

func (d *Device) onEvent(res *http.Response) {
	all, err := io.ReadAll(res.Body)
	if err != nil {
		return
	}

	var chrs CharacteristicEvent
	err = json.Unmarshal(all, &chrs)
	if err != nil {
		return
	}
	for _, ch := range chrs.Characteristics {
		aid := ch.Aid
		iid := ch.Iid
		val := ch.Value

		// update values, so it will be available without extra GetAccessories request
		for _, aa := range d.Accessories() {
			if aa.Id != aid {
				continue
			}
			for _, ss := range aa.Ss {
				for _, cc := range ss.Cs {
					if cc.Iid == iid {
						cc.Value = val
					}
				}
			}
		}

		d.dispatch(CharacteristicUpdate{Aid: aid, Iid: iid, Value: val})
	}
}

// dispatch sends event to every matching subscriber without blocking.
func (d *Device) dispatch(ev CharacteristicUpdate) {
	d.subsMu.Lock()
	defer d.subsMu.Unlock()
	for _, s := range d.subs {
		if !s.covers(ev.Aid, ev.Iid) {
			continue
		}
		select {
		case s.ch <- ev:
		default:
			log.Debug.Printf("device <%s>: event %d.%d dropped, subscriber is not reading\n",
				d.Name, ev.Aid, ev.Iid)
		}
	}
}

func (d *Device) isCovered(aid uint64, iid uint64) bool {
	d.subsMu.Lock()
	defer d.subsMu.Unlock()
	for _, s := range d.subs {
		if s.covers(aid, iid) {
			return true
		}
	}
	return false
}

func (d *Device) addSub(s *eventSub) {
	d.subsMu.Lock()
	d.subs = append(d.subs, s)
	d.subsMu.Unlock()
}

// removeSubs removes and closes subscriptions matching fn.
func (d *Device) removeSubs(fn func(s *eventSub) bool) []*eventSub {
	d.subsMu.Lock()
	defer d.subsMu.Unlock()
	var removed []*eventSub
	kept := d.subs[:0]
	for _, s := range d.subs {
		if fn(s) {
			close(s.ch)
			removed = append(removed, s)
		} else {
			kept = append(kept, s)
		}
	}
	for i := len(kept); i < len(d.subs); i++ {
		d.subs[i] = nil
	}
	d.subs = kept
	return removed
}

// closeSubscriptions closes all subscriber channels.
// Accessory forgets subscriptions when connection is closed.
func (d *Device) closeSubscriptions() {
	d.removeSubs(func(*eventSub) bool { return true })
}

// eventCharacteristics returns characteristics inside of aid/iid scope.
// For accessory or all characteristics only those supporting events are listed.
func (d *Device) eventCharacteristics(aid int64, iid int64) []CharacteristicPut {
	if aid != anyId && iid != anyId {
		return []CharacteristicPut{{Aid: uint64(aid), Iid: uint64(iid)}}
	}
	var cs []CharacteristicPut
	for _, aa := range d.Accessories() {
		if aid != anyId && aa.Id != uint64(aid) {
			continue
		}
		for _, ss := range aa.Ss {
			for _, cc := range ss.Cs {
				for _, pp := range cc.Permissions {
					if pp == "ev" { // supported
						cs = append(cs, CharacteristicPut{Aid: aa.Id, Iid: cc.Iid})
					}
				}
			}
		}
	}
	return cs
}

// putEvents enables or disables event notifications for characteristics.
func (d *Device) putEvents(cs []CharacteristicPut, enable bool) error {
	if len(cs) == 0 {
		return nil
	}

	type putPayload struct {
		Cs []CharacteristicPut `json:"characteristics"`
	}

	pl := putPayload{}
	for _, c := range cs {
		ev := enable
		pl.Cs = append(pl.Cs, CharacteristicPut{Aid: c.Aid, Iid: c.Iid, Events: &ev})
	}

	b, err := json.Marshal(pl)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), reqTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "PUT", "/characteristics", bytes.NewReader(b))
	if err != nil {
		return err
	}

	res, err := d.doRequest(req)
	if err != nil {
		return err
	}

	if enable && res.StatusCode != http.StatusNoContent {
		return errors.New("not 204")
	}

	return nil
}

func (d *Device) subscribe(aid int64, iid int64) (<-chan CharacteristicUpdate, error) {
	d.subscribeMu.Lock()
	defer d.subscribeMu.Unlock()

	// enable only events not enabled by other subscriptions
	var cs []CharacteristicPut
	for _, c := range d.eventCharacteristics(aid, iid) {
		if !d.isCovered(c.Aid, c.Iid) {
			cs = append(cs, c)
		}
	}

	// register before request, so no event is missed right after enabling
	s := &eventSub{aid: aid, iid: iid, ch: make(chan CharacteristicUpdate, eventBufferSize)}
	d.addSub(s)

	if err := d.putEvents(cs, true); err != nil {
		d.removeSubs(func(ss *eventSub) bool { return ss == s })
		return nil, err
	}

	return s.ch, nil
}

// unsubscribe closes subscriptions matching fn and disables events
// inside of aid/iid scope that are no longer needed by remaining subscriptions.
func (d *Device) unsubscribe(aid int64, iid int64, fn func(s *eventSub) bool) error {
	d.subscribeMu.Lock()
	defer d.subscribeMu.Unlock()

	d.removeSubs(fn)

	var cs []CharacteristicPut
	for _, c := range d.eventCharacteristics(aid, iid) {
		if !d.isCovered(c.Aid, c.Iid) {
			cs = append(cs, c)
		}
	}

	return d.putEvents(cs, false)
}

// SubscribeToEvents enables events for single characteristic.
// Returned channel is closed on unsubscribe or when connection is closed.
// Events are dropped if channel is not read fast enough.
func (d *Device) SubscribeToEvents(aid uint64, iid uint64) (<-chan CharacteristicUpdate, error) {
	return d.subscribe(int64(aid), int64(iid))
}

// SubscribeToAccessoryEvents enables events for all characteristics of accessory.
// GetAccessories should be called prior to this call.
func (d *Device) SubscribeToAccessoryEvents(aid uint64) (<-chan CharacteristicUpdate, error) {
	return d.subscribe(int64(aid), anyId)
}

// SubscribeToAllEvents enables events for all characteristics of all accessories.
// GetAccessories should be called prior to this call.
func (d *Device) SubscribeToAllEvents() (<-chan CharacteristicUpdate, error) {
	return d.subscribe(anyId, anyId)
}

// Unsubscribe closes channel returned by one of Subscribe* methods.
// Events are disabled on accessory when no other subscription needs them.
func (d *Device) Unsubscribe(ch <-chan CharacteristicUpdate) error {
	var target *eventSub
	d.subsMu.Lock()
	for _, s := range d.subs {
		if s.ch == ch {
			target = s
		}
	}
	d.subsMu.Unlock()
	if target == nil {
		// already closed
		return nil
	}
	return d.unsubscribe(target.aid, target.iid, func(s *eventSub) bool { return s == target })
}

// UnsubscribeFromEvents closes all subscriptions to single characteristic.
// Accessory-wide subscriptions keep receiving its events.
func (d *Device) UnsubscribeFromEvents(aid uint64, iid uint64) error {
	return d.unsubscribe(int64(aid), int64(iid), func(s *eventSub) bool {
		return s.within(int64(aid), int64(iid))
	})
}

// UnsubscribeFromAccessoryEvents closes all subscriptions to accessory characteristics.
func (d *Device) UnsubscribeFromAccessoryEvents(aid uint64) error {
	return d.unsubscribe(int64(aid), anyId, func(s *eventSub) bool {
		return s.within(int64(aid), anyId)
	})
}

// UnsubscribeFromAllEvents closes all subscriptions.
func (d *Device) UnsubscribeFromAllEvents() error {
	return d.unsubscribe(anyId, anyId, func(*eventSub) bool { return true })
}
