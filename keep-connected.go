package hkontroller

import (
	"context"
	"time"
)

// pauses between attempts to verify device, see KeepConnected
var (
	reconnectMinDelay = time.Second
	reconnectMaxDelay = time.Minute
)

// KeepConnected verifies paired device and verifies it again whenever connection
// is lost, until ctx is done or device is unpaired. It blocks, so run it in goroutine.
//
// Failed attempts are repeated after pause growing from 1 second up to 1 minute.
// Device that is not discovered is not tried, it is verified as soon as it is
// discovered again, e.g. after accessory restart.
//
// onConnected is called for every new connection, also when it was established
// by PairVerify call meanwhile. Events subscriptions don't survive reconnect,
// so it is a place to subscribe again. onError is called with every failed attempt.
// Both may be nil. Connection is left open when ctx is done.
//
// Only one loop runs for device: if KeepConnected is running already,
// e.g. it is called every time device is discovered, it returns at once.
func (d *Device) KeepConnected(ctx context.Context, onConnected func(), onError func(error)) {
	d.mu.Lock()
	if d.keeping {
		d.mu.Unlock()
		return
	}
	d.keeping = true
	d.mu.Unlock()
	defer func() {
		d.mu.Lock()
		d.keeping = false
		d.mu.Unlock()
	}()

	delay := reconnectMinDelay
	// pause waits before next attempt, false if ctx is done.
	// Device discovered again is tried right away.
	pause := func(changed <-chan struct{}) bool {
		select {
		case <-ctx.Done():
			return false
		case <-changed:
		case <-time.After(delay):
		}
		delay = min(delay*2, reconnectMaxDelay)
		return true
	}

	var lastDone <-chan struct{}
	for ctx.Err() == nil && d.IsPaired() {
		if d.IsVerified() {
			// connection is kept even if mdns lost device, so this goes first
			done := d.Done()
			if done != lastDone {
				lastDone = done
				if onConnected != nil {
					onConnected()
				}
			}
			connectedAt := time.Now()
			select {
			case <-ctx.Done():
				return
			case <-done:
			}
			if d.IsVerified() {
				// replaced by new connection, e.g. PairVerify was called
				continue
			}
			if time.Since(connectedAt) >= reconnectMaxDelay {
				// connection was fine, reconnect right away
				delay = reconnectMinDelay
				continue
			}
			// accessory drops connections, don't spin
			if !pause(d.stateChanged()) {
				return
			}
			continue
		}

		// taken before attempt, so discovery meanwhile is not missed
		changed := d.stateChanged()
		if !d.IsDiscovered() {
			// nowhere to connect, wait for accessory or unpair
			select {
			case <-ctx.Done():
				return
			case <-changed:
			}
			continue
		}

		if err := d.verifyIfNeeded(); err != nil {
			if onError != nil && d.IsPaired() {
				onError(err)
			}
			if !pause(changed) {
				return
			}
		}
	}
}

// stateChanged returns channel closed when device is discovered next time,
// after it was not advertised, or when it is paired or unpaired.
func (d *Device) stateChanged() <-chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.changed == nil {
		d.changed = make(chan struct{})
	}
	return d.changed
}

// notifyStateChanged must be called with d.mu held.
func (d *Device) notifyStateChanged() {
	if d.changed != nil {
		close(d.changed)
		d.changed = nil
	}
}
