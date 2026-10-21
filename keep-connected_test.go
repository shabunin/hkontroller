package hkontroller

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

// fakeVerify replaces verifyDevice: it fails while fail returns true,
// otherwise device gets connection to fake accessory after slow, like dial and handshake take.
// Returns number of attempts and servers of connections.
func fakeVerify(t *testing.T, fail func() bool, slow time.Duration) (attempts func() int, servers func() []net.Conn) {
	var mu sync.Mutex
	n := 0
	var conns []net.Conn
	old := verifyDevice
	verifyDevice = func(d *Device) error {
		mu.Lock()
		n++
		mu.Unlock()
		if fail != nil && fail() {
			return errors.New("verify failed")
		}
		if d.conn() != nil {
			d.close(errors.New("reconnect")) // like connect does
		}
		time.Sleep(slow)
		client, server := net.Pipe()
		acc := &fakeAccessory{t: t, conn: server, handle: noContent}
		go acc.serve()
		cc := newConn(client)
		d.mu.Lock()
		d.cc = cc
		d.httpc = &http.Client{Transport: newRoundTripper(cc)}
		d.verified = true
		d.mu.Unlock()
		d.startBackgroundRead(cc)
		mu.Lock()
		conns = append(conns, server)
		mu.Unlock()
		return nil
	}
	t.Cleanup(func() {
		verifyDevice = old
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			c.Close()
		}
	})
	return func() int {
			mu.Lock()
			defer mu.Unlock()
			return n
		}, func() []net.Conn {
			mu.Lock()
			defer mu.Unlock()
			return append([]net.Conn(nil), conns...)
		}
}

func fastReconnect(t *testing.T, min, max time.Duration) {
	oldMin, oldMax := reconnectMinDelay, reconnectMaxDelay
	reconnectMinDelay, reconnectMaxDelay = min, max
	t.Cleanup(func() { reconnectMinDelay, reconnectMaxDelay = oldMin, oldMax })
}

func pairedDiscoveredDevice(t *testing.T) *Device {
	c := newTestController(t)
	e := entryWithId("Bridge", "AA:BB")
	dd, _ := c.onDnssdAdd(e)
	dd.setPairing(Pairing{Name: "Bridge", Id: "AA:BB"}, true)
	t.Cleanup(func() { dd.Close() })
	return dd
}

// keepConnected runs KeepConnected, returned channel is closed when it returns.
func keepConnected(d *Device, ctx context.Context, onConnected func(), onError func(error)) <-chan struct{} {
	returned := make(chan struct{})
	go func() {
		defer close(returned)
		d.KeepConnected(ctx, onConnected, onError)
	}()
	return returned
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timeout waiting for ", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestKeepConnectedReconnects(t *testing.T) {
	fastReconnect(t, 10*time.Millisecond, 100*time.Millisecond)
	_, servers := fakeVerify(t, nil, 0)
	d := pairedDiscoveredDevice(t)

	ctx, cancel := context.WithCancel(context.Background())
	var mu sync.Mutex
	connected := 0
	returned := keepConnected(d, ctx, func() {
		mu.Lock()
		connected++
		mu.Unlock()
	}, func(err error) { t.Error("unexpected error: ", err) })
	count := func() int {
		mu.Lock()
		defer mu.Unlock()
		return connected
	}

	waitFor(t, "connection", func() bool { return count() == 1 && d.IsVerified() })
	servers()[0].Close() // accessory drops connection
	waitFor(t, "reconnect", func() bool { return count() == 2 && d.IsVerified() })

	cancel()
	waitDone(t, returned)
	if !d.IsVerified() {
		t.Fatal("connection should be left open")
	}
}

func TestKeepConnectedBackoff(t *testing.T) {
	fastReconnect(t, 10*time.Millisecond, 40*time.Millisecond)
	attempts, _ := fakeVerify(t, func() bool { return true }, 0)
	d := pairedDiscoveredDevice(t)

	var mu sync.Mutex
	errs := 0
	ctx, cancel := context.WithCancel(context.Background())
	returned := keepConnected(d, ctx, nil, func(error) {
		mu.Lock()
		errs++
		mu.Unlock()
	})
	time.Sleep(300 * time.Millisecond)
	cancel()
	waitDone(t, returned)

	// pauses 10, 20, 40, 40... ms: about 9 attempts in 300ms, not hundreds
	n := attempts()
	if n < 3 || n > 12 {
		t.Fatalf("%d attempts", n)
	}
	mu.Lock()
	defer mu.Unlock()
	if errs != n {
		t.Fatalf("%d errors reported for %d attempts", errs, n)
	}
}

func TestKeepConnectedWaitsForDiscovery(t *testing.T) {
	fastReconnect(t, time.Hour, time.Hour)
	attempts, _ := fakeVerify(t, nil, 0)
	c := newTestController(t)
	c.st.SavePairing(Pairing{Name: "Bridge", Id: "AA:BB"})
	c.LoadPairings()
	d := c.GetDevice("Bridge")
	defer d.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	keepConnected(d, ctx, nil, nil)
	time.Sleep(50 * time.Millisecond)
	if attempts() != 0 {
		t.Fatal("device that is not discovered should not be tried")
	}

	// discovered: tried right away, not after an hour
	c.onDnssdAdd(entryWithId("Bridge", "AA:BB"))
	waitFor(t, "connection", d.IsVerified)
}

func TestKeepConnectedRediscoveryCutsPause(t *testing.T) {
	fastReconnect(t, time.Hour, time.Hour)
	var mu sync.Mutex
	failing := true
	attempts, _ := fakeVerify(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return failing
	}, 0)
	c := newTestController(t)
	d, _ := c.onDnssdAdd(entryWithId("Bridge", "AA:BB"))
	d.setPairing(Pairing{Name: "Bridge", Id: "AA:BB"}, true)
	defer d.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	keepConnected(d, ctx, nil, nil)
	waitFor(t, "first attempt", func() bool { return attempts() == 1 })

	// accessory restarts
	mu.Lock()
	failing = false
	mu.Unlock()
	c.onDnssdRemove(entryWithId("Bridge", "AA:BB"))
	c.onDnssdAdd(entryWithId("Bridge", "AA:BB"))
	waitFor(t, "connection", d.IsVerified)
}

func TestKeepConnectedStopsWhenUnpaired(t *testing.T) {
	fastReconnect(t, time.Hour, time.Hour)
	fakeVerify(t, nil, 0)
	c := newTestController(t)
	c.st.SavePairing(Pairing{Name: "Bridge", Id: "AA:BB"})
	c.LoadPairings()
	d := c.GetDevice("Bridge")

	// offline, waiting for discovery
	returned := keepConnected(d, context.Background(), nil, nil)
	time.Sleep(20 * time.Millisecond)
	d.ForgetPairing()
	waitDone(t, returned)
}

func TestKeepConnectedSeesManualReconnect(t *testing.T) {
	fastReconnect(t, 10*time.Millisecond, time.Hour)
	verifyAttempts, _ := fakeVerify(t, nil, 50*time.Millisecond)
	d := pairedDiscoveredDevice(t)

	var mu sync.Mutex
	connected := 0
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	keepConnected(d, ctx, func() {
		mu.Lock()
		connected++
		mu.Unlock()
	}, nil)
	count := func() int {
		mu.Lock()
		defer mu.Unlock()
		return connected
	}
	waitFor(t, "connection", func() bool { return count() == 1 })

	// like PairVerify called meanwhile: new connection replaces old one,
	// it is not replaced again by KeepConnected
	attempts := verifyAttempts()
	d.PairVerify()
	waitFor(t, "new connection noticed", func() bool { return count() == 2 })
	time.Sleep(150 * time.Millisecond)
	if n := verifyAttempts(); n != attempts+1 || count() != 2 {
		t.Fatalf("%d verify attempts after manual one, %d connections", n-attempts-1, count())
	}
}

func TestKeepConnectedSingleLoop(t *testing.T) {
	fastReconnect(t, time.Hour, time.Hour)
	fakeVerify(t, nil, 0)
	d := pairedDiscoveredDevice(t)

	var mu sync.Mutex
	connected := 0
	onConnected := func() {
		mu.Lock()
		connected++
		mu.Unlock()
	}
	ctx, cancel := context.WithCancel(context.Background())
	first := keepConnected(d, ctx, onConnected, nil)
	waitFor(t, "connection", d.IsVerified)

	// e.g. called again when device is discovered again
	second := keepConnected(d, ctx, onConnected, nil)
	waitDone(t, second)
	time.Sleep(20 * time.Millisecond)
	mu.Lock()
	if connected != 1 {
		t.Fatalf("onConnected called %d times", connected)
	}
	mu.Unlock()

	// can run again after first one returned
	cancel()
	waitDone(t, first)
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	keepConnected(d, ctx2, onConnected, nil)
	waitFor(t, "onConnected of new loop", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return connected == 2
	})
}
