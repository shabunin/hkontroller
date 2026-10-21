package hkontroller

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/shabunin/dnssd"
)

func testEntry(iface string, port int, ips ...string) dnssd.BrowseEntry {
	e := dnssd.BrowseEntry{Name: "Bridge", IfaceName: iface, Port: port}
	for _, ip := range ips {
		e.IPs = append(e.IPs, net.ParseIP(ip))
	}
	return e
}

func newTestController(t *testing.T) *Controller {
	c, err := NewController(NewMemStore(), "test")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestDiscoveryPerInterface(t *testing.T) {
	c := newTestController(t)

	eth := testEntry("eth0", 51827, "192.168.1.2", "fe80::1")
	wlan := testEntry("wlan0", 51827, "192.168.1.2", "fe80::2")

	dd, discovered := c.onDnssdAdd(eth)
	if !discovered || !dd.IsDiscovered() {
		t.Fatal("first entry should discover device")
	}
	if d2, discovered := c.onDnssdAdd(wlan); discovered || d2 != dd {
		t.Fatal("second interface should not discover device again")
	}

	if _, lost := c.onDnssdRemove(eth); lost {
		t.Fatal("device is still advertised on wlan0")
	}
	if !dd.IsDiscovered() || c.GetDevice("Bridge") == nil {
		t.Fatal("device should stay discovered")
	}

	if _, lost := c.onDnssdRemove(wlan); !lost {
		t.Fatal("device should be lost")
	}
	if dd.IsDiscovered() {
		t.Fatal("device should not be discovered")
	}
	// not paired, so controller forgets it
	if c.GetDevice("Bridge") != nil {
		t.Fatal("lost unpaired device should be removed")
	}

	// remove for unknown device or interface is ignored
	if _, lost := c.onDnssdRemove(wlan); lost {
		t.Fatal("unexpected lost")
	}
}

func TestDiscoveryPairedDeviceStays(t *testing.T) {
	c := newTestController(t)
	dd, _ := c.onDnssdAdd(testEntry("eth0", 51827, "192.168.1.2"))
	dd.setPairing(Pairing{Name: "Bridge", Id: "AA"}, true)

	if _, lost := c.onDnssdRemove(testEntry("eth0", 51827)); !lost {
		t.Fatal("device should be lost")
	}
	if c.GetDevice("Bridge") != dd {
		t.Fatal("paired device should be kept")
	}

	// rediscovered device is the same object
	if d2, discovered := c.onDnssdAdd(testEntry("eth0", 51827, "192.168.1.2")); !discovered || d2 != dd {
		t.Fatal("paired device should be rediscovered")
	}
}

func TestDiscoveryPortChange(t *testing.T) {
	c := newTestController(t)
	dd, _ := c.onDnssdAdd(testEntry("eth0", 51827, "192.168.1.2"))

	// accessory restarted on new port: new entry comes, then removal of old one
	c.onDnssdAdd(testEntry("eth0", 40000, "192.168.1.2"))
	if _, lost := c.onDnssdRemove(testEntry("eth0", 51827)); lost {
		t.Fatal("removal of old port should not lose device")
	}
	if e := dd.GetDnssdEntry(); e.Port != 40000 {
		t.Fatalf("expected new port, got %d", e.Port)
	}
}

func TestDialAddrs(t *testing.T) {
	entries := []dnssd.BrowseEntry{
		testEntry("eth0", 51827, "fe80::1", "192.168.1.2"),
		testEntry("wlan0", 51827, "fe80::2", "192.168.1.2"),
	}
	got := dialAddrs(entries)
	want := []string{
		"192.168.1.2:51827", // same ip4 on both interfaces dialed once
		"[fe80::1%eth0]:51827",
		"[fe80::2%wlan0]:51827",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestDnssdEntryIsCopied(t *testing.T) {
	c := newTestController(t)
	e := testEntry("eth0", 51827, "192.168.1.2", "fe80::1")
	dd, _ := c.onDnssdAdd(e)

	got := dd.GetDnssdEntry()
	got.IPs[0] = net.ParseIP("10.0.0.1")
	e.IPs[1] = net.ParseIP("10.0.0.2")

	if ips := dd.GetDnssdEntry().IPs; ips[0].String() != "192.168.1.2" || ips[1].String() != "fe80::1" {
		t.Fatalf("device entry was modified from outside: %v", ips)
	}
}

func TestLoadPairingsUnescapesNames(t *testing.T) {
	store := NewMemStore()
	st := storer{store}
	if err := st.SavePairing(Pairing{Name: `Hk\ Bridge`, Id: "AA:BB"}); err != nil {
		t.Fatal(err)
	}

	c, err := NewController(store, "test")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.LoadPairings(); err != nil {
		t.Fatal(err)
	}

	dd := c.GetDevice("Hk Bridge")
	if dd == nil || !dd.IsPaired() {
		t.Fatal("paired device should be loaded with unescaped name")
	}
	if pp := st.Pairings(); len(pp) != 1 || pp[0].Name != "Hk Bridge" {
		t.Fatalf("pairing is not migrated in store: %+v", pp)
	}

	// discovery reports unescaped name, so it finds the paired device
	e := testEntry("eth0", 51827, "192.168.1.2")
	e.Name = "Hk Bridge"
	if d2, discovered := c.onDnssdAdd(e); !discovered || d2 != dd {
		t.Fatal("discovered device should be the paired one")
	}
}

// fakeLookup replaces dnssd lookup with fn, which calls add/rmv like dnssd does.
// returned is closed when lookup returns first time.
func fakeLookup(t *testing.T, fn func(add dnssd.AddFunc, rmv dnssd.RmvFunc)) (returned chan struct{}) {
	returned = make(chan struct{})
	var once sync.Once
	old := lookupType
	lookupType = func(ctx context.Context, service string, add dnssd.AddFunc, rmv dnssd.RmvFunc) error {
		defer once.Do(func() { close(returned) })
		fn(add, rmv)
		<-ctx.Done()
		return ctx.Err()
	}
	t.Cleanup(func() { lookupType = old })
	return returned
}

func entryNamed(name string) dnssd.BrowseEntry {
	e := testEntry("eth0", 51827, "192.168.1.2")
	e.Name = name
	return e
}

func receiveDevice(t *testing.T, ch <-chan *Device) *Device {
	t.Helper()
	select {
	case d, ok := <-ch:
		if !ok {
			t.Fatal("channel closed")
		}
		return d
	case <-time.After(time.Second):
		t.Fatal("no device received")
	}
	return nil
}

func TestDiscoveryNotBlockedByReader(t *testing.T) {
	c := newTestController(t)
	browsed := make(chan struct{})
	fakeLookup(t, func(add dnssd.AddFunc, rmv dnssd.RmvFunc) {
		for i := 0; i < 50; i++ {
			add(entryNamed(fmt.Sprintf("Dev %d", i)))
		}
		close(browsed)
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	discoverCh, _ := c.StartDiscoveryWithContext(ctx)

	// nobody reads yet, browsing must go on
	select {
	case <-browsed:
	case <-time.After(time.Second):
		t.Fatal("discovery is blocked until channel is read")
	}

	for i := 0; i < 50; i++ {
		if d := receiveDevice(t, discoverCh); d.Name != fmt.Sprintf("Dev %d", i) {
			t.Fatalf("got %s at %d, order is not kept", d.Name, i)
		}
	}
}

func TestDiscoveryWithUnreadLostChannel(t *testing.T) {
	c := newTestController(t)
	fakeLookup(t, func(add dnssd.AddFunc, rmv dnssd.RmvFunc) {
		add(entryNamed("A"))
		rmv(entryNamed("A"))
		add(entryNamed("B"))
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	discoverCh, _ := c.StartDiscoveryWithContext(ctx)

	// lost channel is never read
	if d := receiveDevice(t, discoverCh); d.Name != "A" {
		t.Fatalf("unexpected %s", d.Name)
	}
	if d := receiveDevice(t, discoverCh); d.Name != "B" {
		t.Fatalf("unexpected %s", d.Name)
	}
}

func TestStopDiscoveryWithoutReader(t *testing.T) {
	c := newTestController(t)
	browsed := make(chan struct{})
	returned := fakeLookup(t, func(add dnssd.AddFunc, rmv dnssd.RmvFunc) {
		add(entryNamed("A"))
		add(entryNamed("B"))
		rmv(entryNamed("A"))
		close(browsed)
	})

	discoverCh, lostCh := c.StartDiscovery()
	select {
	case <-browsed:
	case <-time.After(time.Second):
		t.Fatal("discovery is blocked until channel is read")
	}

	c.StopDiscovery()
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("lookup did not stop")
	}

	// both channels are closed, undelivered devices may be dropped
	for _, ch := range []<-chan *Device{discoverCh, lostCh} {
		timeout := time.After(time.Second)
	drain:
		for {
			select {
			case _, ok := <-ch:
				if !ok {
					break drain
				}
			case <-timeout:
				t.Fatal("channel is not closed after discovery stopped")
			}
		}
	}
}

func TestStopDiscoveryRightAfterStart(t *testing.T) {
	fakeLookup(t, func(dnssd.AddFunc, dnssd.RmvFunc) {})
	for i := 0; i < 100; i++ {
		c := newTestController(t)

		discoverCh, lostCh := c.StartDiscovery()
		c.StopDiscovery()

		// lookup may not even start, channels are closed when discovery is stopped
		for _, ch := range []<-chan *Device{discoverCh, lostCh} {
			select {
			case _, ok := <-ch:
				if ok {
					t.Fatalf("run %d: unexpected device", i)
				}
			case <-time.After(time.Second):
				t.Fatalf("run %d: discovery keeps running after StopDiscovery", i)
			}
		}
	}
}

func TestDiscoveryRetriesWithDelay(t *testing.T) {
	old := lookupType
	t.Cleanup(func() { lookupType = old })
	var mu sync.Mutex
	calls := 0
	lookupType = func(ctx context.Context, service string, add dnssd.AddFunc, rmv dnssd.RmvFunc) error {
		mu.Lock()
		calls++
		mu.Unlock()
		return fmt.Errorf("no interfaces")
	}
	oldDelay := discoveryRetryDelay
	discoveryRetryDelay = 50 * time.Millisecond
	t.Cleanup(func() { discoveryRetryDelay = oldDelay })

	c := newTestController(t)
	discoverCh, _ := c.StartDiscovery()
	time.Sleep(225 * time.Millisecond)
	c.StopDiscovery()
	for range discoverCh {
	}

	mu.Lock()
	defer mu.Unlock()
	if calls < 2 || calls > 6 {
		t.Fatalf("lookup called %d times, expected retry every 50ms", calls)
	}
}

func TestFsStoreOverwrite(t *testing.T) {
	st := NewFsStore(t.TempDir())
	if err := st.Set("key", []byte("long value")); err != nil {
		t.Fatal(err)
	}
	if err := st.Set("key", []byte("short")); err != nil {
		t.Fatal(err)
	}
	if b, _ := st.Get("key"); string(b) != "short" {
		t.Fatalf("got %q", b)
	}
}

func TestEscapedPairingSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	st := storer{NewFsStore(dir)}
	if err := st.SavePairing(Pairing{Name: `Hk\ Bridge`, Id: "AA:BB"}); err != nil {
		t.Fatal(err)
	}

	// first start migrates name and saves shorter pairing
	for i := 0; i < 2; i++ {
		c, err := NewController(NewFsStore(dir), "test")
		if err != nil {
			t.Fatal(err)
		}
		if err := c.LoadPairings(); err != nil {
			t.Fatal(err)
		}
		if dd := c.GetDevice("Hk Bridge"); dd == nil || !dd.IsPaired() {
			t.Fatalf("start %d: pairing is lost", i)
		}
	}
}

func TestLoadPairingWithTrailingData(t *testing.T) {
	// pairing file overwritten without truncate by older versions
	st := storer{NewMemStore()}
	st.Set(keyForPairingName("AA:BB"), []byte(`{"name":"Hk Bridge","id":"AA:BB"}"}`))

	if pp := st.Pairings(); len(pp) != 1 || pp[0].Name != "Hk Bridge" {
		t.Fatalf("damaged pairing is not loaded: %+v", pp)
	}
}

func TestSplitMac(t *testing.T) {
	for _, n := range []int{0, 4, 15} {
		if _, _, err := splitMac(make([]byte, n)); err == nil {
			t.Fatalf("%d bytes: expected error", n)
		}
	}
	data := append([]byte("msg"), bytes.Repeat([]byte{7}, 16)...)
	msg, mac, err := splitMac(data)
	if err != nil || string(msg) != "msg" || mac[0] != 7 || mac[15] != 7 {
		t.Fatalf("got %q %v %v", msg, mac, err)
	}
}
