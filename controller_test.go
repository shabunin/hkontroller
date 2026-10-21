package hkontroller

import (
	"net"
	"reflect"
	"testing"

	"github.com/hkontrol/dnssd"
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
