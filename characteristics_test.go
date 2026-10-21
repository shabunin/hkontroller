package hkontroller

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shabunin/dnssd"
)

func TestGetCharacteristics(t *testing.T) {
	var query string
	d, _ := newTestDevice(t, func(req *http.Request, _ string) string {
		query = req.URL.Query().Get("id")
		// listed in other order, one failed
		return multiStatus(`{"characteristics":[
			{"aid":3,"iid":4,"status":-70402},
			{"aid":1,"iid":2,"value":true,"status":0}]}`)
	})

	res, err := d.GetCharacteristics(CharacteristicId{1, 2}, CharacteristicId{3, 4})
	if query != "1.2,3.4" {
		t.Fatalf("query %q", query)
	}
	var cerr *CharacteristicError
	if !errors.As(err, &cerr) || cerr.Aid != 3 || cerr.Iid != 4 || cerr.Status != JsonStatusServiceCommunicationFailure {
		t.Fatalf("expected error of 3.4, got %v", err)
	}
	if len(res) != 2 || res[0].Aid != 1 || res[0].Value != true || res[1].Iid != 4 || *res[1].Status != -70402 {
		t.Fatalf("results: %+v", res)
	}
}

func TestGetCharacteristicsAllRead(t *testing.T) {
	d, _ := newTestDevice(t, func(*http.Request, string) string {
		return jsonResponse(`{"characteristics":[{"aid":1,"iid":2,"value":1},{"aid":1,"iid":3,"value":"x"}]}`)
	})
	res, err := d.GetCharacteristics(CharacteristicId{1, 2}, CharacteristicId{1, 3})
	if err != nil || res[0].Value != 1.0 || res[1].Value != "x" {
		t.Fatalf("results %+v, %v", res, err)
	}
	if _, err := d.GetCharacteristics(CharacteristicId{1, 2}, CharacteristicId{1, 5}); err == nil {
		t.Fatal("expected error for missing characteristic")
	}
}

func TestPutCharacteristicWithResponse(t *testing.T) {
	var body string
	d, _ := newTestDevice(t, func(_ *http.Request, b string) string {
		body = b
		return multiStatus(`{"characteristics":[{"aid":1,"iid":10,"status":0,"value":"cmVzcG9uc2U="}]}`)
	})

	val, err := d.PutCharacteristicWithResponse(1, 10, "cmVxdWVzdA==")
	if err != nil {
		t.Fatal(err)
	}
	if val != "cmVzcG9uc2U=" {
		t.Fatalf("value %v", val)
	}
	if body != `{"characteristics":[{"aid":1,"iid":10,"value":"cmVxdWVzdA==","r":true}]}` {
		t.Fatalf("request %s", body)
	}
}

func TestPutCharacteristicTimed(t *testing.T) {
	var mu sync.Mutex
	var requests []string
	d, _ := newTestDevice(t, func(req *http.Request, b string) string {
		mu.Lock()
		requests = append(requests, req.URL.Path+" "+b)
		mu.Unlock()
		if req.URL.Path == "/prepare" {
			return jsonResponse(`{"status":0}`)
		}
		return noContent(nil, "")
	})

	if err := d.PutCharacteristicTimed(1, 10, 1, 2500*time.Millisecond); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(requests) != 2 {
		t.Fatalf("requests: %q", requests)
	}
	var prepare struct {
		Ttl int64  `json:"ttl"`
		Pid uint64 `json:"pid"`
	}
	path, b, _ := strings.Cut(requests[0], " ")
	if err := json.Unmarshal([]byte(b), &prepare); path != "/prepare" || err != nil || prepare.Ttl != 2500 || prepare.Pid == 0 {
		t.Fatalf("prepare request %q", requests[0])
	}
	var put characteristicsPut
	path, b, _ = strings.Cut(requests[1], " ")
	if err := json.Unmarshal([]byte(b), &put); path != "/characteristics" || err != nil || put.Pid != prepare.Pid {
		t.Fatalf("write request %q", requests[1])
	}
}

func TestPutCharacteristicTimedPrepareRejected(t *testing.T) {
	d, acc := newTestDevice(t, func(*http.Request, string) string {
		return jsonResponse(`{"status":-70410}`)
	})
	if err := d.PutCharacteristicTimed(1, 10, 1, time.Second); err == nil {
		t.Fatal("expected error")
	}
	if len(acc.putBodies()) != 1 {
		t.Fatal("value should not be written after rejected prepare")
	}
}

// identifyAccessory serves plain http on loopback, like unpaired accessory.
func identifyAccessory(t *testing.T, response string) (*Device, <-chan string) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	requests := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		acc := &fakeAccessory{t: t, conn: conn, handle: func(req *http.Request, _ string) string {
			requests <- req.Method + " " + req.URL.Path
			return response
		}}
		acc.serve()
	}()

	d := newDevice("test", nil, "ctrl", nil, nil)
	d.addDnssdEntry(dnssd.BrowseEntry{Name: "test", IfaceName: "lo", Port: ln.Addr().(*net.TCPAddr).Port,
		IPs: []net.IP{net.ParseIP("127.0.0.1")}})
	return d, requests
}

func TestIdentifyUnpaired(t *testing.T) {
	d, requests := identifyAccessory(t, noContent(nil, ""))
	if err := d.Identify(); err != nil {
		t.Fatal(err)
	}
	if r := <-requests; r != "POST /identify" {
		t.Fatalf("request %q", r)
	}
}

func TestIdentifyPairedByOther(t *testing.T) {
	d, _ := identifyAccessory(t, "HTTP/1.1 400 Bad Request\r\nContent-Length: 17\r\n\r\n"+`{"status":-70401}`)
	err := d.Identify()
	if err == nil || !strings.Contains(err.Error(), "insufficient privileges") {
		t.Fatalf("expected insufficient privileges, got %v", err)
	}
}

func TestIdentifyPaired(t *testing.T) {
	// accessories are not loaded yet
	d, acc := newTestDevice(t, func(req *http.Request, _ string) string {
		if req.URL.Path == "/accessories" {
			return jsonResponse(`{"accessories":[
				{"aid":2,"services":[{"iid":1,"type":"3E","characteristics":[{"iid":5,"type":"14","perms":["pw"]}]}]},
				{"aid":1,"services":[{"iid":1,"type":"3E","characteristics":[
					{"iid":2,"type":"23","perms":["pr"]},
					{"iid":3,"type":"14","perms":["pw"]}]}]}]}`)
		}
		return noContent(nil, "")
	})
	d.setPairing(Pairing{Name: "test", Id: "AA"}, true)

	if err := d.Identify(); err != nil {
		t.Fatal(err)
	}
	if b := acc.putBodies(); len(b) != 1 || b[0] != `{"characteristics":[{"aid":1,"iid":3,"value":true}]}` {
		t.Fatalf("puts: %q", b)
	}
}
