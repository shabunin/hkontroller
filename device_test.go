package hkontroller

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shabunin/dnssd"
)

// fakeAccessory answers requests on the other side of net.Pipe without encryption.
type fakeAccessory struct {
	t    *testing.T
	conn net.Conn
	wmu  sync.Mutex

	// handle returns raw response for request, empty string means no response
	handle func(req *http.Request, body string) string

	mu   sync.Mutex
	puts []string // bodies of PUT /characteristics
}

func (a *fakeAccessory) write(s string) {
	a.wmu.Lock()
	defer a.wmu.Unlock()
	_, _ = a.conn.Write([]byte(s))
}

func (a *fakeAccessory) serve() {
	rd := bufio.NewReader(a.conn)
	for {
		req, err := http.ReadRequest(rd)
		if err != nil {
			return
		}
		b, _ := io.ReadAll(req.Body)
		if req.Method == "PUT" {
			a.mu.Lock()
			a.puts = append(a.puts, string(b))
			a.mu.Unlock()
		}
		if res := a.handle(req, string(b)); res != "" {
			a.write(res)
		}
	}
}

func (a *fakeAccessory) putBodies() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.puts...)
}

func noContent(*http.Request, string) string {
	return "HTTP/1.1 204 No Content\r\n\r\n"
}

func eventMessage(aid, iid uint64, value interface{}) string {
	body := fmt.Sprintf(`{"characteristics":[{"aid":%d,"iid":%d,"value":%v}]}`, aid, iid, value)
	return fmt.Sprintf("EVENT/1.0 200 OK\r\nContent-Type: application/hap+json\r\nContent-Length: %d\r\n\r\n%s",
		len(body), body)
}

func jsonResponse(body string) string {
	return fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/hap+json\r\nContent-Length: %d\r\n\r\n%s",
		len(body), body)
}

// newTestDevice returns verified device connected to fake accessory.
func newTestDevice(t *testing.T, handle func(*http.Request, string) string) (*Device, *fakeAccessory) {
	client, server := net.Pipe()
	acc := &fakeAccessory{t: t, conn: server, handle: handle}
	go acc.serve()

	d := newDevice("test", nil, "ctrl", nil, nil)
	cc := newConn(client)
	cc.SetEventCallback(d.onEvent)
	d.cc = cc
	d.httpc = &http.Client{Transport: newRoundTripper(cc)}
	d.verified = true
	d.startBackgroundRead(cc)

	t.Cleanup(func() {
		server.Close()
		closeWithin(t, d, time.Second)
	})
	return d, acc
}

func closeWithin(t *testing.T, d *Device, timeout time.Duration) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		d.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(timeout):
		t.Fatal("device close is blocked")
	}
}

func receive(t *testing.T, ch <-chan CharacteristicUpdate) CharacteristicUpdate {
	t.Helper()
	select {
	case ev, ok := <-ch:
		if !ok {
			t.Fatal("channel closed")
		}
		return ev
	case <-time.After(time.Second):
		t.Fatal("no event received")
	}
	return CharacteristicUpdate{}
}

func expectNothing(t *testing.T, ch <-chan CharacteristicUpdate) {
	t.Helper()
	select {
	case ev, ok := <-ch:
		t.Fatalf("unexpected event %+v, open=%v", ev, ok)
	case <-time.After(50 * time.Millisecond):
	}
}

func expectClosed(t *testing.T, ch <-chan CharacteristicUpdate) {
	t.Helper()
	select {
	case _, ok := <-ch:
		if ok {
			t.Fatal("channel should be closed")
		}
	case <-time.After(time.Second):
		t.Fatal("channel is not closed")
	}
}

func testAccessories() []*Accessory {
	var accs Accessories
	err := json.Unmarshal([]byte(`{"accessories":[{"aid":1,"services":[{"iid":1,"type":"43","characteristics":[
		{"iid":2,"type":"25","perms":["pr","pw","ev"]},
		{"iid":3,"type":"23","perms":["pr"]},
		{"iid":4,"type":"8","perms":["pr","pw","ev"]}]}]}]}`), &accs)
	if err != nil {
		panic(err)
	}
	return accs.Accs
}

func TestSubscriptionsDispatch(t *testing.T) {
	d, acc := newTestDevice(t, noContent)
	d.accs = testAccessories()

	single, err := d.SubscribeToEvents(1, 2)
	if err != nil {
		t.Fatal(err)
	}
	accessory, err := d.SubscribeToAccessoryEvents(1)
	if err != nil {
		t.Fatal(err)
	}

	puts := acc.putBodies()
	if len(puts) != 2 {
		t.Fatalf("expected 2 PUT requests, got %v", puts)
	}
	if !strings.Contains(puts[0], `"aid":1,"iid":2,"ev":true`) {
		t.Fatalf("unexpected PUT: %s", puts[0])
	}
	// 1.2 is already enabled, 1.3 does not support events
	if strings.Contains(puts[1], `"iid":2`) || strings.Contains(puts[1], `"iid":3`) ||
		!strings.Contains(puts[1], `"aid":1,"iid":4,"ev":true`) {
		t.Fatalf("unexpected PUT: %s", puts[1])
	}

	acc.write(eventMessage(1, 2, true))
	for _, ch := range []<-chan CharacteristicUpdate{single, accessory} {
		ev := receive(t, ch)
		if ev.Aid != 1 || ev.Iid != 2 || ev.Value != true {
			t.Fatalf("unexpected event %+v", ev)
		}
	}

	acc.write(eventMessage(1, 4, 42))
	if ev := receive(t, accessory); ev.Iid != 4 {
		t.Fatalf("unexpected event %+v", ev)
	}
	expectNothing(t, single)

	// value is updated in accessories list
	if v := d.Accessories()[0].Ss[0].Cs[2].Value; v != float64(42) {
		t.Fatalf("accessory value not updated: %v", v)
	}

	// accessory subscription still needs 1.2, so no request is sent
	if err := d.UnsubscribeFromEvents(1, 2); err != nil {
		t.Fatal(err)
	}
	expectClosed(t, single)
	if n := len(acc.putBodies()); n != 2 {
		t.Fatalf("expected no new PUT, got %d", n)
	}

	if err := d.Unsubscribe(accessory); err != nil {
		t.Fatal(err)
	}
	expectClosed(t, accessory)
	puts = acc.putBodies()
	if len(puts) != 3 || !strings.Contains(puts[2], `"iid":2,"ev":false`) ||
		!strings.Contains(puts[2], `"iid":4,"ev":false`) {
		t.Fatalf("unexpected PUT: %v", puts)
	}

	// already closed
	if err := d.Unsubscribe(accessory); err != nil {
		t.Fatal(err)
	}
}

func TestSlowSubscriberDoesNotBlockConnection(t *testing.T) {
	d, acc := newTestDevice(t, func(req *http.Request, _ string) string {
		if req.Method == "GET" {
			return jsonResponse(`{"characteristics":[{"aid":1,"iid":2,"value":1}]}`)
		}
		return noContent(req, "")
	})

	ignored, err := d.SubscribeToEvents(1, 2)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < eventBufferSize*4; i++ {
		acc.write(eventMessage(1, 2, i))
	}

	done := make(chan error, 1)
	go func() {
		_, err := d.GetCharacteristic(1, 2)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("request blocked by subscriber that is not reading")
	}

	if n := len(ignored); n != eventBufferSize {
		t.Fatalf("expected %d buffered events, got %d", eventBufferSize, n)
	}
}

func TestEventFollowedByResponse(t *testing.T) {
	d, _ := newTestDevice(t, func(*http.Request, string) string {
		// event and response arrive in single write
		return eventMessage(1, 2, 7) + jsonResponse(`{"characteristics":[{"aid":1,"iid":2,"value":7}]}`)
	})

	ch := make(chan CharacteristicUpdate, 1)
	d.addSub(&eventSub{aid: 1, iid: 2, ch: ch})

	c, err := d.GetCharacteristic(1, 2)
	if err != nil {
		t.Fatal(err)
	}
	if c.Value != float64(7) {
		t.Fatalf("unexpected value %v", c.Value)
	}
	if ev := receive(t, ch); ev.Value != float64(7) {
		t.Fatalf("unexpected event %+v", ev)
	}
}

func TestLateResponseAfterTimeout(t *testing.T) {
	release := make(chan struct{})
	d, acc := newTestDevice(t, func(*http.Request, string) string { return "" })

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", "/characteristics?id=1.2", nil)
	if _, err := d.doRequest(req); err == nil {
		t.Fatal("expected timeout")
	}

	// response arrives when nobody waits for it, loop must not block or panic
	go func() {
		acc.write(jsonResponse(`{}`))
		close(release)
	}()
	select {
	case <-release:
	case <-time.After(time.Second):
		t.Fatal("late response is not consumed")
	}

	closeWithin(t, d, time.Second)
}

func TestCloseUnblocksRequestAndSubscriptions(t *testing.T) {
	d, _ := newTestDevice(t, func(req *http.Request, _ string) string {
		if req.Method == "GET" {
			return "" // never answer
		}
		return noContent(req, "")
	})

	ch, err := d.SubscribeToEvents(1, 2)
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		// no request timeout, only close may unblock it
		req, _ := http.NewRequest("GET", "/accessories", nil)
		_, err := d.doRequest(req)
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)

	closeWithin(t, d, time.Second)
	expectClosed(t, ch)

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected error")
		}
	case <-time.After(time.Second):
		t.Fatal("request is not unblocked by close")
	}

	if d.IsVerified() || d.CloseReason() == nil {
		t.Fatal("device state is not reset")
	}
}

func TestCloseWithoutBackgroundRead(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()

	d := newDevice("test", nil, "ctrl", nil, nil)
	d.cc = newConn(client)
	d.httpc = &http.Client{Transport: newRoundTripper(d.cc)}

	closeWithin(t, d, time.Second)
}

func waitDone(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("done channel is not closed")
	}
}

func TestDoneOnConnectionLoss(t *testing.T) {
	d, acc := newTestDevice(t, noContent)

	done := d.Done()
	select {
	case <-done:
		t.Fatal("done is closed while connected")
	default:
	}

	acc.conn.Close() // accessory went offline
	waitDone(t, done)

	if d.IsVerified() || d.CloseReason() == nil {
		t.Fatal("device state is not reset before done")
	}
	// no connection anymore
	waitDone(t, d.Done())
}

func TestDoneOnClose(t *testing.T) {
	d, _ := newTestDevice(t, noContent)
	done := d.Done()
	closeWithin(t, d, time.Second)
	waitDone(t, done)
	if d.CloseReason() == nil {
		t.Fatal("close reason is not set")
	}
}

func TestDoneWithoutConnection(t *testing.T) {
	d := newDevice("test", nil, "ctrl", nil, nil)
	waitDone(t, d.Done())
}

func characteristicResponse(aid, iid uint64, value interface{}) string {
	return jsonResponse(fmt.Sprintf(`{"characteristics":[{"aid":%d,"iid":%d,"value":%v}]}`, aid, iid, value))
}

func getWithTimeout(d *Device, ep string, timeout time.Duration) (*http.Response, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", ep, nil)
	return d.doRequest(req)
}

func TestLateResponseGoesToItsRequest(t *testing.T) {
	d, _ := newTestDevice(t, func(req *http.Request, _ string) string {
		switch req.URL.Query().Get("id") {
		case "1.2":
			time.Sleep(200 * time.Millisecond) // slow accessory
			return characteristicResponse(1, 2, 111)
		case "1.3":
			return characteristicResponse(1, 3, 222)
		}
		return noContent(req, "")
	})

	if _, err := getWithTimeout(d, "/characteristics?id=1.2", 50*time.Millisecond); err == nil {
		t.Fatal("expected timeout")
	}

	// late response of 1.2 must not be taken as response of 1.3
	for i := 0; i < 3; i++ {
		c, err := d.GetCharacteristic(1, 3)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		if c.Value != float64(222) {
			t.Fatalf("request %d: got value %v of another request", i, c.Value)
		}
	}
}

func TestQueuedRequestTimesOut(t *testing.T) {
	d, _ := newTestDevice(t, func(req *http.Request, _ string) string {
		if req.URL.Query().Get("id") == "1.2" {
			return "" // never answer
		}
		return characteristicResponse(1, 3, 222)
	})

	go getWithTimeout(d, "/characteristics?id=1.2", 2*time.Second)
	time.Sleep(50 * time.Millisecond)

	start := time.Now()
	if _, err := getWithTimeout(d, "/characteristics?id=1.3", 100*time.Millisecond); err == nil {
		t.Fatal("expected timeout")
	}
	if waited := time.Since(start); waited > 500*time.Millisecond {
		t.Fatalf("queued request waited %v, longer than its timeout", waited)
	}
}

func TestLostResponseClosesConnection(t *testing.T) {
	defer func(old time.Duration) { lateResponseTimeout = old }(lateResponseTimeout)
	lateResponseTimeout = 200 * time.Millisecond

	d, _ := newTestDevice(t, func(*http.Request, string) string { return "" })
	done := d.Done()

	if _, err := getWithTimeout(d, "/characteristics?id=1.2", 50*time.Millisecond); err == nil {
		t.Fatal("expected timeout")
	}
	// responses can't be matched to requests anymore
	waitDone(t, done)
}

func TestPairingRequestTimesOut(t *testing.T) {
	defer func(old time.Duration) { pairingTimeout = old }(pairingTimeout)
	pairingTimeout = 100 * time.Millisecond

	d, _ := newTestDevice(t, func(*http.Request, string) string { return "" })

	errc := make(chan error, 1)
	go func() {
		_, err := d.doPost("/pairings", HTTPContentTypePairingTLV8, strings.NewReader(""))
		errc <- err
	}()
	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("expected timeout")
		}
	case <-time.After(time.Second):
		t.Fatal("pairing request without answer is stuck")
	}
}

// newEncryptedTestDevice returns verified device with encrypted session to fake accessory.
// Accessory side uses conn as well, so packets are split like by real accessory.
func newEncryptedTestDevice(t *testing.T, handle func(*http.Request, string) string) (*Device, *fakeAccessory) {
	client, server := net.Pipe()
	ss := &session{}
	copy(ss.encryptKey[:], bytes.Repeat([]byte{1}, 32))
	copy(ss.decryptKey[:], bytes.Repeat([]byte{2}, 32))
	sc := newConn(server)
	sc.UpgradeEnc(&session{encryptKey: ss.decryptKey, decryptKey: ss.encryptKey})
	acc := &fakeAccessory{t: t, conn: sc, handle: handle}
	go acc.serve()

	d := newDevice("test", nil, "ctrl", nil, nil)
	cc := newConn(client)
	cc.SetEventCallback(d.onEvent)
	cc.UpgradeEnc(ss)
	d.cc = cc
	d.httpc = &http.Client{Transport: newRoundTripper(cc)}
	d.verified = true
	d.startBackgroundRead(cc)

	t.Cleanup(func() {
		server.Close()
		closeWithin(t, d, time.Second)
	})
	return d, acc
}

func TestEncryptedResponseSizes(t *testing.T) {
	const header = "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n"
	size := 0
	d, _ := newEncryptedTestDevice(t, func(*http.Request, string) string {
		return fmt.Sprintf(header, size) + strings.Repeat("x", size)
	})

	// covers messages ending exactly at packet boundary, 1024, 2048...
	for size = 1; size <= 5200; size++ {
		res, err := getWithTimeout(d, "/x", time.Second)
		if err != nil {
			t.Fatalf("body %d, message %d: %v", size, len(fmt.Sprintf(header, size))+size, err)
		}
		if b, _ := io.ReadAll(res.Body); len(b) != size {
			t.Fatalf("body %d: got %d bytes", size, len(b))
		}
	}
}

func TestEncryptedEventAtPacketBoundary(t *testing.T) {
	d, acc := newEncryptedTestDevice(t, noContent)
	ch, err := d.SubscribeToEvents(1, 2)
	if err != nil {
		t.Fatal(err)
	}

	// pad string value, so event is exactly one full packet
	pad := 0
	ev := eventMessage(1, 2, `""`)
	for len(ev) != packetLengthMax {
		pad += packetLengthMax - len(ev)
		ev = eventMessage(1, 2, `"`+strings.Repeat("x", pad)+`"`)
	}
	acc.write(ev)
	receive(t, ch)
}

func TestConnReadAfterExactPacket(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	ss := &session{}
	cc := newConn(client)
	cc.UpgradeEnc(ss)

	go func() {
		acc := &session{encryptKey: ss.decryptKey}
		for _, msg := range []string{"first", "second"} {
			enc, _ := acc.Encrypt(strings.NewReader(msg))
			io.Copy(server, enc)
		}
	}()

	// buffer of exact packet size, next read must not return io.EOF
	for _, want := range []string{"first", "second"} {
		b := make([]byte, len(want))
		if n, err := cc.Read(b); err != nil || string(b[:n]) != want {
			t.Fatalf("got %q, %v, want %q", b[:n], err, want)
		}
	}
}

func TestPairVerifyShortEncryptedData(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	acc := &fakeAccessory{t: t, conn: server, handle: func(*http.Request, string) string {
		// M2 with public key and 4 bytes of encrypted data, MAC alone is 16
		tlv := append([]byte{6, 1, M2, 3, 32}, make([]byte, 32)...)
		tlv = append(tlv, 5, 4, 1, 2, 3, 4)
		return fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(tlv), tlv)
	}}
	go acc.serve()

	d := newDevice("test", nil, "ctrl", nil, nil)
	d.cc = newConn(client)
	d.httpc = &http.Client{Transport: newRoundTripper(d.cc)}
	d.paired = true

	if err := d.PairVerify(); err == nil {
		t.Fatal("expected error")
	}
}

func multiStatus(body string) string {
	return fmt.Sprintf("HTTP/1.1 207 Multi-Status\r\nContent-Type: application/hap+json\r\nContent-Length: %d\r\n\r\n%s",
		len(body), body)
}

func TestPutCharacteristicError(t *testing.T) {
	var response string
	d, _ := newTestDevice(t, func(*http.Request, string) string { return response })

	response = noContent(nil, "")
	if err := d.PutCharacteristic(1, 10, true); err != nil {
		t.Fatalf("success: %v", err)
	}

	response = multiStatus(`{"characteristics":[{"aid":1,"iid":10,"status":-70404}]}`)
	err := d.PutCharacteristic(1, 10, true)
	var cerr *CharacteristicError
	if !errors.As(err, &cerr) || cerr.Aid != 1 || cerr.Iid != 10 || cerr.Status != JsonStatusReadOnlyCharacteristic {
		t.Fatalf("expected read only error, got %v", err)
	}

	response = fmt.Sprintf("HTTP/1.1 400 Bad Request\r\nContent-Length: 17\r\n\r\n%s", `{"status":-70410}`)
	if err := d.PutCharacteristic(1, 10, true); err == nil {
		t.Fatal("expected error for bad request")
	}
}

func TestSubscribeRejected(t *testing.T) {
	d, _ := newTestDevice(t, func(*http.Request, string) string {
		return multiStatus(`{"characteristics":[{"aid":1,"iid":10,"status":-70406}]}`)
	})
	if _, err := d.SubscribeToEvents(1, 10); err == nil {
		t.Fatal("expected error")
	}
	if d.isCovered(1, 10) {
		t.Fatal("rejected subscription is kept")
	}
}

func TestMalformedResponseClosesConnection(t *testing.T) {
	d, _ := newTestDevice(t, func(*http.Request, string) string { return "garbage\r\n\r\n" })
	if _, err := getWithTimeout(d, "/characteristics?id=1.2", time.Second); err == nil {
		t.Fatal("expected error")
	}
	waitDone(t, d.Done())
}

func TestSetVerifiedOnClosedConnection(t *testing.T) {
	d, _ := newTestDevice(t, noContent)
	cc := d.conn()
	d.Close() // e.g. device lost during pair-verify

	if err := d.setVerified(cc, &session{}); err == nil {
		t.Fatal("expected error")
	}
	if d.IsVerified() {
		t.Fatal("closed device is verified")
	}
}

// pair-verify requests from several goroutines must share one connection
// connCounter counts connections of fake accessory, open and all.
type connCounter struct {
	mu                  sync.Mutex
	accepted, open, max int
}

func (c *connCounter) counts() (accepted, open, max int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.accepted, c.open, c.max
}

// pairingAccessory serves tlv response to every request, device is discovered at it.
func pairingAccessory(t *testing.T, tlv []byte) (*Device, *connCounter) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	counter := &connCounter{}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			counter.mu.Lock()
			counter.accepted++
			counter.open++
			counter.max = max(counter.max, counter.open)
			counter.mu.Unlock()
			acc := &fakeAccessory{t: t, conn: conn, handle: func(*http.Request, string) string {
				return tlvResponse(tlv)
			}}
			go func() {
				acc.serve()
				conn.Close()
				counter.mu.Lock()
				counter.open--
				counter.mu.Unlock()
			}()
		}
	}()

	d := newDevice("test", nil, "ctrl", nil, nil)
	d.addDnssdEntry(dnssd.BrowseEntry{Name: "test", IfaceName: "lo", Port: ln.Addr().(*net.TCPAddr).Port,
		IPs: []net.IP{net.ParseIP("127.0.0.1")}})
	t.Cleanup(func() { d.Close() })
	return d, counter
}

// waitClosed waits until all connections to accessory are closed.
func waitClosed(t *testing.T, counter *connCounter) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		_, open, _ := counter.counts()
		if open == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d connections left open", open)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestFailedPairVerifyClosesConnection(t *testing.T) {
	// M2 with authentication error, e.g. pairing was removed
	d, counter := pairingAccessory(t, []byte{6, 1, M2, 7, 1, 2})
	d.setPairing(Pairing{Name: "test", Id: "AA"}, true)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := d.PairVerify(); err == nil {
				t.Error("expected error")
			}
		}()
	}
	wg.Wait()

	waitClosed(t, counter)
	if accepted, _, max := counter.counts(); accepted != 10 || max != 1 {
		t.Fatalf("%d connections, %d at once, want one attempt at a time", accepted, max)
	}
	if d.conn() != nil || !strings.Contains(fmt.Sprint(d.CloseReason()), "pair-verify error on step M2") {
		t.Fatalf("connection should be closed with verify error, reason: %v", d.CloseReason())
	}
}

func TestFailedPairSetupClosesConnection(t *testing.T) {
	// M2 with unavailable error, e.g. paired with other controller
	d, counter := pairingAccessory(t, []byte{6, 1, M2, 7, 1, 6})

	var terr *TlvError
	if err := d.PairSetup("031-45-154"); !errors.As(err, &terr) || terr.Code != TlvErrorUnavailable.Code {
		t.Fatalf("expected unavailable error, got %v", err)
	}
	waitClosed(t, counter)
	if d.conn() != nil || d.CloseReason() == nil {
		t.Fatal("connection should be closed with pairing error")
	}
}

func tlvResponse(tlv []byte) string {
	return fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(tlv), tlv)
}

// newPairingTestDevice returns connected device before pair-verify, without encryption and background read.
func newPairingTestDevice(t *testing.T, handle func(*http.Request, string) string) *Device {
	client, server := net.Pipe()
	t.Cleanup(func() { server.Close() })
	go (&fakeAccessory{t: t, conn: server, handle: handle}).serve()

	d := newDevice("test", nil, "ctrl", nil, nil)
	d.cc = newConn(client)
	d.httpc = &http.Client{Transport: newRoundTripper(d.cc)}
	return d
}

// attach puts device into controller, advertised with accessory id.
func attach(c *Controller, d *Device, id string) dnssd.BrowseEntry {
	e := testEntry("eth0", 51827, "192.168.1.2")
	e.Name = d.Name
	e.Text = map[string]string{"id": id, "c#": "1"}
	d.ctrl = c
	d.id = deviceKey(e)
	c.putDevice(d)
	d.addDnssdEntry(e)
	return e
}

func TestLostPairedDeviceKeepsConnection(t *testing.T) {
	c := newTestController(t)
	d, _ := newTestDevice(t, func(*http.Request, string) string { return characteristicResponse(1, 2, 1) })
	e := attach(c, d, "AA:BB")
	d.setPairing(Pairing{Name: d.Name, Id: "AA:BB"}, true)

	if _, lost := c.onDnssdRemove(e); !lost {
		t.Fatal("device should be lost")
	}
	select {
	case <-d.Done():
		t.Fatalf("connection closed: %v", d.CloseReason())
	default:
	}
	if _, err := d.GetCharacteristic(1, 2); err != nil {
		t.Fatal(err)
	}
}

func TestLostUnpairedDeviceIsClosed(t *testing.T) {
	c := newTestController(t)
	d, _ := newTestDevice(t, noContent)
	e := attach(c, d, "AA:BB")

	if _, lost := c.onDnssdRemove(e); !lost {
		t.Fatal("device should be lost")
	}
	waitDone(t, d.Done())
	if c.GetDevice(d.Name) != nil {
		t.Fatal("lost unpaired device should be removed")
	}
}

func setAccessories(d *Device, accs []*Accessory) {
	d.mu.Lock()
	d.accs = accs
	d.mu.Unlock()
}

func TestAccessoriesAreCopies(t *testing.T) {
	d, acc := newTestDevice(t, noContent)
	setAccessories(d, testAccessories())
	ch, err := d.SubscribeToAllEvents()
	if err != nil {
		t.Fatal(err)
	}

	accs := d.Accessories()
	accs[0].Ss[0].Cs[0].Value = "changed by user"
	if v := d.Accessories()[0].Ss[0].Cs[0].Value; v != nil {
		t.Fatalf("device accessories are modified from outside: %v", v)
	}

	// read values while events update them, race detector tells
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 100; i++ {
			for _, c := range d.Accessories()[0].Ss[0].Cs {
				_ = fmt.Sprint(c.Value)
			}
		}
	}()
	for i := 0; i < 20; i++ {
		acc.write(eventMessage(1, 2, i))
		receive(t, ch)
	}
	<-done

	if v := d.Accessories()[0].Ss[0].Cs[0].Value; v != float64(19) {
		t.Fatalf("value is not updated by event: %v", v)
	}
}

func TestConfigChangeReloadsAccessories(t *testing.T) {
	var mu sync.Mutex
	body := `{"accessories":[{"aid":1,"services":[]}]}`
	d, _ := newTestDevice(t, func(req *http.Request, _ string) string {
		mu.Lock()
		defer mu.Unlock()
		return jsonResponse(body)
	})
	setAccessories(d, []*Accessory{{Id: 1}})
	c := newTestController(t)
	e := attach(c, d, "AA:BB")

	// same configuration
	c.onDnssdAdd(e)
	if len(d.Accessories()) != 1 {
		t.Fatal("accessories should stay")
	}

	// accessory added on bridge
	mu.Lock()
	body = `{"accessories":[{"aid":1,"services":[]},{"aid":2,"services":[]}]}`
	mu.Unlock()
	e.Text = map[string]string{"id": "AA:BB", "c#": "2"}
	c.onDnssdAdd(e)

	deadline := time.Now().Add(time.Second)
	for len(d.Accessories()) != 2 {
		if time.Now().After(deadline) {
			t.Fatal("accessories are not reloaded after configuration change")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestGetCharacteristicError(t *testing.T) {
	d, _ := newTestDevice(t, func(*http.Request, string) string {
		return multiStatus(`{"characteristics":[{"aid":1,"iid":4,"status":-70405}]}`)
	})
	_, err := d.GetCharacteristic(1, 4)
	var cerr *CharacteristicError
	if !errors.As(err, &cerr) || cerr.Status != JsonStatusWriteOnlyCharacteristic {
		t.Fatalf("expected write only error, got %v", err)
	}
}

func TestGetAccessoriesError(t *testing.T) {
	d, _ := newTestDevice(t, func(*http.Request, string) string {
		return "HTTP/1.1 470 Connection Authorization Required\r\nContent-Length: 17\r\n\r\n{\"status\":-70411}"
	})
	setAccessories(d, testAccessories())
	if err := d.GetAccessories(); err == nil {
		t.Fatal("expected error")
	}
	if len(d.Accessories()) == 0 {
		t.Fatal("accessories loaded before should stay")
	}
}

func TestPairingBackoff(t *testing.T) {
	d := newPairingTestDevice(t, func(*http.Request, string) string {
		// M2 with backoff error, retry in 300 seconds
		return tlvResponse([]byte{6, 1, M2, 7, 1, 3, 8, 2, 0x2c, 0x01})
	})
	_, err := d.pairSetupM1("031-45-154")
	var berr *BackoffError
	if !errors.As(err, &berr) || berr.RetryDelay != 300*time.Second {
		t.Fatalf("expected backoff for 300s, got %v", err)
	}
	var terr *TlvError
	if !errors.As(err, &terr) || terr.Code != TlvErrorBackoff.Code {
		t.Fatalf("backoff should be tlv error, got %v", err)
	}
}

func TestPairSetupErrorWithSalt(t *testing.T) {
	d := newPairingTestDevice(t, func(*http.Request, string) string {
		// M2 with error, but salt and public key present
		tlv := append([]byte{6, 1, M2, 7, 1, 6, 2, 16}, make([]byte, 16)...)
		tlv = append(append(tlv, 3, 32), make([]byte, 32)...)
		return tlvResponse(tlv)
	})
	_, err := d.pairSetupM1("031-45-154")
	var terr *TlvError
	if !errors.As(err, &terr) || terr.Code != TlvErrorUnavailable.Code {
		t.Fatalf("expected unavailable error, got %v", err)
	}
}

func readBody(t *testing.T, res *http.Response, err error) string {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestPairingResponsesInSingleWrite(t *testing.T) {
	defer func(old time.Duration) { pairingTimeout = old }(pairingTimeout)
	pairingTimeout = 200 * time.Millisecond

	first := true
	d := newPairingTestDevice(t, func(*http.Request, string) string {
		if first {
			first = false
			return tlvResponse([]byte("a")) + tlvResponse([]byte("b"))
		}
		return ""
	})
	for _, want := range []string{"a", "b"} {
		res, err := d.doPost("/pair-verify", HTTPContentTypePairingTLV8, strings.NewReader(""))
		if got := readBody(t, res, err); got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	}
}

func TestEventRightAfterPairingResponse(t *testing.T) {
	d := newPairingTestDevice(t, func(*http.Request, string) string {
		return tlvResponse([]byte("a")) + eventMessage(1, 2, 7)
	})
	res, err := d.doPost("/pair-verify", HTTPContentTypePairingTLV8, strings.NewReader(""))
	readBody(t, res, err)

	events := make(chan struct{}, 1)
	d.cc.SetEventCallback(func(*http.Response) { events <- struct{}{} })
	d.startBackgroundRead(d.cc)
	select {
	case <-events:
	case <-time.After(time.Second):
		t.Fatal("event read together with pairing response is lost")
	}
}

func TestReloadEnablesEventsForNewAccessory(t *testing.T) {
	var mu sync.Mutex
	body := `{"accessories":[{"aid":1,"services":[{"iid":1,"type":"49","characteristics":[
		{"iid":10,"type":"25","perms":["pr","pw","ev"]}]}]}]}`
	d, acc := newTestDevice(t, func(req *http.Request, _ string) string {
		if req.Method == "PUT" {
			return noContent(nil, "")
		}
		mu.Lock()
		defer mu.Unlock()
		return jsonResponse(body)
	})
	if err := d.GetAccessories(); err != nil {
		t.Fatal(err)
	}
	ch, err := d.SubscribeToAllEvents()
	if err != nil {
		t.Fatal(err)
	}

	// loaded by user, not changed by accessory
	changed := d.AccessoriesChanged()
	if err := d.GetAccessories(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-changed:
		t.Fatal("AccessoriesChanged fired without configuration change")
	default:
	}
	if puts := acc.putBodies(); len(puts) != 1 {
		t.Fatalf("events enabled again for known characteristics: %v", puts)
	}

	// accessory added on bridge, accessory reports new c#
	mu.Lock()
	body = `{"accessories":[{"aid":1,"services":[{"iid":1,"type":"49","characteristics":[
		{"iid":10,"type":"25","perms":["pr","pw","ev"]}]}]},
		{"aid":2,"services":[{"iid":1,"type":"49","characteristics":[
		{"iid":10,"type":"25","perms":["pr","pw","ev"]},{"iid":11,"type":"23","perms":["pr"]}]}]}]}`
	mu.Unlock()
	d.refreshAccessories()
	select {
	case <-changed:
	case <-time.After(time.Second):
		t.Fatal("AccessoriesChanged is not closed")
	}

	puts := acc.putBodies()
	if len(puts) != 2 || puts[1] != `{"characteristics":[{"aid":2,"iid":10,"ev":true}]}` {
		t.Fatalf("expected events enabled for new characteristic only: %v", puts)
	}
	acc.write(eventMessage(2, 10, 1))
	if ev := receive(t, ch); ev.Aid != 2 || ev.Iid != 10 {
		t.Fatalf("unexpected event %+v", ev)
	}
	if d.AccessoriesChanged() == changed {
		t.Fatal("new channel expected for next change")
	}
}

func TestPairRemoveResponse(t *testing.T) {
	for _, tc := range []struct {
		tlv  []byte
		code byte // expected tlv error code, 0 for success, 0xff for other error
	}{
		{[]byte{6, 1, M2}, 0},
		{[]byte{6, 1, M2, 7, 1, 2}, TlvErrorAuthentication.Code}, // e.g. not admin
		{[]byte{6, 1, M4}, 0xff},
		{[]byte{}, 0xff},
		{[]byte{6, 5, M2}, 0xff}, // truncated
	} {
		d := newPairingTestDevice(t, func(*http.Request, string) string { return tlvResponse(tc.tlv) })
		err := d.PairRemove("ctrl")
		var terr *TlvError
		switch {
		case tc.code == 0 && err != nil:
			t.Fatalf("%v: unexpected error %v", tc.tlv, err)
		case tc.code == 0xff && err == nil:
			t.Fatalf("%v: expected error", tc.tlv)
		case tc.code != 0 && tc.code != 0xff && (!errors.As(err, &terr) || terr.Code != tc.code):
			t.Fatalf("%v: expected tlv error %d, got %v", tc.tlv, tc.code, err)
		}
	}
}

// shortWriteConn accepts only limit bytes, then fails.
type shortWriteConn struct {
	net.Conn
	limit int
}

func (c *shortWriteConn) Write(b []byte) (int, error) {
	if len(b) > c.limit {
		return c.limit, errors.New("short write")
	}
	return len(b), nil
}

func (c *shortWriteConn) Close() error { return nil }

func testSessions() (client, server *session) {
	client = &session{}
	copy(client.encryptKey[:], bytes.Repeat([]byte{1}, 32))
	copy(client.decryptKey[:], bytes.Repeat([]byte{2}, 32))
	return client, &session{encryptKey: client.decryptKey, decryptKey: client.encryptKey}
}

func TestEncryptedWriteReturnsPlainLength(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	css, sss := testSessions()
	cc := newConn(client)
	cc.UpgradeEnc(css)
	sc := newConn(server)
	sc.UpgradeEnc(sss)

	msg := bytes.Repeat([]byte("x"), 3000) // several packets
	errc := make(chan error, 1)
	go func() {
		n, err := cc.Write(msg)
		if err == nil && n != len(msg) {
			err = fmt.Errorf("written %d bytes, want %d", n, len(msg))
		}
		errc <- err
	}()

	got := make([]byte, len(msg))
	if _, err := io.ReadFull(sc, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatal("decrypted data differs")
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
}

func TestEncryptedShortWriteClosesConn(t *testing.T) {
	css, _ := testSessions()
	cc := newConn(&shortWriteConn{limit: 10})
	cc.UpgradeEnc(css)

	n, err := cc.Write([]byte("GET /accessories HTTP/1.1\r\n\r\n"))
	if err == nil {
		t.Fatal("expected error")
	}
	if n != 0 {
		t.Fatalf("n = %d, want 0", n)
	}
	if !cc.isClosed() {
		t.Fatal("connection with broken encryption counter is not closed")
	}
}

// Accessory sending events from several threads without lock may encrypt
// them in one order and write in another. Stream can't be trusted after that.
func TestOutOfOrderPacketsCloseConnection(t *testing.T) {
	d, acc := newEncryptedTestDevice(t, noContent)
	ch, err := d.SubscribeToEvents(1, 2)
	if err != nil {
		t.Fatal(err)
	}

	// packet 0 was response to subscribe
	sc := acc.conn.(*conn)
	ss := sc.session()
	first, err := ss.Encrypt(strings.NewReader(eventMessage(1, 2, 1)))
	if err != nil {
		t.Fatal(err)
	}
	second, err := ss.Encrypt(strings.NewReader(eventMessage(1, 2, 2)))
	if err != nil {
		t.Fatal(err)
	}
	acc.wmu.Lock()
	io.Copy(sc.Conn, second)
	io.Copy(sc.Conn, first)
	acc.wmu.Unlock()

	waitDone(t, d.Done())
	expectClosed(t, ch)
	if reason := d.CloseReason(); reason == nil || !strings.Contains(reason.Error(), "decrypting packet 1 failed") {
		t.Fatalf("close reason: %v", reason)
	}
}
