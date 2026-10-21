package hkontroller

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
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
