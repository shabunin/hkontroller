package hkontroller

import (
	"bufio"
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
