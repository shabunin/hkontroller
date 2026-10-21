package hkontroller

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/shabunin/hkontroller/log"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/shabunin/dnssd"
)

// closedChan is returned by Done when there is no connection.
var closedChan = func() chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}()

const dialTimeout = 5 * time.Second
const reqTimeout = 15 * time.Second

// pairingTimeout is longer, since slow accessories need time for SRP and key generation
var pairingTimeout = 60 * time.Second

// lateResponseTimeout is how long to wait for response of timed out request
// before connection is considered broken
var lateResponseTimeout = reqTimeout

type Device struct {
	Name string

	ctrl *Controller

	controllerId   string
	controllerLTPK []byte
	controllerLTSK []byte

	// mu guards discovery, pairing and connection state below
	mu sync.Mutex

	dnssdEntries map[string]dnssd.BrowseEntry // mdns entries by interface name

	pairing Pairing
	paired  bool // completed /pair-setup?

	verified    bool // is connection established after /pair-verify?
	closeReason error
	cc          *conn
	ss          *session
	httpc       *http.Client // http client with encryption support
	accs        []*Accessory

	subscribeMu sync.Mutex // serializes subscribe/unsubscribe requests
	subsMu      sync.Mutex // guards subs, never held during requests
	subs        []*eventSub
}

type roundTripper struct {
	cc   *conn
	turn chan struct{} // taken by request in flight, one at a time
}

func newRoundTripper(cc *conn) *roundTripper {
	return &roundTripper{cc: cc, turn: make(chan struct{}, 1)}
}

var errConnClosed = errors.New("connection closed")

// RoundTrip implementation to be able to use with http.Client
func (r *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	// if background loop is running, response comes from it
	stopped := r.cc.loopStopped()

	// wait for previous request, but not longer than this one may take
	select {
	case r.turn <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-stopped:
		return nil, errConnClosed
	}
	release := func() { <-r.turn }

	if stopped == nil {
		defer release()
		return r.readDirect(req)
	}

	response := r.cc.expectResponse()
	if err := req.Write(r.cc); err != nil {
		// request may be written partially, following responses can't be trusted
		r.cc.close()
		release()
		return nil, err
	}

	select {
	case rr := <-response:
		release()
		return rr.res, rr.err
	case <-stopped:
		release()
		return nil, errConnClosed
	case <-ctx.Done():
		// keep the turn until late response arrives,
		// so that next request is not sent to busy accessory
		go r.awaitLateResponse(response, stopped, release)
		return nil, ctx.Err()
	}
}

// awaitLateResponse discards response of timed out request. If it doesn't come,
// connection is closed, since responses can't be matched to requests anymore.
func (r *roundTripper) awaitLateResponse(response chan responseResult, stopped <-chan struct{}, release func()) {
	defer release()
	select {
	case <-response:
		log.Debug.Println("late response discarded")
	case <-stopped:
	case <-time.After(lateResponseTimeout):
		log.Debug.Println("no response from accessory, closing connection")
		r.cc.close()
	}
}

// readDirect is used before background loop is started, during pairing.
func (r *roundTripper) readDirect(req *http.Request) (*http.Response, error) {
	if deadline, ok := req.Context().Deadline(); ok {
		r.cc.Conn.SetDeadline(deadline)
		defer r.cc.Conn.SetDeadline(time.Time{})
	}

	if err := req.Write(r.cc); err != nil {
		return nil, err
	}

	rd := bufio.NewReader(r.cc)
	res, err := http.ReadResponse(rd, req)
	if err != nil {
		return nil, err
	}

	return res, nil
}

func newDevice(name string, ctrl *Controller,
	controllerId string, controllerLTPK []byte, controllerLTSK []byte) *Device {

	return &Device{
		Name:           name,
		ctrl:           ctrl,
		controllerId:   controllerId,
		controllerLTPK: controllerLTPK,
		controllerLTSK: controllerLTSK,
		dnssdEntries:   make(map[string]dnssd.BrowseEntry),
	}
}

func copyEntry(e dnssd.BrowseEntry) dnssd.BrowseEntry {
	e.IPs = append([]net.IP(nil), e.IPs...)
	return e
}

// addDnssdEntry stores entry of interface where device is advertised.
// Returns true if device was not discovered before.
func (d *Device) addDnssdEntry(e dnssd.BrowseEntry) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	first := len(d.dnssdEntries) == 0
	d.dnssdEntries[e.IfaceName] = copyEntry(e)
	return first
}

// removeDnssdEntry forgets entry of interface.
// Returns true if device is no longer advertised on any interface.
func (d *Device) removeDnssdEntry(e dnssd.BrowseEntry) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	old, ok := d.dnssdEntries[e.IfaceName]
	if !ok || old.Port != e.Port {
		// unknown or already replaced by entry with new port
		return false
	}
	delete(d.dnssdEntries, e.IfaceName)
	return len(d.dnssdEntries) == 0
}

// entries returns copy of dnssd entries for all interfaces.
func (d *Device) entries() []dnssd.BrowseEntry {
	d.mu.Lock()
	defer d.mu.Unlock()
	var res []dnssd.BrowseEntry
	for _, e := range d.dnssdEntries {
		res = append(res, copyEntry(e))
	}
	return res
}

// GetDnssdEntry returns dnssd entry with IPs of all interfaces device is advertised on.
func (d *Device) GetDnssdEntry() dnssd.BrowseEntry {
	var res dnssd.BrowseEntry
	for i, e := range d.entries() {
		if i == 0 {
			res = e
			continue
		}
		res.IPs = append(res.IPs, e.IPs...)
	}
	return res
}

func (d *Device) setPairing(p Pairing, paired bool) {
	d.mu.Lock()
	d.pairing = p
	d.paired = paired
	d.mu.Unlock()
}

func (d *Device) conn() *conn {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.cc
}

func (d *Device) isConnected() bool {
	cc := d.conn()
	return cc != nil && !cc.isClosed()
}

func (d *Device) client() (*http.Client, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.httpc == nil || d.cc == nil || d.cc.isClosed() {
		return nil, errors.New("no http client available")
	}
	return d.httpc, nil
}

func (d *Device) doRequest(req *http.Request) (*http.Response, error) {
	httpc, err := d.client()
	if err != nil {
		return nil, err
	}
	return httpc.Do(req)
}

// doPost is used for pairing requests.
func (d *Device) doPost(url string, contentType string, body io.Reader) (*http.Response, error) {
	ctx, cancel := context.WithTimeout(context.Background(), pairingTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	return d.doRequest(req)
}

func (d *Device) close(reason error) {
	d.closeConn(d.conn(), reason)
}

// closeConn closes cc if it is still device's connection and
// waits until its background read is stopped.
// Event subscriptions are closed as well.
func (d *Device) closeConn(cc *conn, reason error) {
	d.mu.Lock()
	if d.cc != cc {
		// already closed or replaced by newer connection
		d.mu.Unlock()
		return
	}
	log.Debug.Printf("device <%s> close call with reason: %v\n", d.Name, reason)
	d.closeReason = reason
	d.cc = nil
	d.httpc = nil
	d.verified = false
	d.accs = nil
	d.mu.Unlock()

	if cc != nil {
		cc.close()
		if stopped := cc.loopStopped(); stopped != nil {
			<-stopped
		}
	}

	d.closeSubscriptions()

	if cc != nil {
		close(cc.done)
	}
}

// Done returns channel that is closed when current connection is closed,
// e.g. accessory went offline, device was lost or unpaired, or Close was called.
// CloseReason tells why. If device is not connected, returned channel is already closed.
//
// Typical reconnect loop:
//
//	for d.IsPaired() {
//		if err := d.PairVerify(); err != nil {
//			time.Sleep(retryTimeout)
//			continue
//		}
//		<-d.Done()
//	}
func (d *Device) Done() <-chan struct{} {
	cc := d.conn()
	if cc == nil {
		return closedChan
	}
	return cc.done
}

func (d *Device) Close() error {
	d.close(errors.New("manual close "))
	return nil
}

func (d *Device) connect() error {

	if d.conn() != nil {
		d.close(errors.New("close on reconnect"))
	}

	entries := d.entries()
	if len(entries) == 0 {
		return errors.New("not discovered")
	}

	dial, err := dialServiceInstance(context.Background(), entries, dialTimeout)
	if err != nil {
		return err
	}

	// connection, http client
	cc := newConn(dial)
	cc.SetEventCallback(d.onEvent)

	d.mu.Lock()
	d.cc = cc
	d.httpc = &http.Client{
		Transport: newRoundTripper(cc),
	}
	d.closeReason = nil
	d.mu.Unlock()

	return nil
}

// setVerified switches connection to encrypted session and starts background read.
func (d *Device) setVerified(ss *session) {
	d.mu.Lock()
	cc := d.cc
	d.ss = ss
	d.verified = true
	d.mu.Unlock()

	cc.UpgradeEnc(ss)
	d.startBackgroundRead(cc)
}

// startBackgroundRead reads responses and events from cc
// until it is closed, then closes device connection.
func (d *Device) startBackgroundRead(cc *conn) {
	stopped := cc.startLoop()
	go func() {
		<-stopped
		log.Debug.Println("background read: loop stopped")
		d.closeConn(cc, errors.New("stop background read"))
	}()
}

// IsDiscovered indicates if device is advertised via multicast dns
func (d *Device) IsDiscovered() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.dnssdEntries) > 0
}

// IsPaired returns true if device is paired by this controller.
// If another client is paired with device it will return false.
func (d *Device) IsPaired() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.paired
}

func (d *Device) GetPairingInfo() Pairing {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.pairing
}

// IsVerified returns true if /pair-verify step was completed by this controller.
func (d *Device) IsVerified() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.verified
}

// CloseReason returns last close reason if connection is closed
func (d *Device) CloseReason() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.closeReason
}

// Accessories return list of previously discovered accessories.
// GetAccessories should be called prior to this call.
func (d *Device) Accessories() []*Accessory {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.accs
}

// GetAccessories sends GET /accessories request and store
// result that can be retrieved with Accessories() method.
func (d *Device) GetAccessories() error {

	if !d.IsVerified() {
		return errors.New("paired device not verified or not connected")
	}

	ctx, cancel := context.WithTimeout(context.Background(), reqTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", "/accessories", nil)
	if err != nil {
		return err
	}
	res, err := d.doRequest(req)
	if err != nil {
		return err
	}

	all, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}

	var accs Accessories
	err = json.Unmarshal(all, &accs)
	if err != nil {
		return err
	}

	// shorten UUIDs
	for _, a := range accs.Accs {
		for _, s := range a.Ss {
			s.Type = s.Type.ToShort()
			for _, c := range s.Cs {
				c.Type = c.Type.ToShort()
			}
		}
	}

	d.mu.Lock()
	d.accs = accs.Accs
	d.mu.Unlock()

	return nil
}

// GetCharacteristic sends GET /characteristic request and return characteristic description and value.
func (d *Device) GetCharacteristic(aid uint64, cid uint64) (CharacteristicDescription, error) {
	ep := fmt.Sprintf("/characteristics?id=%d.%d", aid, cid)

	ctx, cancel := context.WithTimeout(context.Background(), reqTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", ep, nil)

	if err != nil {
		return CharacteristicDescription{}, err
	}

	res, err := d.doRequest(req)
	if err != nil {
		return CharacteristicDescription{}, err
	}

	all, err := io.ReadAll(res.Body)
	if err != nil {
		return CharacteristicDescription{}, err
	}

	type responsePayload struct {
		Characteristics []CharacteristicDescription `json:"characteristics"`
	}

	var chrs responsePayload
	err = json.Unmarshal(all, &chrs)
	if err != nil {
		return CharacteristicDescription{}, err
	}

	for _, c := range chrs.Characteristics {
		if c.Aid == aid && c.Iid == cid {
			return c, nil
		}
	}

	return CharacteristicDescription{}, errors.New("wrong response")
}

// PutCharacteristic makes PUT /characteristic request to control characteristic value.
func (d *Device) PutCharacteristic(aid uint64, cid uint64, val interface{}) error {

	type putPayload struct {
		Cs []CharacteristicPut `json:"characteristics"`
	}

	c := putPayload{Cs: []CharacteristicPut{{Aid: aid, Iid: cid, Value: val}}}
	b, err := json.Marshal(c)
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
	_ = res

	//all, err := io.ReadAll(res.Body)
	//if err != nil {
	//	return err
	//}
	//
	// TODO: extract errors. if response message is empty then no error occured
	// 		 case of error:
	//        {"characteristics":[{"aid":1,"iid":12,"status":-70402}]}
	// fmt.Println(string(all))

	return nil
}
