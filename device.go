package hkontroller

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/shabunin/hkontroller/log"
	"io"
	"net"
	"net/http"
	"strings"
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
	// Name is name device was created with, when it was discovered
	// or loaded from pairing. It doesn't change, see CurrentName.
	Name string

	id string // accessory id, key in controller devices

	ctrl *Controller

	controllerId   string
	controllerLTPK []byte
	controllerLTSK []byte

	// pairMu serializes PairSetup and PairVerify,
	// so they never open connections concurrently
	pairMu sync.Mutex

	// mu guards discovery, pairing and connection state below
	mu sync.Mutex

	dnssdEntries map[string]dnssd.BrowseEntry // mdns entries by interface name
	configNumber string                       // c# txt record, changes when accessories change
	currentName  string                       // latest mdns name, accessory may be renamed

	pairing Pairing
	paired  bool // completed /pair-setup?

	verified    bool // is connection established after /pair-verify?
	closeReason error
	cc          *conn
	ss          *session
	httpc       *http.Client // http client with encryption support
	accs        []*Accessory
	accsChanged chan struct{} // closed when accessories are loaded again after configuration change
	changed     chan struct{} // closed when device is discovered again or pairing changes, see stateChanged
	keeping     bool          // KeepConnected is running

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
		go r.awaitLateResponse(response, stopped, release, lateResponseTimeout)
		return nil, ctx.Err()
	}
}

// awaitLateResponse discards response of timed out request. If it doesn't come,
// connection is closed, since responses can't be matched to requests anymore.
func (r *roundTripper) awaitLateResponse(response chan responseResult, stopped <-chan struct{}, release func(),
	timeout time.Duration) {
	defer release()
	select {
	case <-response:
		log.Debug.Println("late response discarded")
	case <-stopped:
	case <-time.After(timeout):
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
	text := make(map[string]string, len(e.Text))
	for k, v := range e.Text {
		text[k] = v
	}
	e.Text = text
	return e
}

// Id returns accessory pairing id, e.g. "0E:AA:BB:CC:DD:05".
// Unlike name, it doesn't change. Empty if accessory doesn't advertise it.
func (d *Device) Id() string {
	if strings.HasPrefix(d.id, namePrefix) {
		return ""
	}
	return d.id
}

// entryUpdate tells what changed when mdns entry was added.
type entryUpdate struct {
	first         bool // device was not discovered before
	configChanged bool // c# changed, accessories have to be loaded again
	renamed       bool // paired device has new name, pairing has to be saved
}

// addDnssdEntry stores entry of interface where device is advertised.
func (d *Device) addDnssdEntry(e dnssd.BrowseEntry) entryUpdate {
	d.mu.Lock()
	defer d.mu.Unlock()
	var u entryUpdate
	u.first = len(d.dnssdEntries) == 0
	if u.first {
		d.notifyStateChanged()
	}
	d.dnssdEntries[e.IfaceName] = copyEntry(e)
	if cn := e.Text["c#"]; cn != "" {
		u.configChanged = d.configNumber != "" && cn != d.configNumber
		d.configNumber = cn
	}
	d.currentName = e.Name
	if d.paired && d.pairing.Name != e.Name {
		d.pairing.Name = e.Name
		u.renamed = true
	}
	return u
}

// removeDnssdEntry forgets entry of interface.
// Returns true if device is no longer advertised on any interface.
func (d *Device) removeDnssdEntry(e dnssd.BrowseEntry) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	old, ok := d.dnssdEntries[e.IfaceName]
	if !ok || old.Port != e.Port || old.Name != e.Name {
		// unknown or already replaced by entry with new port or name
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

// CurrentName returns name accessory is advertised with. It differs from Name
// if accessory was renamed. If device is not discovered, it is the last known name.
func (d *Device) CurrentName() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.currentNameLocked()
}

func (d *Device) currentNameLocked() string {
	if d.currentName != "" {
		return d.currentName
	}
	return d.Name
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
	if d.paired != paired {
		d.notifyStateChanged()
	}
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
// It fails if cc was closed meanwhile, e.g. device was lost during pair-verify.
func (d *Device) setVerified(cc *conn, ss *session) error {
	d.mu.Lock()
	if d.cc != cc || cc.isClosed() {
		d.mu.Unlock()
		return errConnClosed
	}
	d.ss = ss
	d.verified = true
	d.mu.Unlock()

	cc.UpgradeEnc(ss)
	d.startBackgroundRead(cc)
	return nil
}

// startBackgroundRead reads responses and events from cc
// until it is closed, then closes device connection.
func (d *Device) startBackgroundRead(cc *conn) {
	stopped := cc.startLoop()
	go func() {
		<-stopped
		reason := cc.loopError()
		log.Debug.Println("background read: loop stopped: ", reason)
		if reason == nil {
			reason = errors.New("stop background read")
		}
		d.closeConn(cc, reason)
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

// Accessories return copy of previously discovered accessories.
// GetAccessories should be called prior to this call.
// Values are updated by events of subscribed characteristics,
// call Accessories again to get them.
func (d *Device) Accessories() []*Accessory {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.accs == nil {
		return nil
	}
	res := make([]*Accessory, len(d.accs))
	for i, a := range d.accs {
		res[i] = a.clone()
	}
	return res
}

// setValue updates value of characteristic in accessories.
func (d *Device) setValue(aid uint64, iid uint64, val interface{}) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, aa := range d.accs {
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
}

// refreshAccessories loads accessories again after configuration change,
// if they were loaded before.
func (d *Device) refreshAccessories() {
	d.mu.Lock()
	loaded := d.accs != nil && d.verified
	d.mu.Unlock()
	if !loaded {
		return
	}
	log.Debug.Printf("device <%s>: configuration changed, loading accessories\n", d.Name)
	if err := d.GetAccessories(); err != nil {
		log.Debug.Printf("device <%s>: loading accessories failed: %v\n", d.Name, err)
		return
	}

	d.mu.Lock()
	if d.accsChanged != nil {
		close(d.accsChanged)
		d.accsChanged = nil
	}
	d.mu.Unlock()
}

// AccessoriesChanged returns channel that is closed when accessories are loaded again,
// because accessory reported configuration change, e.g. accessory was added to bridge.
// Call it again to wait for next change. To not miss change, call it before Accessories:
//
//	changed := d.AccessoriesChanged()
//	accs := d.Accessories()
//	<-changed
func (d *Device) AccessoriesChanged() <-chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.accsChanged == nil {
		d.accsChanged = make(chan struct{})
	}
	return d.accsChanged
}

// GetAccessories sends GET /accessories request and store
// result that can be retrieved with Accessories() method.
// Accessories are loaded again automatically when accessory reports configuration change.
// Events are enabled for new characteristics covered by subscriptions,
// e.g. SubscribeToAllEvents was called before accessory was added to bridge.
func (d *Device) GetAccessories() error {

	if !d.IsVerified() {
		return errors.New("paired device not verified or not connected")
	}
	cc := d.conn()

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
	if err := responseError(res, all); err != nil {
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
	if d.cc != cc {
		d.mu.Unlock()
		return errConnClosed
	}
	old := d.accs
	d.accs = accs.Accs
	d.mu.Unlock()

	if err := d.enableNewEvents(old, accs.Accs); err != nil {
		return fmt.Errorf("enabling events: %w", err)
	}
	return nil
}

// GetCharacteristic sends GET /characteristic request and return characteristic description and value.
func (d *Device) GetCharacteristic(aid uint64, cid uint64) (CharacteristicDescription, error) {
	res, err := d.GetCharacteristics(CharacteristicId{aid, cid})
	if err != nil {
		return CharacteristicDescription{}, err
	}
	return res[0], nil
}

// PutCharacteristic makes PUT /characteristic request to control characteristic value.
func (d *Device) PutCharacteristic(aid uint64, cid uint64, val interface{}) error {
	res, err := d.putCharacteristics(characteristicsPut{
		Cs: []CharacteristicPut{{Aid: aid, Iid: cid, Value: val}},
	})
	if err != nil {
		return err
	}
	return putResult(res)
}

// putResult returns error of PUT /characteristics response.
func putResult(res *http.Response) error {
	all, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}
	return responseError(res, all)
}

// responseError returns error of /accessories or /characteristics response.
// PUT succeeds with 204 No Content. When request fails for some characteristics,
// accessory lists status of every one with 207 Multi-Status,
// e.g. {"characteristics":[{"aid":1,"iid":12,"status":-70402}]},
// or reports status of whole request, e.g. {"status":-70401}.
func responseError(res *http.Response, body []byte) error {
	if res.StatusCode == http.StatusNoContent {
		return nil
	}

	var payload struct {
		Characteristics []CharacteristicDescription `json:"characteristics"`
		Status          *int                        `json:"status"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return fmt.Errorf("unexpected response %d: %q", res.StatusCode, body)
	}
	for _, c := range payload.Characteristics {
		if c.Status != nil && *c.Status != JsonStatusSuccess {
			return &CharacteristicError{Aid: c.Aid, Iid: c.Iid, Status: *c.Status}
		}
	}
	if payload.Status != nil && *payload.Status != JsonStatusSuccess {
		return fmt.Errorf("unexpected response %d: %s", res.StatusCode, jsonStatusMessage(*payload.Status))
	}
	if res.StatusCode != http.StatusMultiStatus && res.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected response %d", res.StatusCode)
	}
	return nil
}
