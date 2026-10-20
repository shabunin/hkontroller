package hkontroller

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/hkontrol/hkontroller/log"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/hkontrol/dnssd"
)

// closedChan is returned by Done when there is no connection.
var closedChan = func() chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}()

const dialTimeout = 5 * time.Second
const reqTimeout = 15 * time.Second

type Device struct {
	Name string

	ctrl *Controller

	dnssdBrowseEntry *dnssd.BrowseEntry

	controllerId   string
	controllerLTPK []byte
	controllerLTSK []byte

	pairing Pairing

	discovered bool // discovered mdns?
	paired     bool // completed /pair-setup?

	// mu guards connection state below
	mu          sync.Mutex
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
	cc *conn
	mu sync.Mutex
}

func newRoundTripper(cc *conn) *roundTripper {
	return &roundTripper{cc: cc}
}

// RoundTrip implementation to be able to use with http.Client
func (r *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {

	r.mu.Lock()
	defer r.mu.Unlock()

	// if background loop is running, response comes from it
	stopped := r.cc.loopStopped()
	var response chan responseResult
	if stopped != nil {
		response = make(chan responseResult, 1)
		r.cc.expectResponse(response)
		defer r.cc.expectResponse(nil)
	}

	err := req.Write(r.cc)
	if err != nil {
		return nil, err
	}

	if stopped != nil {
		select {
		case rr := <-response:
			return rr.res, rr.err
		case <-stopped:
			return nil, errors.New("connection closed")
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
	}

	rd := bufio.NewReader(r.cc)
	res, err := http.ReadResponse(rd, req)
	if err != nil {
		return nil, err
	}

	return res, nil
}

func newDevice(dnssdEntry *dnssd.BrowseEntry, name string, ctrl *Controller,
	controllerId string, controllerLTPK []byte, controllerLTSK []byte) *Device {

	d := &Device{
		dnssdBrowseEntry: dnssdEntry,
		Name:             name,
		ctrl:             ctrl,
		controllerId:     controllerId,
		controllerLTPK:   controllerLTPK,
		controllerLTSK:   controllerLTSK,
	}

	if dnssdEntry != nil {
		d.Name = dnssdEntry.Name
	}

	return d
}

func (d *Device) setDnssdEntry(e *dnssd.BrowseEntry) {
	d.dnssdBrowseEntry = e
	if e != nil {
		d.Name = e.Name
	}
}

func (d *Device) mergeDnssdEntry(e dnssd.BrowseEntry) {
	if d.dnssdBrowseEntry == nil {
		d.dnssdBrowseEntry = &e
		return
	}
	for _, ip := range e.IPs {
		d.dnssdBrowseEntry.IPs = append(d.dnssdBrowseEntry.IPs, ip)
	}
}

func (d *Device) GetDnssdEntry() dnssd.BrowseEntry {
	if d.dnssdBrowseEntry != nil {
		return *d.dnssdBrowseEntry
	}
	return dnssd.BrowseEntry{}
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
func (d *Device) doPost(url string, contentType string, body io.Reader) (*http.Response, error) {
	httpc, err := d.client()
	if err != nil {
		return nil, err
	}
	return httpc.Post(url, contentType, body)
}
func (d *Device) doGet(url string) (*http.Response, error) {
	httpc, err := d.client()
	if err != nil {
		return nil, err
	}
	return httpc.Get(url)
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

	if d.dnssdBrowseEntry == nil || !d.discovered {
		return errors.New("not discovered")
	}

	dial, err := dialServiceInstance(context.Background(), d.dnssdBrowseEntry, dialTimeout)
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
	return d.discovered
}

// IsPaired returns true if device is paired by this controller.
// If another client is paired with device it will return false.
func (d *Device) IsPaired() bool {
	return d.paired
}

func (d *Device) GetPairingInfo() Pairing {
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
