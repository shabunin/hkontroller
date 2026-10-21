package hkontroller

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/shabunin/dnssd"
	_ "github.com/shabunin/dnssd/log"
	"github.com/shabunin/hkontroller/log"
)

type pairSetupPayload struct {
	Method        byte   `tlv8:"0"`
	Identifier    string `tlv8:"1"`
	Salt          []byte `tlv8:"2"`
	PublicKey     []byte `tlv8:"3"`
	Proof         []byte `tlv8:"4"`
	EncryptedData []byte `tlv8:"5"`
	State         byte   `tlv8:"6"`
	Error         byte   `tlv8:"7"`
	RetryDelay    byte   `tlv8:"8"`
	Certificate   []byte `tlv8:"9"`
	Signature     []byte `tlv8:"10"`
	Permissions   byte   `tlv8:"11"`
	FragmentData  []byte `tlv8:"13"`
	FragmentLast  []byte `tlv8:"14"`
}

type Controller struct {
	name            string
	uuid            string
	mu              sync.Mutex
	cancelDiscovery context.CancelFunc
	devices         map[string]*Device

	st *storer

	localLTKP []byte
	localLTSK []byte
}

func NewController(store Store, name string) (*Controller, error) {

	st := storer{store}

	keypair, err := st.KeyPair()
	if err != nil {
		keypair, err = generateKeyPair()
		if err != nil {
			return nil, fmt.Errorf("generating keypair failed: %v", err)
		}
		if err := st.SaveKeyPair(keypair); err != nil {
			return nil, fmt.Errorf("saving keypair failed: %v", err)
		}
	}

	return &Controller{
		name:      name,
		mu:        sync.Mutex{},
		devices:   make(map[string]*Device),
		st:        &st,
		localLTKP: keypair.Public,
		localLTSK: keypair.Private,
	}, nil
}

func (c *Controller) putDevice(dd *Device) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.devices[dd.Name] = dd
}

// onPaired is called by device after successful /pair-setup.
func (c *Controller) onPaired(dd *Device) {
	p := dd.GetPairingInfo()
	log.Debug.Println("save pairing: ", p)
	if err := c.st.SavePairing(p); err != nil {
		log.Info.Println("save pairing failed: ", err)
	}
}

// onUnpaired is called by device after pairing was removed.
func (c *Controller) onUnpaired(dd *Device) {
	if err := c.st.DeletePairing(dd.GetPairingInfo().Id); err != nil {
		log.Info.Println("delete pairing failed: ", err)
	}
	dd.setPairing(Pairing{}, false)

	dd.close(errors.New("device unpaired"))

	// if not paired and not discovered,
	// then it should not present anymore
	if !dd.IsDiscovered() {
		c.mu.Lock()
		delete(c.devices, dd.Name)
		c.mu.Unlock()
	}
}

// onLost is called when device is no longer advertised via mdns.
func (c *Controller) onLost(dd *Device) {
	// if lost and not paired,
	// then it should not present anymore
	if !dd.IsPaired() {
		c.mu.Lock()
		delete(c.devices, dd.Name)
		c.mu.Unlock()
	}
}

// onDnssdAdd stores mdns entry. Returns device and true if device is newly discovered.
func (c *Controller) onDnssdAdd(e dnssd.BrowseEntry) (*Device, bool) {
	c.mu.Lock()
	dd, ok := c.devices[e.Name]
	if !ok {
		// not exist - init one
		dd = newDevice(e.Name, c, c.name, c.localLTKP, c.localLTSK)
		c.devices[e.Name] = dd
	}
	c.mu.Unlock()

	return dd, dd.addDnssdEntry(e)
}

// onDnssdRemove forgets mdns entry. Device is lost only when it is not
// advertised on any interface anymore, then it returns device and true.
func (c *Controller) onDnssdRemove(e dnssd.BrowseEntry) (*Device, bool) {
	dd := c.getDevice(e.Name)
	if dd == nil || !dd.removeDnssdEntry(e) {
		return dd, false
	}
	dd.close(errors.New("device lost from mdns"))
	c.onLost(dd)
	return dd, true
}

func (c *Controller) getDevice(id string) *Device {
	c.mu.Lock()
	defer c.mu.Unlock()
	dd, ok := c.devices[id]
	if !ok {
		return nil
	}
	return dd
}

// StartDiscoveryWithContext browses for HomeKit accessories until ctx is done
// or StopDiscovery is called. Devices are sent to the first channel when they
// are discovered and to the second one when they are lost.
// Discovery never waits for channels to be read, devices are queued in order.
// Both channels are closed when discovery stops, devices not yet read are dropped.
func (c *Controller) StartDiscoveryWithContext(ctx context.Context) (<-chan *Device, <-chan *Device) {

	discovered := newDeviceQueue()
	lost := newDeviceQueue()

	// entries come per network interface,
	// so device is sent to channels only when its state changes
	addFn := func(e dnssd.BrowseEntry) {
		if dd, ok := c.onDnssdAdd(e); ok {
			discovered.push(dd)
		}
	}

	rmvFn := func(e dnssd.BrowseEntry) {
		if dd, ok := c.onDnssdRemove(e); ok {
			lost.push(dd)
		}
	}

	// set before goroutine starts, so StopDiscovery works right after this call
	ctx, cancel := context.WithCancel(ctx)
	c.mu.Lock()
	c.cancelDiscovery = cancel
	c.mu.Unlock()

	stopped, stop := context.WithCancel(context.Background())
	discoverCh := discovered.forward(stopped)
	lostCh := lost.forward(stopped)

	go func() {
		defer stop()
		defer cancel()
		for {
			err := lookupType(ctx, "_hap._tcp.local.", addFn, rmvFn)
			if ctx.Err() != nil {
				return
			}
			// e.g. no network interfaces yet, don't spin
			log.Debug.Println("discovery error: ", err)
			select {
			case <-time.After(discoveryRetryDelay):
			case <-ctx.Done():
				return
			}
		}
	}()
	return discoverCh, lostCh
}

// deviceQueue passes devices to channel without blocking the sender.
type deviceQueue struct {
	mu     sync.Mutex
	items  []*Device
	notify chan struct{}
}

func newDeviceQueue() *deviceQueue {
	return &deviceQueue{notify: make(chan struct{}, 1)}
}

func (q *deviceQueue) push(d *Device) {
	q.mu.Lock()
	q.items = append(q.items, d)
	q.mu.Unlock()
	select {
	case q.notify <- struct{}{}:
	default:
	}
}

func (q *deviceQueue) pop() (*Device, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.items) == 0 {
		return nil, false
	}
	d := q.items[0]
	q.items[0] = nil
	q.items = q.items[1:]
	return d, true
}

// forward sends queued devices to returned channel in order,
// until ctx is done, then closes the channel.
func (q *deviceQueue) forward(ctx context.Context) <-chan *Device {
	out := make(chan *Device)
	go func() {
		defer close(out)
		for {
			d, ok := q.pop()
			if !ok {
				select {
				case <-q.notify:
					continue
				case <-ctx.Done():
					return
				}
			}
			select {
			case out <- d:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out
}

func (c *Controller) StartDiscovery() (<-chan *Device, <-chan *Device) {
	return c.StartDiscoveryWithContext(context.Background())
}

func (c *Controller) StopDiscovery() {
	c.mu.Lock()
	cancel := c.cancelDiscovery
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// GetAllDevices returns list of all devices loaded or discovered by controller.
func (c *Controller) GetAllDevices() []*Device {
	var result []*Device

	c.mu.Lock()
	defer c.mu.Unlock()
	for _, d := range c.devices {
		result = append(result, d)
	}

	return result
}

// GetPairedDevices returns list of devices that has been paired.
// Connected or not.
func (c *Controller) GetPairedDevices() []*Device {
	var result []*Device

	c.mu.Lock()
	defer c.mu.Unlock()
	for _, d := range c.devices {
		if d.IsPaired() {
			result = append(result, d)
		}
	}

	return result
}

// GetVerifiedDevices returns list of devices with established encrypted session.
func (c *Controller) GetVerifiedDevices() []*Device {
	var result []*Device

	c.mu.Lock()
	defer c.mu.Unlock()
	for _, d := range c.devices {
		if d.IsVerified() {
			result = append(result, d)
		}
	}

	return result
}

func (c *Controller) LoadPairings() error {

	pp := c.st.Pairings()
	for _, p := range pp {
		// pairings saved with older dnssd have escaped names, e.g. "My\ Bridge",
		// discovered names are unescaped now
		if name := strings.ReplaceAll(p.Name, `\`, ""); name != p.Name {
			p.Name = name
			if err := c.st.SavePairing(p); err != nil {
				log.Info.Println("save pairing failed: ", err)
			}
		}
		dd := newDevice(p.Name, c, c.name, c.localLTKP, c.localLTSK)
		dd.setPairing(p, true)

		c.putDevice(dd)
	}

	return nil
}

func (c *Controller) GetDevice(deviceName string) *Device {
	return c.getDevice(deviceName)
}

// lookupType is replaced in tests
var lookupType = dnssd.LookupType

// discoveryRetryDelay is a pause before lookup is restarted after error
var discoveryRetryDelay = time.Second
