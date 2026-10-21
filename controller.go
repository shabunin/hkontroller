package hkontroller

import (
	"context"
	"crypto/ed25519"
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
	RetryDelay    uint16 `tlv8:"8"` // seconds
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
	devices         map[string]*Device // by accessory id, see deviceKey

	// pairingsMu serializes saving and deleting of pairings,
	// so pairing deleted by unpair is not saved again after rename
	pairingsMu sync.Mutex

	st *storer

	localLTKP []byte
	localLTSK []byte
}

func NewController(store Store, name string) (*Controller, error) {

	st := storer{store}

	keypair, err := st.KeyPair()
	if err != nil {
		// new keypair would make all existing pairings useless,
		// so it is generated only when there is none
		exists, kerr := st.hasKey("keypair")
		if kerr != nil {
			return nil, fmt.Errorf("loading keypair failed: %v", kerr)
		}
		if exists {
			return nil, fmt.Errorf("loading keypair failed: %v", err)
		}
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

// namePrefix marks key of accessory that doesn't advertise its id.
const namePrefix = "name:"

// deviceKey identifies accessory by pairing id from txt record,
// since name may change, e.g. after rename or mdns name conflict.
func deviceKey(e dnssd.BrowseEntry) string {
	if id := e.Text["id"]; id != "" {
		return strings.ToUpper(id)
	}
	return namePrefix + e.Name
}

// findDevice returns device of mdns entry and its key. Must be called with c.mu held.
func (c *Controller) findDevice(e dnssd.BrowseEntry) (*Device, string) {
	key := deviceKey(e)
	if dd, ok := c.devices[key]; ok {
		return dd, key
	}
	if strings.HasPrefix(key, namePrefix) {
		// no id, so only name can tell
		for _, dd := range c.devices {
			if dd.Name == e.Name {
				return dd, dd.id
			}
		}
	}
	return nil, key
}

func (c *Controller) putDevice(dd *Device) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.devices[dd.id] = dd
}

func (c *Controller) deleteDevice(dd *Device) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.devices[dd.id] == dd {
		delete(c.devices, dd.id)
	}
}

// onPaired is called by device after successful /pair-setup.
func (c *Controller) onPaired(dd *Device) {
	c.savePairing(dd)
}

// savePairing saves pairing of device, if it is still paired.
func (c *Controller) savePairing(dd *Device) {
	c.pairingsMu.Lock()
	defer c.pairingsMu.Unlock()
	if !dd.IsPaired() {
		return
	}
	p := dd.GetPairingInfo()
	log.Debug.Println("save pairing: ", p)
	if err := c.st.SavePairing(p); err != nil {
		log.Info.Println("save pairing failed: ", err)
	}
}

// onUnpaired is called by device after pairing was removed.
func (c *Controller) onUnpaired(dd *Device) {
	c.pairingsMu.Lock()
	if err := c.st.DeletePairing(dd.GetPairingInfo().Id); err != nil {
		log.Info.Println("delete pairing failed: ", err)
	}
	dd.setPairing(Pairing{}, false)
	c.pairingsMu.Unlock()

	dd.close(errors.New("device unpaired"))

	// if not paired and not discovered,
	// then it should not present anymore
	if !dd.IsDiscovered() {
		c.deleteDevice(dd)
	}
}

// onLost is called when device is no longer advertised via mdns.
// Connection of paired device is kept, mdns may miss announcements
// while accessory is still reachable. If it is not, connection breaks by itself.
func (c *Controller) onLost(dd *Device) {
	// if lost and not paired,
	// then it should not present anymore
	if !dd.IsPaired() {
		dd.close(errors.New("device lost from mdns"))
		c.deleteDevice(dd)
	}
}

// onDnssdAdd stores mdns entry. Returns device and true if device is newly discovered.
func (c *Controller) onDnssdAdd(e dnssd.BrowseEntry) (*Device, bool) {
	c.mu.Lock()
	dd, key := c.findDevice(e)
	if dd == nil {
		// not exist - init one
		dd = newDevice(e.Name, c, c.name, c.localLTKP, c.localLTSK)
		dd.id = key
		c.devices[key] = dd
	}
	c.mu.Unlock()

	u := dd.addDnssdEntry(e)
	if u.renamed {
		// so device is loaded with new name next time
		c.savePairing(dd)
	}
	if u.configChanged {
		go dd.refreshAccessories()
	}
	return dd, u.first
}

// onDnssdRemove forgets mdns entry. Device is lost only when it is not
// advertised on any interface anymore, then it returns device and true.
func (c *Controller) onDnssdRemove(e dnssd.BrowseEntry) (*Device, bool) {
	c.mu.Lock()
	dd, _ := c.findDevice(e)
	c.mu.Unlock()
	if dd == nil || !dd.removeDnssdEntry(e) {
		return dd, false
	}
	c.onLost(dd)
	return dd, true
}

// getDevice returns device by name, current or the one it was created with.
// Same name may belong to several accessories, e.g. paired one is offline
// or was renamed, then the one advertised with this name now is preferred.
func (c *Controller) getDevice(name string) *Device {
	c.mu.Lock()
	defer c.mu.Unlock()
	var res *Device
	best := 0
	for _, dd := range c.devices {
		score := 0
		if dd.CurrentName() == name {
			score += 2
		} else if dd.Name != name {
			continue
		}
		if dd.IsDiscovered() {
			score++
		}
		if res == nil || score > best {
			res, best = dd, score
		}
	}
	return res
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
		dd.id = strings.ToUpper(p.Id)
		dd.setPairing(p, true)

		c.putDevice(dd)
	}

	return nil
}

// Id returns controller id, accessories know this controller by it.
func (c *Controller) Id() string {
	return c.name
}

// PublicKey returns long-term public key of controller.
func (c *Controller) PublicKey() []byte {
	return append([]byte(nil), c.localLTKP...)
}

// AddPairing adds pairing with accessory made by another controller.
// That controller is admin of accessory, it adds this one with PairAdd,
// giving Id and PublicKey of this controller, and passes GetPairingInfo
// of its device here. Pairing is saved and device is returned
// to be verified, e.g. with KeepConnected.
func (c *Controller) AddPairing(p Pairing) (*Device, error) {
	if p.Id == "" {
		return nil, errors.New("pairing has no accessory id")
	}
	if len(p.PublicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("accessory public key must be %d bytes, got %d", ed25519.PublicKeySize, len(p.PublicKey))
	}
	key := strings.ToUpper(p.Id)

	c.pairingsMu.Lock()
	defer c.pairingsMu.Unlock()
	c.mu.Lock()
	defer c.mu.Unlock()

	dd := c.devices[key]
	if dd != nil {
		if dd.IsPaired() {
			return nil, errors.New("device is paired already")
		}
		p.Name = dd.CurrentName()
	} else if p.Name == "" {
		p.Name = p.Id
	}
	if err := c.st.SavePairing(p); err != nil {
		return nil, fmt.Errorf("save pairing: %w", err)
	}
	if dd == nil {
		dd = newDevice(p.Name, c, c.name, c.localLTKP, c.localLTSK)
		dd.id = key
		c.devices[key] = dd
	}
	dd.setPairing(p, true)
	return dd, nil
}

// GetDevice returns device by name, see Device.CurrentName.
func (c *Controller) GetDevice(deviceName string) *Device {
	return c.getDevice(deviceName)
}

// lookupType is replaced in tests
var lookupType = dnssd.LookupType

// discoveryRetryDelay is a pause before lookup is restarted after error
var discoveryRetryDelay = time.Second
