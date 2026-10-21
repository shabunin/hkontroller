# hkontroller

HomeKit controller library in Go: discover HomeKit accessories on the local network,
pair with them, read and write characteristics and receive events,
like the Home app does.

It works with accessories over IP (Wi-Fi and Ethernet), e.g. Homebridge,
HAP-NodeJS, HomeKit bridges and devices.

```sh
go get github.com/shabunin/hkontroller
```

Requires Go 1.26 or newer.

## Example

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/shabunin/hkontroller"
)

func main() {
	// keys and pairings are kept in directory
	c, err := hkontroller.NewController(hkontroller.NewFsStore("./store"), "my-controller")
	if err != nil {
		log.Fatal(err)
	}
	_ = c.LoadPairings()

	discovered, _ := c.StartDiscovery()
	for d := range discovered {
		if d.Id() != "0E:AA:BB:CC:DD:05" {
			continue
		}
		if !d.IsPaired() {
			if err := d.PairSetup("031-45-154"); err != nil {
				log.Fatal(err)
			}
		}
		go d.KeepConnected(context.Background(), func() { onConnected(d) }, func(err error) {
			log.Println("connecting:", err)
		})
	}
}

// onConnected is called for every new connection,
// events have to be subscribed again after reconnect.
func onConnected(d *hkontroller.Device) {
	if err := d.GetAccessories(); err != nil {
		log.Println(err)
		return
	}
	for _, a := range d.Accessories() {
		for _, s := range a.Ss {
			for _, ch := range s.Cs {
				fmt.Printf("%d.%d %s = %v\n", a.Id, ch.Iid, ch.Type, ch.Value)
			}
		}
	}

	// turn on lamp: accessory 4, characteristic 10
	if err := d.PutCharacteristic(4, 10, true); err != nil {
		log.Println(err)
	}

	events, err := d.SubscribeToAllEvents()
	if err != nil {
		log.Println(err)
		return
	}
	go func() {
		// closed when connection is lost
		for ev := range events {
			fmt.Printf("event %d.%d = %v\n", ev.Aid, ev.Iid, ev.Value)
		}
	}()
}
```

[examples](examples) has a command line controller to try it with real accessories.

## What it does

**Discovery.** `StartDiscovery` browses `_hap._tcp` with mDNS and sends devices
to a channel when they appear and disappear. Devices are identified by accessory id,
so a renamed accessory keeps its pairing: `Name` is the name the device was created with,
`CurrentName` is the name it's advertised with now. When an accessory's configuration
number changes, its accessories are loaded again (`AccessoriesChanged` tells about it),
and events are enabled for new characteristics that are subscribed to.

**Pairing.**
- `PairSetup` pairs with setup code. A `BackoffError` tells how long to wait
  when the accessory asks to.
- `PairVerify` establishes encrypted session.
- `KeepConnected` does it for you and reconnects after the connection is lost.
- `Unpair` removes the pairing from the accessory. `ForgetPairing` forgets it locally,
  e.g. after factory reset.
- `PairAdd`, `PairRemove` and `ListPairings` manage other controllers.

Pairings and controller keys are kept in a `Store`: `NewFsStore` writes files to a directory,
`NewMemStore` keeps them in memory, or implement your own.

**Characteristics.**
- `GetAccessories` loads accessories, services and characteristics; `Accessories` returns them.
- `GetCharacteristic`, `GetCharacteristics` read one or several values in one request.
- `PutCharacteristic` writes value.
- `PutCharacteristicWithResponse` for characteristics with write response (`wr`).
- `PutCharacteristicTimed` for characteristics with timed write (`tw`), e.g. locks.
- `Identify` asks accessory to blink or beep.

Errors reported by accessory for a characteristic are `*CharacteristicError`
with HAP status code.

**Events.** `SubscribeToEvents`, `SubscribeToAccessoryEvents` and `SubscribeToAllEvents`
return channels of value updates. Several subscriptions may cover the same characteristic,
events are disabled on accessory when none needs them. A slow reader never blocks
the connection, its events are dropped instead. Channels are closed on `Unsubscribe`
or when connection is lost.

## Not supported

- Bluetooth LE and Thread accessories
- pairing with MFi authentication or software tokens, transient and split pairing
- cameras and HomeKit Secure Video streams
- setup payloads (`X-HM://` codes), setup code has to be entered

## Logging

Debug log is off by default:

```go
import "github.com/shabunin/hkontroller/log"

log.Debug.Enable()
```

## Credits

Derived from [`github.com/brutella/hap`](https://github.com/brutella/hap),
library to create HomeKit accessories.

## License

[Apache License 2.0](LICENSE)
