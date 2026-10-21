# command line HomeKit controller

```sh
go run ./examples
```

Flags:

- `-store ./.store` directory for controller keys and pairings
- `-name hkontrol` controller name, accessories use it as controller id
- `-debug` print debug log

It discovers accessories, connects to paired ones and reconnects when connection is lost.
Commands complete with Tab, history is under arrow keys, Ctrl-C or Ctrl-D quit.

```text
> help
  help                                     show commands
  devices                                  list devices
  use [no|name|id]                         select device, without argument unselect
  pair <pin>                               pair device, e.g. pair 031-45-154
  verify                                   establish encrypted session again
  unpair                                   remove pairing from accessory and forget it
  forget                                   forget pairing without asking accessory, e.g. after reset
  pairings                                 list controllers paired with accessory
  accessories                              load and show accessories
  identify                                 ask accessory to identify itself, e.g. blink
  get <aid> <iid> [<aid> <iid>...]         read characteristics
  put [-r | -t <ttl>] <aid> <iid> <value>  write characteristic: true, false, number or text;
                                           -r returns write response, -t is timed write, e.g. -t 2s
  watch <aid> <iid> | <aid> | all          subscribe to events
  unwatch <aid> <iid> | <aid> | all        unsubscribe from events
  quit                                     exit, Ctrl-C and Ctrl-D work too
```

## accessories to try

[Homebridge](https://homebridge.io) with
[homebridge-dummy](https://github.com/mpatfield/homebridge-dummy) plugin
makes accessories that don't control anything:

```sh
mkdir hb && cd hb
npm install homebridge homebridge-dummy
./node_modules/.bin/homebridge -U ./storage -P ./node_modules
```

`storage/config.json`:

```json
{
  "bridge": {
    "name": "Hk Fake Bridge",
    "username": "0E:AA:BB:CC:DD:05",
    "port": 51827,
    "pin": "031-45-154"
  },
  "platforms": [
    {
      "platform": "HomebridgeDummy",
      "accessories": [
        {
          "id": "blinker",
          "name": "Blinker",
          "type": "Switch",
          "schedule": { "type": "INTERVAL", "time": 5, "units": "SECONDS" },
          "autoReset": { "type": "TIMEOUT", "time": 2, "units": "SECONDS" }
        },
        { "id": "switch", "name": "Plain Switch", "type": "Switch" },
        { "id": "lamp", "name": "Lamp", "type": "Lightbulb", "isDimmer": true }
      ]
    }
  ]
}
```

Blinker turns on every 5 seconds and off after 2, so it sends events.
To pair the bridge again after its pairing was lost, delete `storage/persist`
and restart Homebridge.

## session

Select device by number from `devices`, by name or by id, then pair:

```text
> devices
  no  id                 discovered  paired  verified  name
  0   0E:AA:BB:CC:DD:05  yes         -       -         Hk Fake Bridge 391F
> use 0
Hk Fake Bridge 391F> pair 031-45-154
paired, connecting
Hk Fake Bridge 391F: connected
```

`accessories` shows accessory ids (`#2`) and characteristic ids (`10`):

```text
Hk Fake Bridge 391F> accessories
#2 Blinker
  ├─ AccessoryInfo
  │  ├─ 2   Identify = <nil>  [pw]
  │  ├─ 3   Manufacturer = Homebridge  [pr]
  │  ...
  └─ Switch
     ├─ 9   Name = Blinker  [pr]
     └─ 10  On = 0  [ev pr pw]
...
```

Read and write values, several at once too:

```text
Hk Fake Bridge 391F> put 4 11 37
4.11 = 37
Hk Fake Bridge 391F> get 4 10 4 11
4.10 = 0
4.11 = 37
```

Watch events. Watched events are subscribed again after reconnect:

```text
Hk Fake Bridge 391F> watch 2 10
watching
event Hk Fake Bridge 391F 2.10 = 1
event Hk Fake Bridge 391F 2.10 = 0
Hk Fake Bridge 391F> unwatch 2 10
stopped watching
```

Characteristics with `tw` permission, e.g. some locks, need timed write,
the ones with `wr` return a value when written:

```text
> put 2 11 5
put: characteristic 2.11 error -70410: invalid value in request
> put -t 2s 2 11 7
2.11 = 7
> put -r 2 12 hello
2.12 = hello, response: echo:hello
```

`unpair` removes pairing from accessory, `forget` only forgets it,
e.g. when accessory was reset.
