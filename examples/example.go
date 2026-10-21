// Command example is interactive HomeKit controller.
//
//	go run ./examples [-store dir] [-name controller] [-debug]
//
// Type help for commands. Tab completes command names, arrows edit line and browse history,
// Ctrl-C or Ctrl-D quits. Keys and pairings are stored in ./.store by default.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shabunin/hkontroller"
	"github.com/shabunin/hkontroller/log"
	"golang.org/x/term"
)

type command struct {
	name  string
	args  string
	help  string
	needs bool // needs selected device
	run   func(args []string) error
}

type cli struct {
	c        *hkontroller.Controller
	out      io.Writer      // terminal keeps prompt and typed line when events are printed
	term     *term.Terminal // nil if stdin is not a terminal
	restore  func()
	commands []command

	mu         sync.Mutex
	device     *hkontroller.Device
	listed     []*hkontroller.Device // last devices listing, for use <no>
	connecting map[*hkontroller.Device]bool
	watches    map[*hkontroller.Device][]watch // subscribed again after reconnect
}

// watch is characteristic, accessory or all of them, any is -1.
type watch struct {
	aid, iid int64
}

// within tells if w is part of scope, like subscriptions closed by Unsubscribe* methods.
func (w watch) within(scope watch) bool {
	return (scope.aid == -1 || scope.aid == w.aid) && (scope.iid == -1 || scope.iid == w.iid)
}

func main() {
	store := flag.String("store", "./.store", "directory for keys and pairings")
	name := flag.String("name", "hkontrol", "controller name, used as controller id by accessories")
	debug := flag.Bool("debug", false, "print debug log")
	flag.Parse()

	c, err := hkontroller.NewController(hkontroller.NewFsStore(*store), *name)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	l := &cli{c: c, out: os.Stdout, restore: func() {}, connecting: make(map[*hkontroller.Device]bool),
		watches: make(map[*hkontroller.Device][]watch)}
	l.initCommands()

	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		state, err := term.MakeRaw(fd)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		l.restore = func() { _ = term.Restore(fd, state) }
		l.term = term.NewTerminal(struct {
			io.Reader
			io.Writer
		}{os.Stdin, os.Stdout}, "> ")
		l.term.AutoCompleteCallback = l.complete
		l.out = l.term
		watchSize(fd, l.term)
	}

	log.Info.SetOutput(l.out)
	if *debug {
		log.Debug.SetOutput(l.out)
	}

	_ = c.LoadPairings()
	// paired devices are connected when discovered
	for _, d := range c.GetPairedDevices() {
		go l.keepConnected(d)
	}
	l.discover()
	l.printf("type help for commands\n")
	l.run()
}

func (l *cli) printf(format string, args ...interface{}) {
	fmt.Fprintf(l.out, format, args...)
}

func (l *cli) quit() {
	for _, d := range l.c.GetVerifiedDevices() {
		d.Close()
	}
	l.restore()
	os.Exit(0)
}

func (l *cli) readLine() (string, error) {
	if l.term != nil {
		line, err := l.term.ReadLine()
		if errors.Is(err, term.ErrPasteIndicator) {
			err = nil
		}
		return line, err
	}
	return stdinLine()
}

var stdin = bufio.NewReader(os.Stdin)

func stdinLine() (string, error) {
	line, err := stdin.ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func (l *cli) run() {
	for {
		line, err := l.readLine()
		if err != nil {
			// Ctrl-C, Ctrl-D or stdin is closed
			l.quit()
		}
		args := strings.Fields(line)
		if len(args) == 0 {
			continue
		}
		cmd := l.find(args[0])
		if cmd == nil {
			l.printf("unknown command %q, type help\n", args[0])
			continue
		}
		if cmd.needs && l.selected() == nil {
			l.printf("select device first: use <no>\n")
			continue
		}
		if err := cmd.run(args[1:]); err != nil {
			l.printf("%s: %v\n", cmd.name, err)
		}
	}
}

func (l *cli) find(name string) *command {
	for i := range l.commands {
		if l.commands[i].name == name {
			return &l.commands[i]
		}
	}
	return nil
}

// complete completes command name on Tab.
func (l *cli) complete(line string, pos int, key rune) (string, int, bool) {
	if key != '\t' || strings.Contains(line[:pos], " ") {
		return "", 0, false
	}
	var matches []string
	for _, c := range l.commands {
		if strings.HasPrefix(c.name, line[:pos]) {
			matches = append(matches, c.name)
		}
	}
	if len(matches) == 0 {
		return "", 0, false
	}
	if len(matches) == 1 {
		return matches[0] + " ", len(matches[0]) + 1, true
	}
	prefix := matches[0]
	for _, m := range matches[1:] {
		for !strings.HasPrefix(m, prefix) {
			prefix = prefix[:len(prefix)-1]
		}
	}
	return prefix, len(prefix), true
}

func (l *cli) selected() *hkontroller.Device {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.device
}

func (l *cli) selectDevice(d *hkontroller.Device) {
	l.mu.Lock()
	l.device = d
	l.mu.Unlock()
	if l.term == nil {
		return
	}
	if d == nil {
		l.term.SetPrompt("> ")
	} else {
		l.term.SetPrompt(d.CurrentName() + "> ")
	}
}

// discover prints discovered and lost devices.
func (l *cli) discover() {
	discoverCh, lostCh := l.c.StartDiscovery()
	go func() {
		for d := range discoverCh {
			l.printf("discovered: %s %s\n", d.CurrentName(), d.Id())
		}
	}()
	go func() {
		for d := range lostCh {
			l.printf("lost: %s\n", d.CurrentName())
		}
	}()
}

// keepConnected runs reconnect loop of the library while device is paired.
// There is one loop per device.
func (l *cli) keepConnected(d *hkontroller.Device) {
	l.mu.Lock()
	if l.connecting[d] {
		l.mu.Unlock()
		return
	}
	l.connecting[d] = true
	l.mu.Unlock()
	defer func() {
		l.mu.Lock()
		delete(l.connecting, d)
		delete(l.watches, d)
		l.mu.Unlock()
	}()

	d.KeepConnected(context.Background(), func() {
		l.printf("%s: connected\n", d.CurrentName())
		done := d.Done()
		go l.watchChanges(d, done)
		go func() {
			<-done
			if d.IsPaired() {
				l.printf("%s: connection closed: %v\n", d.CurrentName(), d.CloseReason())
			}
		}()
		l.rewatch(d)
	}, func(err error) {
		l.printf("%s: pair-verify: %v\n", d.CurrentName(), err)
	})
}

// rewatch subscribes again to events watched before reconnect.
func (l *cli) rewatch(d *hkontroller.Device) {
	l.mu.Lock()
	ww := append([]watch(nil), l.watches[d]...)
	l.mu.Unlock()
	if len(ww) == 0 {
		return
	}
	if err := d.GetAccessories(); err != nil {
		l.printf("%s: loading accessories: %v\n", d.CurrentName(), err)
		return
	}
	for _, w := range ww {
		if err := l.subscribe(d, w); err != nil {
			l.printf("%s: watch again: %v\n", d.CurrentName(), err)
		}
	}
}

// watchChanges tells when accessories are changed, until connection is closed.
func (l *cli) watchChanges(d *hkontroller.Device, done <-chan struct{}) {
	for {
		select {
		case <-d.AccessoriesChanged():
			l.printf("%s: accessories changed, %d now\n", d.CurrentName(), len(d.Accessories()))
		case <-done:
			return
		}
	}
}

func (l *cli) initCommands() {
	l.commands = []command{
		{"help", "", "show commands", false, l.cmdHelp},
		{"devices", "", "list devices", false, l.cmdDevices},
		{"use", "[no|name|id]", "select device, without argument unselect", false, l.cmdUse},
		{"pair", "<pin>", "pair device, e.g. pair 031-45-154", true, l.cmdPair},
		{"verify", "", "establish encrypted session again", true, l.cmdVerify},
		{"unpair", "", "remove pairing from accessory and forget it", true, l.cmdUnpair},
		{"forget", "", "forget pairing without asking accessory, e.g. after reset", true, l.cmdForget},
		{"pairings", "", "list controllers paired with accessory", true, l.cmdPairings},
		{"accessories", "", "load and show accessories", true, l.cmdAccessories},
		{"identify", "", "ask accessory to identify itself, e.g. blink", true, l.cmdIdentify},
		{"get", "<aid> <iid> [<aid> <iid>...]", "read characteristics", true, l.cmdGet},
		{"put", "[-r | -t <ttl>] <aid> <iid> <value>",
			"write characteristic: true, false, number or text;\n" +
				"-r returns write response, -t is timed write, e.g. -t 2s", true, l.cmdPut},
		{"watch", "<aid> <iid> | <aid> | all", "subscribe to events", true, l.cmdWatch},
		{"unwatch", "<aid> <iid> | <aid> | all", "unsubscribe from events", true, l.cmdUnwatch},
		{"quit", "", "exit, Ctrl-C and Ctrl-D work too", false, func([]string) error { l.quit(); return nil }},
	}
}

func (l *cli) cmdHelp([]string) error {
	for _, c := range l.commands {
		usage := c.name
		if c.args != "" {
			usage += " " + c.args
		}
		for i, line := range strings.Split(c.help, "\n") {
			if i > 0 {
				usage = ""
			}
			l.printf("  %-40s %s\n", usage, line)
		}
	}
	return nil
}

func status(ok bool, s string) string {
	if ok {
		return s
	}
	return "-"
}

func (l *cli) cmdDevices([]string) error {
	devices := l.c.GetAllDevices()
	sort.Slice(devices, func(i, j int) bool { return devices[i].CurrentName() < devices[j].CurrentName() })
	l.mu.Lock()
	l.listed = devices
	l.mu.Unlock()

	if len(devices) == 0 {
		l.printf("no devices yet\n")
		return nil
	}
	l.printf("%-3s %-18s %-11s %-7s %-9s %s\n", "no", "id", "discovered", "paired", "verified", "name")
	for i, d := range devices {
		l.printf("%-3d %-18s %-11s %-7s %-9s %s\n", i, d.Id(),
			status(d.IsDiscovered(), "yes"), status(d.IsPaired(), "yes"), status(d.IsVerified(), "yes"), d.CurrentName())
	}
	return nil
}

func (l *cli) cmdUse(args []string) error {
	if len(args) == 0 {
		l.selectDevice(nil)
		return nil
	}
	arg := strings.Join(args, " ")

	l.mu.Lock()
	listed := l.listed
	l.mu.Unlock()
	if i, err := strconv.Atoi(arg); err == nil {
		if i < 0 || i >= len(listed) {
			return fmt.Errorf("no device %d, see devices", i)
		}
		l.selectDevice(listed[i])
		return nil
	}
	if d := l.c.GetDevice(arg); d != nil {
		l.selectDevice(d)
		return nil
	}
	for _, d := range l.c.GetAllDevices() {
		if strings.EqualFold(d.Id(), arg) {
			l.selectDevice(d)
			return nil
		}
	}
	return fmt.Errorf("no device %q, see devices", arg)
}

func (l *cli) cmdPair(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: pair <pin>")
	}
	d := l.selected()
	if err := d.PairSetup(args[0]); err != nil {
		return err
	}
	l.printf("paired, connecting\n")
	go l.keepConnected(d)
	return nil
}

func (l *cli) cmdVerify([]string) error {
	d := l.selected()
	if err := d.PairVerify(); err != nil {
		return err
	}
	// it tells when connected
	go l.keepConnected(d)
	return nil
}

func (l *cli) cmdUnpair([]string) error {
	if err := l.selected().Unpair(); err != nil {
		return fmt.Errorf("%w, pairing is kept, use forget if accessory was reset", err)
	}
	l.printf("unpaired\n")
	return nil
}

func (l *cli) cmdForget([]string) error {
	l.selected().ForgetPairing()
	l.printf("pairing forgotten, accessory was not asked\n")
	return nil
}

func (l *cli) cmdPairings([]string) error {
	pp, err := l.selected().ListPairings()
	if err != nil {
		return err
	}
	for _, p := range pp {
		perm := "user"
		if p.Permission == hkontroller.PermissionAdmin {
			perm = "admin"
		}
		l.printf("  %-40s %-6s %x\n", p.Id, perm, p.PublicKey)
	}
	return nil
}

func (l *cli) cmdAccessories([]string) error {
	d := l.selected()
	if err := d.GetAccessories(); err != nil {
		return err
	}
	for _, a := range d.Accessories() {
		name := ""
		if info := a.GetService(hkontroller.SType_AccessoryInfo); info != nil {
			if c := info.GetCharacteristic(hkontroller.CType_Name); c != nil {
				name = fmt.Sprint(c.Value)
			}
		}
		l.printf("\n#%d %s\n", a.Id, name)
		for i, s := range a.Ss {
			branch, indent := "├─", "│  "
			if i == len(a.Ss)-1 {
				branch, indent = "└─", "   "
			}
			l.printf("  %s %s\n", branch, s.Type)
			for j, c := range s.Cs {
				cbranch := "├─"
				if j == len(s.Cs)-1 {
					cbranch = "└─"
				}
				l.printf("  %s%s %-3d %s = %v  [%s]\n", indent, cbranch, c.Iid, c.Type, c.Value,
					strings.Join(c.Permissions, " "))
			}
		}
	}
	l.printf("\n")
	return nil
}

func parseIds(args []string) (uint64, uint64, error) {
	if len(args) < 2 {
		return 0, 0, errors.New("aid and iid expected")
	}
	aid, err := strconv.ParseUint(args[0], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("aid: %w", err)
	}
	iid, err := strconv.ParseUint(args[1], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("iid: %w", err)
	}
	return aid, iid, nil
}

func (l *cli) cmdIdentify([]string) error {
	if err := l.selected().Identify(); err != nil {
		return err
	}
	l.printf("identify sent\n")
	return nil
}

func (l *cli) cmdGet(args []string) error {
	if len(args) == 0 || len(args)%2 != 0 {
		return errors.New("usage: get <aid> <iid> [<aid> <iid>...]")
	}
	var ids []hkontroller.CharacteristicId
	for i := 0; i < len(args); i += 2 {
		aid, iid, err := parseIds(args[i:])
		if err != nil {
			return err
		}
		ids = append(ids, hkontroller.CharacteristicId{Aid: aid, Iid: iid})
	}
	res, err := l.selected().GetCharacteristics(ids...)
	var cerr *hkontroller.CharacteristicError
	if err != nil && !errors.As(err, &cerr) {
		return err
	}
	for _, c := range res {
		if c.Status != nil && *c.Status != hkontroller.JsonStatusSuccess {
			l.printf("%d.%d: %v\n", c.Aid, c.Iid, &hkontroller.CharacteristicError{Aid: c.Aid, Iid: c.Iid, Status: *c.Status})
			continue
		}
		l.printf("%d.%d = %v\n", c.Aid, c.Iid, c.Value)
	}
	return nil
}

// parseValue makes bool, number or text of value.
// Older form with type, e.g. "number 42" or "bool true", works too.
func parseValue(args []string) interface{} {
	if len(args) == 2 && (args[0] == "number" || args[0] == "bool") {
		args = args[1:]
	}
	s := strings.Join(args, " ")
	switch s {
	case "true", "on":
		return true
	case "false", "off":
		return false
	}
	if n, err := strconv.ParseFloat(s, 64); err == nil {
		return n
	}
	return s
}

func (l *cli) cmdPut(args []string) error {
	usage := errors.New("usage: put [-r | -t <ttl>] <aid> <iid> <value>")
	withResponse := false
	var ttl time.Duration
	switch {
	case len(args) > 0 && args[0] == "-r":
		withResponse = true
		args = args[1:]
	case len(args) > 1 && args[0] == "-t":
		var err error
		if ttl, err = time.ParseDuration(args[1]); err != nil || ttl <= 0 {
			return fmt.Errorf("ttl: %q, e.g. 2s or 500ms", args[1])
		}
		args = args[2:]
	}
	aid, iid, err := parseIds(args)
	if err != nil || len(args) < 3 {
		return usage
	}
	value := parseValue(args[2:])
	d := l.selected()
	switch {
	case withResponse:
		res, err := d.PutCharacteristicWithResponse(aid, iid, value)
		if err != nil {
			return err
		}
		l.printf("%d.%d = %v, response: %v\n", aid, iid, value, res)
		return nil
	case ttl > 0:
		err = d.PutCharacteristicTimed(aid, iid, value, ttl)
	default:
		err = d.PutCharacteristic(aid, iid, value)
	}
	if err != nil {
		return err
	}
	l.printf("%d.%d = %v\n", aid, iid, value)
	return nil
}

// parseWatch parses <aid> <iid> | <aid> | all.
func parseWatch(args []string) (watch, error) {
	switch {
	case len(args) == 1 && args[0] == "all":
		return watch{-1, -1}, nil
	case len(args) == 1:
		aid, err := strconv.ParseUint(args[0], 10, 64)
		if err != nil {
			return watch{}, fmt.Errorf("aid: %w", err)
		}
		return watch{int64(aid), -1}, nil
	default:
		aid, iid, err := parseIds(args)
		return watch{int64(aid), int64(iid)}, err
	}
}

// subscribe prints events of w until channel is closed.
func (l *cli) subscribe(d *hkontroller.Device, w watch) error {
	var ch <-chan hkontroller.CharacteristicUpdate
	var err error
	switch {
	case w.aid == -1:
		ch, err = d.SubscribeToAllEvents()
	case w.iid == -1:
		ch, err = d.SubscribeToAccessoryEvents(uint64(w.aid))
	default:
		ch, err = d.SubscribeToEvents(uint64(w.aid), uint64(w.iid))
	}
	if err != nil {
		return err
	}
	go func() {
		for ev := range ch {
			l.printf("event %s %d.%d = %v\n", d.CurrentName(), ev.Aid, ev.Iid, ev.Value)
		}
	}()
	return nil
}

func (l *cli) cmdWatch(args []string) error {
	w, err := parseWatch(args)
	if err != nil {
		return err
	}
	d := l.selected()
	if err := l.subscribe(d, w); err != nil {
		return err
	}
	l.mu.Lock()
	l.watches[d] = append(l.watches[d], w)
	l.mu.Unlock()
	l.printf("watching\n")
	return nil
}

func (l *cli) cmdUnwatch(args []string) error {
	w, err := parseWatch(args)
	if err != nil {
		return err
	}
	d := l.selected()
	switch {
	case w.aid == -1:
		err = d.UnsubscribeFromAllEvents()
	case w.iid == -1:
		err = d.UnsubscribeFromAccessoryEvents(uint64(w.aid))
	default:
		err = d.UnsubscribeFromEvents(uint64(w.aid), uint64(w.iid))
	}
	if err != nil {
		return err
	}
	l.mu.Lock()
	var kept []watch
	for _, ww := range l.watches[d] {
		if !ww.within(w) {
			kept = append(kept, ww)
		}
	}
	l.watches[d] = kept
	l.mu.Unlock()
	l.printf("stopped watching\n")
	return nil
}
