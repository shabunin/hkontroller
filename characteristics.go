package hkontroller

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// CharacteristicId identifies characteristic of accessory.
type CharacteristicId struct {
	Aid uint64
	Iid uint64
}

// GetCharacteristics reads values of several characteristics in one request.
// Results are in order of ids. If accessory couldn't read some of them,
// results are returned anyway, failed ones have Status set,
// and error is *CharacteristicError of the first one.
func (d *Device) GetCharacteristics(ids ...CharacteristicId) ([]CharacteristicDescription, error) {
	if len(ids) == 0 {
		return nil, errors.New("no characteristics to read")
	}
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = fmt.Sprintf("%d.%d", id.Aid, id.Iid)
	}
	ep := "/characteristics?id=" + strings.Join(parts, ",")

	ctx, cancel := context.WithTimeout(context.Background(), reqTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", ep, nil)
	if err != nil {
		return nil, err
	}

	res, err := d.doRequest(req)
	if err != nil {
		return nil, err
	}

	all, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	statusErr := responseError(res, all)
	var chrsErr *CharacteristicError
	if statusErr != nil && !errors.As(statusErr, &chrsErr) {
		return nil, statusErr
	}

	var payload struct {
		Characteristics []CharacteristicDescription `json:"characteristics"`
	}
	if err := json.Unmarshal(all, &payload); err != nil {
		return nil, err
	}

	result := make([]CharacteristicDescription, len(ids))
	for i, id := range ids {
		found := false
		for _, c := range payload.Characteristics {
			if c.Aid == id.Aid && c.Iid == id.Iid {
				result[i] = c
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("no characteristic %d.%d in response", id.Aid, id.Iid)
		}
	}
	return result, statusErr
}

// PutCharacteristicWithResponse writes value and returns value accessory responded with.
// It is for characteristics with write response permission ("wr"), e.g. Setup Endpoints.
func (d *Device) PutCharacteristicWithResponse(aid uint64, iid uint64, val interface{}) (interface{}, error) {
	r := true
	res, err := d.putCharacteristics(characteristicsPut{
		Cs: []CharacteristicPut{{Aid: aid, Iid: iid, Value: val, Response: &r}},
	})
	if err != nil {
		return nil, err
	}

	all, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	if err := responseError(res, all); err != nil {
		return nil, err
	}
	if res.StatusCode == http.StatusNoContent {
		return nil, errors.New("no value in response")
	}

	var payload struct {
		Characteristics []CharacteristicDescription `json:"characteristics"`
	}
	if err := json.Unmarshal(all, &payload); err != nil {
		return nil, err
	}
	for _, c := range payload.Characteristics {
		if c.Aid == aid && c.Iid == iid {
			return c.Value, nil
		}
	}
	return nil, fmt.Errorf("no characteristic %d.%d in response", aid, iid)
}

// PutCharacteristicTimed writes value with timed write: accessory is told
// to expect write within ttl first, and rejects it if it comes later.
// It is required for characteristics with timed write permission ("tw"),
// e.g. lock or garage door target state.
func (d *Device) PutCharacteristicTimed(aid uint64, iid uint64, val interface{}, ttl time.Duration) error {
	if ttl <= 0 {
		return errors.New("ttl must be positive")
	}
	pid, err := prepareId()
	if err != nil {
		return err
	}
	if err := d.prepareWrite(pid, ttl); err != nil {
		return fmt.Errorf("prepare write: %w", err)
	}

	res, err := d.putCharacteristics(characteristicsPut{
		Cs:  []CharacteristicPut{{Aid: aid, Iid: iid, Value: val}},
		Pid: pid,
	})
	if err != nil {
		return err
	}
	return putResult(res)
}

// prepareWrite sends PUT /prepare request of timed write.
func (d *Device) prepareWrite(pid uint64, ttl time.Duration) error {
	b, err := json.Marshal(struct {
		Ttl int64  `json:"ttl"` // milliseconds
		Pid uint64 `json:"pid"`
	}{ttl.Milliseconds(), pid})
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), reqTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "PUT", "/prepare", bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", hapJsonContentType)
	res, err := d.doRequest(req)
	if err != nil {
		return err
	}
	all, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}
	return responseError(res, all)
}

// prepareId returns random id of timed write.
func prepareId() (uint64, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	// some accessories parse pid as js number, keep it in 53 bits
	return binary.LittleEndian.Uint64(b[:]) >> 11, nil
}

type characteristicsPut struct {
	Cs  []CharacteristicPut `json:"characteristics"`
	Pid uint64              `json:"pid,omitempty"`
}

// putCharacteristics sends PUT /characteristics request.
func (d *Device) putCharacteristics(pl characteristicsPut) (*http.Response, error) {
	b, err := json.Marshal(pl)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), reqTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "PUT", "/characteristics", bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", hapJsonContentType)
	return d.doRequest(req)
}

const hapJsonContentType = "application/hap+json"

// Identify asks accessory to identify itself, e.g. to blink or beep.
// Unpaired accessory is asked with POST /identify over new connection.
// Paired accessory refuses that, so true is written to Identify characteristic
// of primary accessory (aid 1) instead, then device has to be verified,
// accessories are loaded if they were not.
// To identify bridged accessory, write to its own Identify characteristic.
func (d *Device) Identify() error {
	if d.IsPaired() {
		return d.identifyPaired()
	}

	entries := d.entries()
	if len(entries) == 0 {
		return errors.New("device is not discovered")
	}

	ctx, cancel := context.WithTimeout(context.Background(), reqTimeout)
	defer cancel()

	nc, err := dialServiceInstance(ctx, entries, dialTimeout)
	if err != nil {
		return err
	}
	defer nc.Close()
	deadline, _ := ctx.Deadline()
	nc.SetDeadline(deadline)

	req, err := http.NewRequestWithContext(ctx, "POST", "/identify", nil)
	if err != nil {
		return err
	}
	if err := req.Write(nc); err != nil {
		return err
	}
	res, err := http.ReadResponse(bufio.NewReader(nc), req)
	if err != nil {
		return err
	}
	all, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}
	return responseError(res, all)
}

func (d *Device) identifyPaired() error {
	if !d.IsVerified() {
		return errors.New("paired device has to be verified to identify")
	}
	accs := d.Accessories()
	if accs == nil {
		if err := d.GetAccessories(); err != nil {
			return err
		}
		accs = d.Accessories()
	}
	for _, a := range accs {
		if a.Id != 1 {
			continue
		}
		if info := a.GetService(SType_AccessoryInfo); info != nil {
			if c := info.GetCharacteristic(CType_Identify); c != nil {
				return d.PutCharacteristic(a.Id, c.Iid, true)
			}
		}
	}
	return errors.New("no identify characteristic")
}
