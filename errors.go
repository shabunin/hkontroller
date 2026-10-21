package hkontroller

import (
	"fmt"
	"time"
)

type PairVerifyError struct {
	Step string
	err  error
}

func (e *PairVerifyError) Unwrap() error {
	return e.err
}

func (e *PairVerifyError) Error() string {
	return fmt.Sprintf("pair-verify error on step %s: %v", e.Step, e.err)
}

type PairSetupError struct {
	Step string
	err  error
}

func (p *PairSetupError) Error() string {
	return fmt.Sprintf("pair-setup error on step %s: %v", p.Step, p.err)
}

func (p *PairSetupError) Unwrap() error {
	return p.err
}

type TlvError struct {
	Code    byte
	Message string
}

func (t *TlvError) Error() string {
	return fmt.Sprintf("tlv error %x: %s", t.Code, t.Message)
}

// Error codes for TLV8 communication.
var (
	TlvErrorUnknown        = TlvError{0x1, "unknown"}
	TlvErrorAuthentication = TlvError{0x2, "setup code or signature verification failed"}
	TlvErrorBackoff        = TlvError{0x3,
		"client must look at the retry delay TLV item and wait that many seconds before retrying"}
	TlvErrorMaxPeers    = TlvError{0x4, "server cannot accept any more pairings"}
	TlvErrorMaxTries    = TlvError{0x5, "server reached its maximum number of authentication attempts"}
	TlvErrorUnavailable = TlvError{0x6, "server pairing method is unavailable"}
	TlvErrorBusy        = TlvError{0x7, "server is busy and cannot accept a pairing request at this time"}

	tlvErrors = []TlvError{
		TlvErrorUnknown, TlvErrorAuthentication,
		TlvErrorBackoff, TlvErrorMaxPeers,
		TlvErrorMaxTries, TlvErrorUnavailable, TlvErrorBusy,
	}
)

// BackoffError is returned when accessory asks to wait before next pairing attempt.
// It wraps TlvErrorBackoff.
type BackoffError struct {
	RetryDelay time.Duration
}

func (e *BackoffError) Error() string {
	return fmt.Sprintf("%v, retry in %v", &TlvErrorBackoff, e.RetryDelay)
}

func (e *BackoffError) Unwrap() error {
	return &TlvErrorBackoff
}

// pairingError returns error reported in pairing response, or nil.
func pairingError(m pairSetupPayload) error {
	if m.Error == 0 {
		return nil
	}
	if m.Error == TlvErrorBackoff.Code {
		return &BackoffError{RetryDelay: time.Duration(m.RetryDelay) * time.Second}
	}
	return TlvErrorFromCode(m.Error)
}

func TlvErrorFromCode(code byte) error {
	for _, e := range tlvErrors {
		if e.Code == code {
			return &e
		}
	}
	return &TlvErrorUnknown
}

// CharacteristicError is returned when accessory rejects request to characteristic.
type CharacteristicError struct {
	Aid    uint64
	Iid    uint64
	Status int // one of JsonStatus* codes
}

func (e *CharacteristicError) Error() string {
	return fmt.Sprintf("characteristic %d.%d error %d: %s", e.Aid, e.Iid, e.Status, jsonStatusMessage(e.Status))
}

func jsonStatusMessage(status int) string {
	switch status {
	case JsonStatusInsufficientPrivileges:
		return "insufficient privileges"
	case JsonStatusServiceCommunicationFailure:
		return "unable to communicate with requested service"
	case JsonStatusResourceBusy:
		return "resource is busy, try again"
	case JsonStatusReadOnlyCharacteristic:
		return "cannot write to read only characteristic"
	case JsonStatusWriteOnlyCharacteristic:
		return "cannot read from write only characteristic"
	case JsonStatusNotificationNotSupported:
		return "notification is not supported for characteristic"
	case JsonStatusOutOfResource:
		return "out of resources to process request"
	case JsonStatusOperationTimedOut:
		return "operation timed out"
	case JsonStatusResourceDoesNotExist:
		return "resource does not exist"
	case JsonStatusInvalidValueInRequest:
		return "invalid value in request"
	case JsonStatusInsufficientAuthorization:
		return "insufficient authorization"
	}
	return "unknown"
}
