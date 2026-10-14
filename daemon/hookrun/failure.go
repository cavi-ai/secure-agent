package hookrun

import "errors"

// FailureCode is a bounded diagnostic, never a native error or payload. It also
// implements error so hosts can use errors.Is without parsing diagnostic text.
type FailureCode string

const (
	ErrInvalidInput        FailureCode = "invalid-input"
	ErrUnsupportedProtocol FailureCode = "unsupported-protocol"
	ErrScopeMismatch       FailureCode = "scope-mismatch"
	ErrDeliveryConflict    FailureCode = "delivery-conflict"
	ErrQueueFull           FailureCode = "queue-full"
	ErrRecorderUnavailable FailureCode = "recorder-unavailable"
	ErrRecorderFailed      FailureCode = "recorder-failed"
	ErrOutboxFailed        FailureCode = "outbox-failed"
	ErrOutboxFull          FailureCode = "outbox-full"
)

func (c FailureCode) Error() string { return "hook forwarding: " + string(c) }

// ErrorCode extracts a structured code through wrapped errors. Unclassified
// errors remain local; callers choose a safe code for their operation.
func ErrorCode(err error) FailureCode {
	var code FailureCode
	if errors.As(err, &code) && (captureCode(code) || deliveryCode(code) || storageCode(code)) {
		return code
	}
	return ""
}

func captureCode(code FailureCode) bool {
	switch code {
	case "", ErrInvalidInput, ErrUnsupportedProtocol, ErrScopeMismatch, ErrDeliveryConflict, ErrQueueFull:
		return true
	}
	return false
}

func deliveryCode(code FailureCode) bool {
	return code == "" || code == ErrRecorderUnavailable || code == ErrRecorderFailed
}

func storageCode(code FailureCode) bool {
	return code == "" || code == ErrOutboxFailed || code == ErrOutboxFull
}
