package hookrun

// ForwarderHealth separates independent observations. A connected source does
// not imply working delivery or persistence. Nil health means a legacy report;
// nil Outbox in version 2 means persistence was not enabled by this host.
type ForwarderHealth struct {
	SourceState   string        `json:"source_state"`
	CaptureError  FailureCode   `json:"capture_error,omitempty"`
	DeliveryError FailureCode   `json:"delivery_error,omitempty"`
	ReportError   bool          `json:"report_error"`
	Outbox        *OutboxHealth `json:"outbox,omitempty"`
}

type OutboxHealth struct {
	Persisted uint64      `json:"persisted"`
	Recovered uint64      `json:"recovered"`
	Error     FailureCode `json:"error,omitempty"`
}

// State preserves the aggregate state for consumers while retaining the
// evidence needed to distinguish source failures from forwarding failures.
func (h ForwarderHealth) State() string {
	if h.CaptureError != "" || h.DeliveryError != "" || h.Outbox != nil && h.Outbox.Error != "" {
		return "error"
	}
	return h.SourceState
}

func (h ForwarderHealth) valid(pending uint64) bool {
	if h.SourceState != "connected" && h.SourceState != "disconnected" && h.SourceState != "error" || !captureCode(h.CaptureError) || !deliveryCode(h.DeliveryError) {
		return false
	}
	return h.Outbox == nil || h.Outbox.Persisted <= pending && h.Outbox.Recovered <= 1<<53-1 && storageCode(h.Outbox.Error)
}
