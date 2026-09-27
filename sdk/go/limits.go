package orbit

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const maxSafeInteger int64 = 1<<53 - 1

// UsageCounter is the service's authoritative result for one usage period.
type UsageCounter struct {
	Name            string     `json:"name"`
	Period          string     `json:"period"`
	Limit           int64      `json:"limit"`
	Used            int64      `json:"used"`
	Remaining       int64      `json:"remaining"`
	PeriodStartedAt *time.Time `json:"period_started_at"`
	ResetsAt        *time.Time `json:"resets_at"`
}
type Consumption struct {
	UsageCounter
	OperationID   string `json:"idempotency_key"`
	ConsumedUnits int64  `json:"consumed_units"`
}
type ResourceCounter struct {
	Name      string `json:"name"`
	Limit     int64  `json:"limit"`
	Used      int64  `json:"used"`
	Remaining int64  `json:"remaining"`
}
type ResourceAllocation struct {
	ResourceCounter
	OperationID  string `json:"idempotency_key"`
	AllocationID string `json:"allocation_id"`
	ResourceID   string `json:"resource_id"`
	Units        int64  `json:"units"`
	State        string `json:"state"`
}

// MutationError retains the operation ID for deliberate recovery. Uncertain is
// true when no trustworthy outcome was received. Retry with this same ID and input.
// Capacity counters are present only on a validated capacity denial.
type MutationError struct {
	OperationID string
	Uncertain   bool
	Usage       *UsageCounter
	Resources   *ResourceCounter
	Cause       error
}

// Error describes the outcome without echoing the operation ID or server text.
func (e *MutationError) Error() string {
	switch {
	case e == nil:
		return "Orbit mutation failed"
	case e.Usage != nil:
		return "The usage limit is reached."
	case e.Resources != nil:
		return "The resource limit is reached."
	case e.Uncertain:
		return "The Orbit mutation outcome is uncertain. Retry with the same operation ID and input."
	case e.Cause != nil:
		return e.Cause.Error()
	default:
		return "Orbit mutation failed"
	}
}
func (e *MutationError) Unwrap() error             { return e.Cause }
func (e MutationError) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(e.Error())) }

func limitName(name string) bool { return validEntitlements(map[string]bool{name: true}) }
func safeUnits(units int64) bool { return units > 0 && units <= maxSafeInteger }
func exactFields(data []byte, names ...string) bool {
	if onlyFields(data, names...) != nil {
		return false
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil || len(fields) != len(names) {
		return false
	}
	for _, name := range names {
		if fields[name] == nil {
			return false
		}
	}
	return true
}
func requiredFields(data []byte, names ...string) bool {
	var fields map[string]json.RawMessage
	if decodeJSON(data, &fields) != nil {
		return false
	}
	for _, name := range names {
		if fields[name] == nil || string(fields[name]) == "null" {
			return false
		}
	}
	return true
}
func validCounter(name string, limit, used, remaining int64, expected string) bool {
	return name == expected && limitName(name) && limit >= 0 && limit <= maxSafeInteger && used >= 0 && used <= limit && remaining == limit-used
}
func parseUsage(data []byte, name string) (UsageCounter, error) {
	var value UsageCounter
	if decodeJSON(data, &value) != nil || !requiredFields(data, "name", "period", "limit", "used", "remaining") || !validCounter(value.Name, value.Limit, value.Used, value.Remaining, name) {
		return value, ErrInvalidResponse
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(data, &fields)
	if fields["period_started_at"] == nil || fields["resets_at"] == nil {
		return value, ErrInvalidResponse
	}
	switch value.Period {
	case "lifetime":
		if value.PeriodStartedAt != nil || value.ResetsAt != nil {
			return value, ErrInvalidResponse
		}
	case "day", "month":
		if value.PeriodStartedAt == nil || value.ResetsAt == nil || !value.ResetsAt.After(*value.PeriodStartedAt) || !validServiceTime(*value.PeriodStartedAt) || !validServiceTime(*value.ResetsAt) {
			return value, ErrInvalidResponse
		}
	default:
		return value, ErrInvalidResponse
	}
	return value, nil
}
func validServiceTime(t time.Time) bool {
	_, offset := t.Zone()
	return offset == 0 && t.Unix() >= 0 && t.Unix() <= downloadMaxTime
}
func parseResources(data []byte, name string) (ResourceCounter, error) {
	var value ResourceCounter
	if decodeJSON(data, &value) != nil || !requiredFields(data, "name", "limit", "used", "remaining") || !validCounter(value.Name, value.Limit, value.Used, value.Remaining, name) {
		return value, ErrInvalidResponse
	}
	return value, nil
}
func optionalOperationID(ids []string) (string, error) {
	if len(ids) > 1 || len(ids) == 1 && !validOperationID(ids[0]) {
		return "", ErrConfiguration
	}
	if len(ids) == 1 {
		return ids[0], nil
	}
	device, err := NewInstallation()
	if err != nil {
		return "", err
	}
	return device.InstallationID, nil
}

// onlineService authenticates directly with the current activation credential.
// It never starts a floating session or switches out of offline-file mode.
func (c *Client) onlineService(ctx context.Context, suffix string, extra map[string]any) (json.RawMessage, error) {
	ctx, stop := c.operationContext(ctx)
	defer stop()
	if ctx.Err() != nil {
		return nil, ErrCancelled
	}
	c.mu.Lock()
	if err := c.syncStorageLocked(); err != nil {
		c.mu.Unlock()
		return nil, err
	}
	if c.state.offline != nil && c.state.offline.authorized {
		c.mu.Unlock()
		return nil, &Error{Kind: Denied, Code: "online_required"}
	}
	saved := cloneCredential(c.state.credential)
	generation := c.state.generation
	if saved == nil {
		c.mu.Unlock()
		return nil, ErrNotActivated
	}
	body := c.sessionProof(saved)
	for key, value := range extra {
		body[key] = value
	}
	c.mu.Unlock()
	data, err := c.transport.Post(ctx, clientPrefix+"activations/"+saved.ActivationID+suffix, body, true)
	if fence := c.checkGeneration(generation); fence != nil {
		return nil, fence
	}
	if ctx.Err() != nil {
		return nil, ErrCancelled
	}
	return data, err
}
func serviceRoute(path string) bool {
	if !strings.HasPrefix(path, clientPrefix+"activations/") {
		return false
	}
	return strings.Contains(path, "/usage/") || strings.Contains(path, "/resources/") || strings.HasSuffix(path, "/updates") || strings.HasSuffix(path, "/downloads/authorize")
}
func mutationFailure(id string, err error) *MutationError {
	uncertain := true
	if failure, ok := err.(*Error); ok && (failure.Kind == Denied || failure.Kind == Configuration || failure.Kind == NotActivated) {
		uncertain = false
	}
	return &MutationError{OperationID: id, Uncertain: uncertain, Cause: err}
}
func capacityDenial(data []byte, name, id string, units int64, resource bool) *MutationError {
	var envelope struct {
		Error struct {
			Code      string          `json:"code"`
			Message   string          `json:"message"`
			RequestID string          `json:"request_id"`
			Counter   json.RawMessage `json:"counter"`
			ID        string          `json:"idempotency_key"`
			Units     int64           `json:"requested_units"`
		} `json:"error"`
	}
	if decodeJSON(data, &envelope) != nil {
		return mutationFailure(id, ErrInvalidResponse)
	}
	e := envelope.Error
	expected := "usage_limit_reached"
	if resource {
		expected = "resource_limit_reached"
	}
	if e.Code != expected || e.Message == "" || !validRequestID(e.RequestID) || e.ID != id || e.Units != units {
		return mutationFailure(id, ErrInvalidResponse)
	}
	result := &MutationError{OperationID: id, Cause: &Error{Kind: Denied, Code: e.Code, RequestID: e.RequestID}}
	if resource {
		value, err := parseResources(e.Counter, name)
		if err != nil {
			return mutationFailure(id, err)
		}
		if units <= value.Remaining {
			return mutationFailure(id, ErrInvalidResponse)
		}
		result.Resources = &value
	} else {
		value, err := parseUsage(e.Counter, name)
		if err != nil {
			return mutationFailure(id, err)
		}
		if units <= value.Remaining {
			return mutationFailure(id, ErrInvalidResponse)
		}
		result.Usage = &value
	}
	return result
}
func hasServiceError(data []byte) bool {
	var fields map[string]json.RawMessage
	return json.Unmarshal(data, &fields) == nil && fields["error"] != nil
}

func (c *Client) Usage(ctx context.Context, name string) (UsageCounter, error) {
	if !limitName(name) {
		return UsageCounter{}, ErrConfiguration
	}
	data, err := c.onlineService(ctx, "/usage/"+name, nil)
	if err != nil {
		return UsageCounter{}, err
	}
	return parseUsage(data, name)
}
func (c *Client) Consume(ctx context.Context, name string, units int64, operationID ...string) (Consumption, error) {
	id, err := optionalOperationID(operationID)
	if err != nil {
		return Consumption{}, err
	}
	if !limitName(name) || !safeUnits(units) {
		return Consumption{}, ErrConfiguration
	}
	data, err := c.onlineService(ctx, "/usage/"+name+"/consume", map[string]any{"units": units, "idempotency_key": id})
	if err != nil {
		return Consumption{}, mutationFailure(id, err)
	}
	if hasServiceError(data) {
		return Consumption{}, capacityDenial(data, name, id, units, false)
	}
	counter, err := parseUsage(data, name)
	var value Consumption
	if err != nil || decodeJSON(data, &value) != nil || value.OperationID != id || value.ConsumedUnits != units || counter.Used < units {
		return Consumption{}, mutationFailure(id, ErrInvalidResponse)
	}
	value.UsageCounter = counter
	return value, nil
}
func (c *Client) Resources(ctx context.Context, name string) (ResourceCounter, error) {
	if !limitName(name) {
		return ResourceCounter{}, ErrConfiguration
	}
	data, err := c.onlineService(ctx, "/resources/"+name, nil)
	if err != nil {
		return ResourceCounter{}, err
	}
	return parseResources(data, name)
}
func (c *Client) AcquireResource(ctx context.Context, name, resourceID string, units int64, operationID ...string) (ResourceAllocation, error) {
	id, err := optionalOperationID(operationID)
	if err != nil {
		return ResourceAllocation{}, err
	}
	if !limitName(name) || !opaque(resourceID) || !safeUnits(units) {
		return ResourceAllocation{}, ErrConfiguration
	}
	data, err := c.onlineService(ctx, "/resources/"+name+"/acquire", map[string]any{"resource_id": resourceID, "units": units, "idempotency_key": id})
	if err != nil {
		return ResourceAllocation{}, mutationFailure(id, err)
	}
	if hasServiceError(data) {
		return ResourceAllocation{}, capacityDenial(data, name, id, units, true)
	}
	return parseAllocation(data, name, resourceID, "", units, id, false)
}
func (c *Client) ReleaseResource(ctx context.Context, name, allocationID string, operationID ...string) (ResourceAllocation, error) {
	id, err := optionalOperationID(operationID)
	if err != nil {
		return ResourceAllocation{}, err
	}
	if !limitName(name) || !opaque(allocationID) {
		return ResourceAllocation{}, ErrConfiguration
	}
	data, err := c.onlineService(ctx, "/resources/"+name+"/allocations/"+allocationID+"/release", map[string]any{"idempotency_key": id})
	if err != nil {
		return ResourceAllocation{}, mutationFailure(id, err)
	}
	return parseAllocation(data, name, "", allocationID, 0, id, true)
}
func parseAllocation(data []byte, name, resourceID, allocationID string, units int64, id string, release bool) (ResourceAllocation, error) {
	counter, err := parseResources(data, name)
	var value ResourceAllocation
	if err != nil ||
		decodeJSON(data, &value) != nil ||
		value.OperationID != id ||
		!opaque(value.AllocationID) ||
		!opaque(value.ResourceID) ||
		!safeUnits(value.Units) ||
		resourceID != "" &&
			value.ResourceID != resourceID ||
		allocationID != "" &&
			value.AllocationID != allocationID ||
		units != 0 &&
			value.Units != units ||
		(value.State != "active" &&
			value.State != "released") ||
		value.State == "active" && value.Units > counter.Used ||
		release &&
			value.State != "released" {
		return ResourceAllocation{}, mutationFailure(id, ErrInvalidResponse)
	}
	value.ResourceCounter = counter
	return value, nil
}

// Limit definitions are display metadata, never evidence of remaining capacity.
type UsageLimit struct {
	Limit           int64   `json:"limit"`
	Period          string  `json:"period"`
	RequiredFeature *string `json:"required_feature"`
}
type ResourceLimit struct {
	Limit           int64   `json:"limit"`
	RequiredFeature *string `json:"required_feature"`
}

func (value *UsageLimit) UnmarshalJSON(data []byte) error {
	type plain UsageLimit
	var parsed plain
	if !exactFields(data, "limit", "period", "required_feature") ||
		!requiredFields(data, "limit", "period") ||
		decodeJSON(data, &parsed) != nil ||
		parsed.Limit < 0 ||
		parsed.Limit > maxSafeInteger ||
		(parsed.Period != "day" &&
			parsed.Period != "month" &&
			parsed.Period != "lifetime") ||
		parsed.RequiredFeature != nil &&
			!limitName(*parsed.RequiredFeature) {
		return ErrInvalidResponse
	}
	*value = UsageLimit(parsed)
	return nil
}
func (value *ResourceLimit) UnmarshalJSON(data []byte) error {
	type plain ResourceLimit
	var parsed plain
	if !exactFields(data, "limit", "required_feature") || !requiredFields(data, "limit") || decodeJSON(data, &parsed) != nil || parsed.Limit < 0 || parsed.Limit > maxSafeInteger || parsed.RequiredFeature != nil && !limitName(*parsed.RequiredFeature) {
		return ErrInvalidResponse
	}
	*value = ResourceLimit(parsed)
	return nil
}
