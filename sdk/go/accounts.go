package orbit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// Customer and Account contain display metadata; login grants no feature access.
type Customer struct {
	ID        string `json:"id"`
	Username  string `json:"username"`
	Email     string `json:"email"`
	Suspended bool   `json:"suspended"`
	CreatedAt string `json:"created_at"`
}
type Account struct {
	Customer  Customer
	ExpiresAt string
}

// CustomerSessionProof holds sensitive login proof only in memory. Possession
// establishes neither current session validity nor licensed access.
type CustomerSessionProof struct {
	token string
}

// AuthorizationHeader returns the sensitive Bearer authorization header value.
// Send it only to your own trusted HTTPS backend, which must verify the session
// online with Orbit. Never log or persist it, send it to arbitrary URLs, or
// forward it through redirects. This proof grants no licensed access.
func (p CustomerSessionProof) AuthorizationHeader() string {
	return "Bearer " + p.token
}

func (CustomerSessionProof) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("[Orbit customer session proof redacted]"))
}
func (CustomerSessionProof) MarshalJSON() ([]byte, error) { return nil, ErrConfiguration }

type accountSession struct {
	token   string
	account Account
}
type loginReply struct {
	Customer  Customer `json:"customer"`
	Session   string   `json:"session"`
	ExpiresAt string   `json:"expires_at"`
}

type OwnedLicence struct {
	ID              string          `json:"id"`
	PolicyName      string          `json:"policy_name"`
	State           string          `json:"state"`
	ExpiryMode      string          `json:"expiry_mode"`
	FirstUsedAt     *string         `json:"first_used_at"`
	ExpiresAt       *string         `json:"expires_at"`
	DurationSeconds *int64          `json:"duration_seconds"`
	DeviceLimit     int32           `json:"device_limit"`
	HWIDLocked      bool            `json:"hwid_locked"`
	OfflineAllowed  bool            `json:"offline_allowed"`
	OfflineSeconds  int32           `json:"offline_seconds"`
	Entitlements    map[string]bool `json:"entitlements"`
}
type OwnedLicences struct {
	Items      []OwnedLicence `json:"items"`
	NextCursor *string        `json:"next_cursor"`
}

// Registration is sent once and never retained by the client. Avoid logging it.
type Registration struct {
	LicenceKey string
	Username   string
	Email      string
	Password   string
}

func (Registration) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("[Orbit registration redacted]"))
}
func (Registration) MarshalJSON() ([]byte, error) { return nil, ErrConfiguration }

// PendingRegistration keeps the scoped resend proof private in memory.
type PendingRegistration struct {
	Accepted         bool
	ExpiresAt        string
	resendCredential string
	applicationID    string
	environmentID    string
}

func (PendingRegistration) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("[Orbit pending registration redacted]"))
}

type registrationReply struct {
	Accepted         bool   `json:"accepted"`
	ExpiresAt        string `json:"expires_at"`
	ResendCredential string `json:"resend_credential"`
}
type acceptedReply struct {
	Accepted bool `json:"accepted"`
}

func (c *Client) Account() (*Account, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.syncStorageLocked(); err != nil {
		return nil, err
	}
	if c.state.account == nil {
		return nil, nil
	}
	copied := c.state.account.account
	return &copied, nil
}

// CustomerSessionProof copies locally held login proof after synchronizing
// storage invalidation. It does not establish online validity or licensed access.
func (c *Client) CustomerSessionProof() (*CustomerSessionProof, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.syncStorageLocked(); err != nil {
		return nil, err
	}
	if c.state.account == nil {
		return nil, ErrReauthenticationRequired
	}
	return &CustomerSessionProof{token: strings.Clone(c.state.account.token)}, nil
}

func (c *Client) Login(ctx context.Context, username, password string) (Account, error) {
	if username == "" || len(username) > 128 || len(password) > 256 || !utf8.ValidString(password) {
		return Account{}, ErrConfiguration
	}
	generation, err := c.generation()
	if err != nil {
		return Account{}, err
	}
	if err := c.lockOperation(ctx, generation); err != nil {
		return Account{}, err
	}
	defer c.unlockOperation()
	c.mu.Lock()
	if err := c.syncStorageLocked(); err != nil {
		c.mu.Unlock()
		return Account{}, err
	}
	if c.state.generation != generation {
		c.mu.Unlock()
		return Account{}, ErrStaleResponse
	}
	clearState(&c.state)
	if err := c.invalidateLocked(); err != nil {
		c.mu.Unlock()
		return Account{}, err
	}
	generation = c.state.generation
	c.mu.Unlock()
	data, err := c.transport.Post(ctx, clientPrefix+"sessions", c.scopeBody(map[string]any{"username": username, "password": password}), false)
	var reply loginReply
	if err == nil {
		err = decodeJSON(data, &reply)
	}
	if err == nil {
		err = checkLogin(reply)
	}
	if err := c.finishAccount(ctx, generation, err); err != nil {
		return Account{}, err
	}
	account := Account{Customer: reply.Customer, ExpiresAt: reply.ExpiresAt}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.syncStorageLocked(); err != nil {
		return Account{}, err
	}
	if c.state.generation != generation {
		return Account{}, ErrStaleResponse
	}
	if ctx.Err() != nil {
		return Account{}, ErrCancelled
	}
	c.state.account = &accountSession{token: reply.Session, account: account}
	return account, nil
}

func (c *Client) ActivateAccount(ctx context.Context, licenceID, idempotencyKey string) (Snapshot, error) {
	return c.ActivateAccountWithPrevious(ctx, licenceID, "", idempotencyKey)
}
func (c *Client) ActivateAccountWithPrevious(ctx context.Context, licenceID, previousCredential, idempotencyKey string) (Snapshot, error) {
	if !opaque(licenceID) {
		return Snapshot{}, ErrConfiguration
	}
	return c.activate(ctx, "", licenceID, previousCredential, idempotencyKey)
}

// LogoutAccount clears local access before networking, even when ctx is already
// cancelled. A nil result confirms remote revocation when a session was present.
func (c *Client) LogoutAccount(ctx context.Context) error {
	c.mu.Lock()
	if err := c.syncStorageLocked(); err != nil {
		c.mu.Unlock()
		return err
	}
	session := c.state.account
	clearState(&c.state)
	if err := c.invalidateLocked(); err != nil {
		c.mu.Unlock()
		return err
	}
	generation := c.state.generation
	c.mu.Unlock()
	if session == nil {
		return nil
	}
	data, err := c.transport.DeleteBearer(ctx, c.accountPath(clientPrefix+"sessions/current", ""), session.token)
	if generationErr := c.checkGeneration(generation); generationErr != nil {
		return generationErr
	}
	if err != nil {
		return err
	}
	if data != nil {
		return ErrInvalidResponse
	}
	return nil
}

// OwnedLicences returns at most one page. Pass an empty cursor for the first.
func (c *Client) OwnedLicences(ctx context.Context, after string) (OwnedLicences, error) {
	if after != "" && !opaque(after) {
		return OwnedLicences{}, ErrConfiguration
	}
	generation, err := c.generation()
	if err != nil {
		return OwnedLicences{}, err
	}
	if err := c.lockOperation(ctx, generation); err != nil {
		return OwnedLicences{}, err
	}
	defer c.unlockOperation()
	session, err := c.customerSession(generation)
	if err != nil {
		return OwnedLicences{}, err
	}
	data, err := c.transport.GetBearer(ctx, c.accountPath(clientPrefix+"licences", after), session.token)
	var page OwnedLicences
	if err == nil {
		err = decodeJSON(data, &page)
	}
	if err == nil {
		if len(page.Items) > 50 || page.NextCursor != nil && !opaque(*page.NextCursor) {
			err = ErrInvalidResponse
		}
		for _, licence := range page.Items {
			if validation := checkLicence(licence); validation != nil {
				err = validation
				break
			}
		}
	}
	if err := c.finishAccount(ctx, generation, err); err != nil {
		return OwnedLicences{}, err
	}
	return page, nil
}

func (c *Client) ClaimLicence(ctx context.Context, key, idempotencyKey string) (OwnedLicence, error) {
	if key == "" || len(key) > 256 || !validOperationID(idempotencyKey) {
		return OwnedLicence{}, ErrConfiguration
	}
	var licence OwnedLicence
	err := c.accountPost(ctx, clientPrefix+"licence-claims", map[string]any{"licence_key": key, "idempotency_key": idempotencyKey}, true, func(data json.RawMessage) error {
		if err := decodeJSON(data, &licence); err != nil {
			return err
		}
		return checkLicence(licence)
	})
	return licence, err
}
func (c *Client) RequestEmailChange(ctx context.Context, password, email string) error {
	if len(password) > 256 || len(email) > 254 || !utf8.ValidString(password) {
		return ErrConfiguration
	}
	return c.accountPost(ctx, clientPrefix+"email-changes", map[string]any{"password": password, "email": email}, false, checkAccepted)
}
func (c *Client) Register(ctx context.Context, input Registration) (*PendingRegistration, error) {
	if input.LicenceKey == "" || len(input.LicenceKey) > 256 || len(input.Username) > 128 || len(input.Email) > 254 || len(input.Password) > 256 || !utf8.ValidString(input.Password) || utf8.RuneCountInString(input.Password) < 8 {
		return nil, ErrConfiguration
	}
	data, err := c.publicPost(ctx, clientPrefix+"registrations", map[string]any{"licence_key": input.LicenceKey, "username": input.Username, "email": input.Email, "password": input.Password})
	if err != nil {
		return nil, err
	}
	var reply registrationReply
	if decodeJSON(data, &reply) != nil || !reply.Accepted || !bearer(reply.ResendCredential) {
		return nil, ErrInvalidResponse
	}
	if _, err := timestamp(reply.ExpiresAt); err != nil {
		return nil, err
	}
	return &PendingRegistration{Accepted: true, ExpiresAt: reply.ExpiresAt, resendCredential: reply.ResendCredential, applicationID: c.config.ApplicationID, environmentID: c.config.EnvironmentID}, nil
}
func (c *Client) ResendRegistration(ctx context.Context, pending *PendingRegistration) error {
	if pending == nil || pending.applicationID != c.config.ApplicationID || pending.environmentID != c.config.EnvironmentID || !bearer(pending.resendCredential) {
		return ErrConfiguration
	}
	data, err := c.publicPost(ctx, clientPrefix+"registrations/resend", map[string]any{"resend_credential": pending.resendCredential})
	if err != nil {
		return err
	}
	return checkAccepted(data)
}
func (c *Client) RequestPasswordRecovery(ctx context.Context, email string) error {
	if len(email) > 254 {
		return ErrConfiguration
	}
	data, err := c.publicPost(ctx, clientPrefix+"password-recovery", map[string]any{"email": email})
	if err != nil {
		return err
	}
	return checkAccepted(data)
}
func (c *Client) scopeBody(body map[string]any) map[string]any {
	body["application_id"] = c.config.ApplicationID
	body["environment_id"] = c.config.EnvironmentID
	return body
}
func (c *Client) accountPath(route, after string) string {
	result := route + "?application_id=" + c.config.ApplicationID + "&environment_id=" + c.config.EnvironmentID
	if after != "" {
		result += "&after=" + after
	}
	return result
}
func (c *Client) customerSession(generation uint64) (*accountSession, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.syncStorageLocked(); err != nil {
		return nil, err
	}
	if c.state.generation != generation {
		return nil, ErrStaleResponse
	}
	if c.state.account == nil {
		return nil, ErrReauthenticationRequired
	}
	copy := *c.state.account
	return &copy, nil
}
func (c *Client) accountPost(ctx context.Context, route string, body map[string]any, safe bool, validate func(json.RawMessage) error) error {
	generation, err := c.generation()
	if err != nil {
		return err
	}
	if err := c.lockOperation(ctx, generation); err != nil {
		return err
	}
	defer c.unlockOperation()
	session, err := c.customerSession(generation)
	if err != nil {
		return err
	}
	body["customer_session"] = session.token
	data, err := c.transport.Post(ctx, route, c.scopeBody(body), safe)
	if err == nil {
		err = validate(data)
	}
	return c.finishAccount(ctx, generation, err)
}
func (c *Client) publicPost(ctx context.Context, route string, body map[string]any) (json.RawMessage, error) {
	generation, err := c.generation()
	if err != nil {
		return nil, err
	}
	data, responseErr := c.transport.Post(ctx, route, c.scopeBody(body), false)
	if err := c.checkGeneration(generation); err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, ErrCancelled
	}
	return data, responseErr
}
func (c *Client) finishAccount(ctx context.Context, generation uint64, err error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if syncErr := c.syncStorageLocked(); syncErr != nil {
		return syncErr
	}
	if c.state.generation != generation {
		return ErrStaleResponse
	}
	if ctx.Err() != nil {
		return ErrCancelled
	}
	if err != nil && !errors.Is(err, ErrTransient) && !errors.Is(err, ErrCancelled) && !errors.Is(err, &Error{Kind: Denied, Code: "session_expired"}) {
		clearState(&c.state)
		if storageErr := c.invalidateLocked(); storageErr != nil {
			return storageErr
		}
	}
	return err
}
func checkAccepted(data json.RawMessage) error {
	var reply acceptedReply
	if decodeJSON(data, &reply) != nil || !reply.Accepted {
		return ErrInvalidResponse
	}
	return nil
}
func checkLogin(reply loginReply) error {
	customer := reply.Customer
	if !opaque(customer.ID) || customer.Suspended || len(customer.Username) < 3 || len(customer.Username) > 32 || !errorCode(customer.Username) || len(customer.Email) == 0 || len(customer.Email) > 254 || !bearer(reply.Session) {
		return ErrInvalidResponse
	}
	if _, err := timestamp(customer.CreatedAt); err != nil {
		return err
	}
	if _, err := timestamp(reply.ExpiresAt); err != nil {
		return err
	}
	return nil
}
func checkLicence(licence OwnedLicence) error {
	if !opaque(licence.ID) || licence.DeviceLimit < 1 || licence.DeviceLimit > 100 || !validEntitlements(licence.Entitlements) || utf8.RuneCountInString(licence.PolicyName) > 80 {
		return ErrInvalidResponse
	}
	for _, date := range []*string{licence.FirstUsedAt, licence.ExpiresAt} {
		if date != nil {
			if _, err := timestamp(*date); err != nil {
				return err
			}
		}
	}
	return nil
}
