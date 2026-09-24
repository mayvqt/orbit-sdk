package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	orbit "github.com/mayvqt/orbit-sdk/sdk/go"
)

const commands = "Commands: activate, login, licences, more, select, claim, register, resend, recover, email, account-logout, status, export, deactivate, logout, quit"

type console struct {
	input      *bufio.Scanner
	client     *orbit.Client
	pending    *orbit.PendingRegistration
	nextCursor string
}

func (c *console) prompt(label string, password bool) (string, error) {
	fmt.Print(label)
	if !c.input.Scan() {
		if err := c.input.Err(); err != nil {
			return "", err
		}
		return "", io.EOF
	}
	value := c.input.Text()
	if !password {
		value = strings.TrimSpace(value)
	}
	return value, nil
}
func (c *console) password() (string, error) {
	return c.prompt("Password (this console does not hide terminal input): ", true)
}
func operationID() (string, error) {
	device, err := orbit.NewInstallation()
	return device.InstallationID, err
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	args := os.Args[1:]
	if len(args) != 4 && len(args) != 5 {
		return errors.New("Usage: orbit-licensed-export URL APP_ID ENVIRONMENT_ID ISSUER [INSTALLATION_ID]")
	}
	device, err := orbit.NewInstallation()
	if err != nil {
		return err
	}
	if len(args) == 5 {
		device.InstallationID = args[4]
	}
	transport, err := newTransport(args[0])
	if err != nil {
		return err
	}
	defer transport.CloseIdleConnections()
	client, err := orbit.NewClient(orbit.Config{ApplicationID: args[1], EnvironmentID: args[2], Issuer: args[3]}, device, transport)
	if err != nil {
		return err
	}
	fmt.Printf("Installation ID: %s (public; reuse this ID after restart)\n", device.InstallationID)
	fmt.Println("This example keeps bearer credentials in memory. Use a protected Storage adapter in your application.")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if state, err := client.Snapshot(); err == nil && (state.Access == orbit.AccessRefreshRequired || state.Access == orbit.AccessOffline || state.Access == orbit.AccessExpired) {
					_, _ = client.RequireAccess(ctx, "export")
				}
			}
		}
	}()
	defer func() { cancel(); _ = client.Logout(); <-done }()
	input := bufio.NewScanner(os.Stdin)
	input.Buffer(make([]byte, 1024), 64*1024)
	c := console{input: input, client: client}
	fmt.Println(commands)
	for {
		command, err := c.prompt("orbit> ", false)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if command == "quit" || command == "" {
			return nil
		}
		if err := c.command(ctx, command); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			c.reportError(err)
		}
	}
}
func (c *console) command(ctx context.Context, command string) error {
	switch command {
	case "activate":
		key, err := c.prompt("Licence key (paste locally; never pass it on the command line): ", false)
		if err != nil {
			return err
		}
		operation, err := operationID()
		if err != nil {
			return err
		}
		state, err := c.client.Activate(ctx, key, operation)
		if err != nil {
			return err
		}
		fmt.Printf("Access: %s\n", state.Access)
	case "login":
		username, err := c.prompt("Customer username: ", false)
		if err != nil {
			return err
		}
		password, err := c.password()
		if err != nil {
			return err
		}
		c.nextCursor = ""
		account, err := c.client.Login(ctx, username, password)
		if err != nil {
			return err
		}
		fmt.Printf("Signed in as %s. Use licences and select before protected work.\n", account.Customer.Username)
	case "licences", "more":
		if command == "licences" {
			c.nextCursor = ""
		}
		if command == "more" && c.nextCursor == "" {
			fmt.Println("No next page. Use licences to start again.")
			return nil
		}
		page, err := c.client.OwnedLicences(ctx, c.nextCursor)
		if err != nil {
			return err
		}
		if len(page.Items) == 0 {
			fmt.Println("No owned licences. Use claim with an eligible key.")
		}
		for _, licence := range page.Items {
			expiry := "not started or perpetual"
			if licence.ExpiresAt != nil {
				expiry = *licence.ExpiresAt
			}
			fmt.Printf("%s | %s | %s | expires %s\n", licence.ID, licence.PolicyName, licence.State, expiry)
		}
		c.nextCursor = ""
		if page.NextCursor != nil {
			c.nextCursor = *page.NextCursor
			fmt.Println("Use more for the next page.")
		}
	case "select":
		licence, err := c.prompt("Licence ID from licences: ", false)
		if err != nil {
			return err
		}
		operation, err := operationID()
		if err != nil {
			return err
		}
		state, err := c.client.ActivateAccount(ctx, licence, operation)
		if err != nil {
			return err
		}
		fmt.Printf("Access: %s\n", state.Access)
	case "claim":
		key, err := c.prompt("Licence key to claim (paste locally): ", false)
		if err != nil {
			return err
		}
		operation, err := operationID()
		if err != nil {
			return err
		}
		licence, err := c.client.ClaimLicence(ctx, key, operation)
		if err != nil {
			return err
		}
		fmt.Printf("Claimed licence %s. Use select to activate it.\n", licence.ID)
	case "register":
		key, err := c.prompt("Licence key (paste locally): ", false)
		if err != nil {
			return err
		}
		username, err := c.prompt("New customer username: ", false)
		if err != nil {
			return err
		}
		email, err := c.prompt("Email address: ", false)
		if err != nil {
			return err
		}
		fmt.Println("Customer passwords require at least 8 characters; spaces are preserved.")
		password, err := c.password()
		if err != nil {
			return err
		}
		pending, err := c.client.Register(ctx, orbit.Registration{LicenceKey: key, Username: username, Email: email, Password: password})
		if err != nil {
			return err
		}
		c.pending = pending
		fmt.Println("Request accepted. If eligible, confirm the email link, then return here and login. Use resend if needed.")
	case "resend":
		if c.pending == nil {
			fmt.Println("Start registration in this process before requesting a resend.")
			return nil
		}
		if err := c.client.ResendRegistration(ctx, c.pending); err != nil {
			return err
		}
		fmt.Println("Request accepted. Check your email if the pending registration is eligible.")
	case "recover":
		email, err := c.prompt("Customer email address: ", false)
		if err != nil {
			return err
		}
		if err := c.client.RequestPasswordRecovery(ctx, email); err != nil {
			return err
		}
		fmt.Println("Request accepted. If eligible, use the email link and then login again.")
	case "email":
		email, err := c.prompt("New customer email address: ", false)
		if err != nil {
			return err
		}
		password, err := c.password()
		if err != nil {
			return err
		}
		if err := c.client.RequestEmailChange(ctx, password, email); err != nil {
			return err
		}
		fmt.Println("Confirm the links sent to both addresses, then login again.")
	case "account-logout":
		c.nextCursor = ""
		if err := c.client.LogoutAccount(ctx); err != nil {
			fmt.Printf("Local access cleared; remote customer signout was not confirmed: %v\n", err)
			c.printSupport(err)
		} else {
			fmt.Println("Customer session signed out. Local access is cleared; occupied device slots remain.")
		}
	case "status":
		state, err := c.client.Snapshot()
		if err != nil {
			return err
		}
		data, err := json.Marshal(state)
		if err != nil {
			return err
		}
		fmt.Println(string(data))
	case "export":
		if _, err := c.client.RequireAccess(ctx, "export"); err != nil {
			fmt.Printf("Export denied: %v\n", err)
			c.printSupport(err)
		} else {
			fmt.Println("Export authorized: synthetic report, rows=3, total=42")
		}
	case "deactivate":
		operation, err := operationID()
		if err != nil {
			return err
		}
		if err := c.client.Deactivate(ctx, operation); err != nil {
			fmt.Printf("Local access cleared; server release was not confirmed: %v\n", err)
			c.printSupport(err)
		} else {
			fmt.Println("Device slot released; new activation follows the policy cooldown.")
		}
	case "logout":
		if err := c.client.Logout(); err != nil {
			return err
		}
		c.pending = nil
		c.nextCursor = ""
		fmt.Println("Local access cleared. The server device slot remains occupied.")
	default:
		fmt.Println(commands)
	}
	return nil
}

func (c *console) printSupport(err error) {
	var failure *orbit.Error
	if errors.As(err, &failure) {
		summary, _ := json.Marshal(c.client.SupportSummary(err))
		fmt.Printf("Support summary: %s\n", summary)
	}
}

func (c *console) reportError(err error) {
	var failure *orbit.Error
	if errors.As(err, &failure) {
		fmt.Println(failure)
	} else {
		fmt.Println(err)
	}
	c.printSupport(err)
}
