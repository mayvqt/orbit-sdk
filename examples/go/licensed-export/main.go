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

const commands = "Commands: activate, login, licences, more, select, claim, register, resend, recover, email, account-logout, status, export, metered-export, updates, download, idle, resume, deactivate, logout, quit"

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

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	appKey := strings.TrimSpace(os.Getenv("ORBIT_APP_KEY"))
	if appKey == "" {
		return errors.New("Set ORBIT_APP_KEY from the Integration page")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	options := orbit.Options{StatePath: os.Getenv("ORBIT_STATE_PATH")}
	client, err := openClient(ctx, appKey, options)
	if err != nil {
		return err
	}
	defer client.Close()
	input := bufio.NewScanner(os.Stdin)
	input.Buffer(make([]byte, 1024), 64*1024)
	c := console{input: input, client: client}
	_, err = client.EnsureAccess(ctx, "export", func(context.Context) (string, error) {
		fmt.Println("Activate with a licence key, or leave it empty to use the account commands.")
		key, promptErr := c.prompt("Licence key: ", false)
		if errors.Is(promptErr, io.EOF) {
			return "", nil
		}
		return key, promptErr
	})
	if err != nil && !errors.Is(err, orbit.ErrNotActivated) {
		c.reportError(err)
	}
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
		state, err := c.client.Activate(ctx, key)
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
				expiry = licence.ExpiresAt.Format(time.RFC3339)
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
		state, err := c.client.ActivateAccount(ctx, licence)
		if err != nil {
			return err
		}
		fmt.Printf("Access: %s\n", state.Access)
	case "claim":
		key, err := c.prompt("Licence key to claim (paste locally): ", false)
		if err != nil {
			return err
		}
		licence, err := c.client.ClaimLicence(ctx, key)
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
	case "idle":
		return c.client.EndSession(ctx)
	case "resume":
		_, err := c.client.StartSession(ctx)
		return err
	case "metered-export":
		if _, err := c.client.RequireAccess(ctx, "export"); err != nil {
			return err
		}
		jobID, err := c.prompt("Export job ID (16–128 characters; reuse for retries): ", false)
		if err != nil {
			return err
		}
		result, err := c.client.Consume(ctx, "exports", 1, jobID)
		if err != nil {
			var mutation *orbit.MutationError
			if errors.As(err, &mutation) && mutation.Uncertain {
				fmt.Println("Outcome unknown. Retry this export with the same job ID.")
			}
			return err
		}
		fmt.Printf("Export authorized: synthetic report. Remaining exports: %d\n", result.Remaining)
	case "updates", "download":
		update, err := c.client.CheckForUpdates(ctx, 0)
		if err != nil {
			return err
		}
		if update == nil {
			fmt.Println("No eligible update for this target.")
			return nil
		}
		fmt.Printf("Update available: %s\n", update.Release.Version)
		if command == "updates" {
			return nil
		}
		destination, err := c.prompt("Destination file (must not already exist): ", false)
		if err != nil {
			return err
		}
		authorized, err := c.client.AuthorizeDownload(ctx, update.Release.ID, update.Artifact.ID)
		if err != nil {
			return err
		}
		if err := authorized.Download(ctx, destination, 128*1024*1024); err != nil {
			return err
		}
		fmt.Println("Verified download saved. No installer was executed.")
	case "deactivate":
		if err := c.client.Deactivate(ctx); err != nil {
			fmt.Printf("Local access cleared; server release was not confirmed: %v\n", err)
			c.printSupport(err)
		} else {
			fmt.Println("Device slot released.")
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
