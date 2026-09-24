//go:build linux

package orbit

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os/exec"
	"runtime"
	"syscall"
	"time"
)

const secretRecordLimit = 4096
const secretBase64Limit = 5464
const secretCommandDeadline = 5 * time.Second

type secretOutput struct {
	data     []byte
	limit    int
	overflow bool
	cancel   context.CancelFunc
}

func (output *secretOutput) Write(data []byte) (int, error) {
	remaining := output.limit - len(output.data)
	if len(data) > remaining {
		output.data = append(output.data, data[:remaining]...)
		output.overflow = true
		output.cancel()
	} else {
		output.data = append(output.data, data...)
	}
	return len(data), nil
}

func secretTool(operation, item string, input []byte) ([]byte, error) {
	if !lowerHex(item, 64) || operation != "lookup" && operation != "store" {
		return nil, ErrStorage
	}
	arguments := []string{operation}
	if operation == "store" {
		arguments = append(arguments, "--label=Orbit SDK protected storage")
	}
	arguments = append(arguments, "application", "orbit-sdk", "sdk", "go", "scope", item)
	ctx, cancel := context.WithTimeout(context.Background(), secretCommandDeadline)
	defer cancel()
	command := exec.CommandContext(ctx, "/usr/bin/secret-tool", arguments...)
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// Kill helpers in the private process group too, then bound pipe draining
	// even if an unexpected descendant escaped while retaining a pipe handle.
	command.Cancel = func() error {
		err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		if err == syscall.ESRCH {
			return nil
		}
		return err
	}
	command.WaitDelay = 200 * time.Millisecond
	stdout := &secretOutput{data: make([]byte, 0, secretBase64Limit+1), limit: secretBase64Limit + 1, cancel: cancel}
	stderr := &secretOutput{data: make([]byte, 0, 4096), limit: 4096, cancel: cancel}
	command.Stdin = bytes.NewReader(input)
	command.Stdout, command.Stderr = stdout, stderr
	err := command.Run()
	defer func() { clear(stderr.data); runtime.KeepAlive(stderr.data) }()
	failed := func() ([]byte, error) { clear(stdout.data); return nil, ErrStorage }
	if ctx.Err() != nil || stdout.overflow || stderr.overflow {
		return failed()
	}
	if err != nil {
		var exited *exec.ExitError
		if operation == "lookup" && errors.As(err, &exited) && exited.ExitCode() == 1 && len(stdout.data) == 0 && len(stderr.data) == 0 {
			return nil, errStorageMissing
		}
		return failed()
	}
	if len(stderr.data) != 0 || operation == "store" && len(stdout.data) != 0 {
		return failed()
	}
	return stdout.data, nil
}

func lookupSecretRecord(item string) ([]byte, error) {
	output, err := secretTool("lookup", item, nil)
	if err != nil {
		return nil, err
	}
	defer func() { clear(output); runtime.KeepAlive(output) }()
	return decodeSecretOutput(output)
}

func decodeSecretOutput(output []byte) ([]byte, error) {
	encoded := output
	if len(encoded) > 0 && encoded[len(encoded)-1] == '\n' {
		encoded = encoded[:len(encoded)-1]
	}
	if len(encoded) == 0 || len(encoded) > secretBase64Limit || bytes.ContainsAny(encoded, "\r\n \t") {
		return nil, ErrStorage
	}
	record := make([]byte, base64.StdEncoding.DecodedLen(len(encoded)))
	count, err := base64.StdEncoding.Strict().Decode(record, encoded)
	if err != nil || count == 0 || count > secretRecordLimit {
		clear(record)
		return nil, ErrStorage
	}
	return record[:count], nil
}

func storeSecretRecord(item string, record []byte) error {
	if len(record) == 0 || len(record) > secretRecordLimit {
		return ErrStorage
	}
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(record)))
	base64.StdEncoding.Encode(encoded, record)
	defer func() { clear(encoded); runtime.KeepAlive(encoded) }()
	_, err := secretTool("store", item, encoded)
	return err
}
