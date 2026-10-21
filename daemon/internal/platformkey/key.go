// Package platformkey stores encryption keys in the operating system keystore.
package platformkey

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"time"
)

// Load keeps secret values out of command arguments, files and error text.
// A missing or locked keystore is an error, never a plaintext fallback.
func Load(identity string) ([]byte, error) {
	sum := sha256.Sum256([]byte(identity))
	account := hex.EncodeToString(sum[:16])
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	read := func() ([]byte, error) {
		var cmd *exec.Cmd
		switch runtime.GOOS {
		case "darwin":
			cmd = exec.CommandContext(ctx, "/usr/bin/security", "find-generic-password", "-s", "com.secure-agent.history", "-a", account, "-w")
		case "linux":
			cmd = exec.CommandContext(ctx, "secret-tool", "lookup", "service", "secure-agent-history", "account", account)
		default:
			return nil, errors.New("operating system keystore is unavailable")
		}
		data, err := cmd.Output()
		if err != nil {
			return nil, err
		}
		key, err := hex.DecodeString(string(bytes.TrimSpace(data)))
		clear(data)
		if err != nil || len(key) != 32 {
			clear(key)
			return nil, errors.New("invalid history key")
		}
		return key, nil
	}
	key, err := read()
	if err == nil {
		return key, nil
	}
	var exit *exec.ExitError
	// Only an absent item permits creation. Never replace a locked key.
	if !errors.As(err, &exit) || (runtime.GOOS == "darwin" && exit.ExitCode() != 44) || (runtime.GOOS == "linux" && exit.ExitCode() != 1) {
		return nil, errors.New("history keystore could not be unlocked")
	}
	if runtime.GOOS == "linux" && !linuxItemAbsent(ctx, account) {
		return nil, errors.New("history keystore could not be unlocked")
	}
	key = make([]byte, 32)
	if _, err = rand.Read(key); err != nil {
		return nil, errors.New("history key could not be created")
	}
	encoded := []byte(hex.EncodeToString(key))
	defer clear(encoded)
	defer clear(key)
	var cmd *exec.Cmd
	if runtime.GOOS == "darwin" {
		// Interactive command input keeps the key out of process listings.
		cmd = exec.CommandContext(ctx, "/usr/bin/security", "-i")
		cmd.Stdin = bytes.NewReader(append([]byte(fmt.Sprintf("add-generic-password -s com.secure-agent.history -a %s -w ", account)), append(encoded, '\n')...))
	} else {
		cmd = exec.CommandContext(ctx, "secret-tool", "store", "--label=Secure Agent encrypted history", "service", "secure-agent-history", "account", account)
		cmd.Stdin = bytes.NewReader(encoded)
	}
	if cmd.Run() != nil {
		return nil, errors.New("history key could not be saved in the operating system keystore")
	}
	saved, err := read()
	if err != nil || subtle.ConstantTimeCompare(saved, key) != 1 {
		clear(saved)
		return nil, errors.New("history key storage could not be confirmed")
	}
	return saved, nil
}

// Unlike lookup, secret-tool search distinguishes an empty successful search
// from a backend error. Any item (including a locked or unreadable item) emits
// a header. Never create a replacement unless the search succeeds with no items.
func linuxItemAbsent(ctx context.Context, account string) bool {
	data, err := exec.CommandContext(ctx, "secret-tool", "search", "--all", "service", "secure-agent-history", "account", account).Output()
	defer clear(data)
	return err == nil && len(bytes.TrimSpace(data)) == 0
}
