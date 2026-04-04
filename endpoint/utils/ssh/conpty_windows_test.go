//go:build windows
// +build windows

package ssh

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestConPTYInteractiveExit(t *testing.T) {
	cmdPath := strings.TrimSpace(os.Getenv("ComSpec"))
	if cmdPath == "" {
		systemRoot := strings.TrimSpace(os.Getenv("SystemRoot"))
		if systemRoot == "" {
			systemRoot = `C:\Windows`
		}
		cmdPath = filepath.Join(systemRoot, "System32", "cmd.exe")
	}

	cmd := exec.Command(cmdPath, "/K")
	conpty, err := startConPTY(cmd, 120, 30)
	if err != nil {
		t.Fatalf("startConPTY failed: %v", err)
	}

	var out bytes.Buffer
	var outMu sync.Mutex
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		buf := make([]byte, 4096)
		for {
			n, readErr := conpty.Read(buf)
			if n > 0 {
				outMu.Lock()
				out.Write(buf[:n])
				outMu.Unlock()
			}
			if readErr != nil {
				return
			}
		}
	}()

	readyDeadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(readyDeadline) {
		outMu.Lock()
		current := out.String()
		outMu.Unlock()
		if strings.Contains(current, "cmd.exe") || len(current) > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	_, _ = conpty.Write([]byte("\r"))
	_, _ = conpty.Write([]byte("exit\r\n"))

	waitDone := make(chan error, 1)
	go func() {
		waitDone <- conpty.Wait()
	}()

	select {
	case waitErr := <-waitDone:
		if waitErr != nil {
			t.Fatalf("conpty wait failed: %v", waitErr)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("conpty did not exit after sending exit command")
	}

	_ = conpty.Close()

	select {
	case <-readDone:
	case <-time.After(3 * time.Second):
		t.Fatal("conpty reader did not stop after close")
	}

	outMu.Lock()
	defer outMu.Unlock()
	if out.Len() == 0 {
		t.Fatal("expected some shell output before exit, got empty output")
	}
}
