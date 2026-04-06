package ssh

import (
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"

	"aps/endpoint/utils/ssh/pty"
	"aps/endpoint/utils/ssh/radix"

	"golang.org/x/crypto/ssh"
)

// The `session` type represents a session in a Go program that includes various fields and methods for
// managing SSH connections and port forwarding.
// @property l - A pointer to a logger.Logger object, which is used for logging purposes.
// @property c - - `c` is a pointer to an `ssh.ServerConn` object. This object represents an SSH server
// connection.
// @property {string} xshell - The `xshell` property is a string that represents the name or identifier
// of the shell being used in the session.
// @property pty - The `pty` property is a file descriptor that represents the pseudo-terminal
// associated with the session. It is used for interacting with the terminal, such as reading input and
// writing output.
// @property tty - The `tty` property is a file descriptor that represents the terminal device
// associated with the session. It is used for input and output operations with the terminal.
// @property commands - The `commands` property is a radix tree data structure that stores the commands
// available for the session. It is used to map command names to their corresponding functions or
// handlers.
// @property exitChan - The `exitChan` property is a channel used to signal the session to exit or
// terminate. It is typically used to communicate between different goroutines or to coordinate the
// termination of a session.
// @property forwardedTCPPorts - The `forwardedTCPPorts` property is a map that stores the TCP ports
// that have been forwarded by the SSH session. The keys of the map are strings representing the
// forwarded port numbers, and the values are `net.Listener` objects that represent the listening
// sockets for those ports.
// @property directTCPPorts - The `directTCPPorts` property is a map that stores the TCP listeners for
// direct port forwarding. It maps a string (typically the port number) to a `net.Listener` object.
// This allows the SSH server to accept incoming TCP connections on a specific port and forward them to
// the appropriate destination
// @property mu - The `mu` property is a `sync.Mutex` object, which is used for synchronization and
// mutual exclusion. It provides a way to ensure that only one goroutine can access a particular
// section of code at a time, preventing concurrent access and potential race conditions.
type session struct {
	c                 *ssh.ServerConn
	xshell            string
	pty               *os.File
	tty               *os.File
	conPTY            conPTYSession
	ptyInitErr        error
	termCols          uint16
	termRows          uint16
	commands          *radix.Tree
	exitChan          chan bool
	forwardedTCPPorts map[string]net.Listener
	directTCPPorts    map[string]net.Listener
	mu                sync.Mutex
}

type conPTYSession interface {
	io.ReadWriteCloser
	Resize(cols, rows uint16) error
	Wait() error
}

// The `initPty` function initializes the pseudo-terminal (pty) for the SSH session. It opens the pty
// and tty files, sets the default shell, and sets the environment variable `TERM` to `xterm`. The pty
// is used for interacting with the terminal, such as reading input and writing output. The function
// returns an error if there is any issue with initializing the pty.
func (s *session) initPty() (err error) {
	s.xshell = chooseDefaultShell()
	if s.xshell == "" {
		return errors.New("no suitable default shell found")
	}
	if s.termCols == 0 {
		s.termCols = 120
	}
	if s.termRows == 0 {
		s.termRows = 30
	}
	if runtime.GOOS == "windows" {
		return nil
	}

	s.pty, s.tty, err = pty.Open()
	if err != nil {
		// log.Echo().WithError(err).Debug("could not start pty")
		return err
	}

	return nil
}

func chooseDefaultShell() string {
	var candidates []string
	if runtime.GOOS == "windows" {
		systemRoot := strings.TrimSpace(os.Getenv("SystemRoot"))
		if systemRoot == "" {
			systemRoot = `C:\Windows`
		}
		programFiles := strings.TrimSpace(os.Getenv("ProgramFiles"))
		if programFiles == "" {
			programFiles = `C:\Program Files`
		}
		candidates = []string{
			strings.TrimSpace(os.Getenv("ComSpec")),
			filepath.Join(programFiles, "PowerShell", "7", "pwsh.exe"),
			filepath.Join(systemRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
			filepath.Join(systemRoot, "System32", "cmd.exe"),
		}
	} else {
		candidates = []string{
			strings.TrimSpace(os.Getenv("SHELL")),
			"/bin/bash",
			"/usr/bin/bash",
			"/bin/zsh",
			"/usr/bin/zsh",
			"/bin/sh",
			"/usr/bin/sh",
			"/bin/ash",
			"/usr/bin/ash",
		}
	}

	for _, shell := range candidates {
		shell = strings.TrimSpace(shell)
		if shell == "" {
			continue
		}
		info, err := os.Stat(shell)
		if err != nil || info.IsDir() {
			continue
		}
		if runtime.GOOS != "windows" && info.Mode()&0o111 == 0 {
			continue
		}
		return shell
	}
	return ""
}

func buildInteractiveShellCommand(shellPath string) *exec.Cmd {
	name := strings.ToLower(path.Base(strings.ReplaceAll(shellPath, "\\", "/")))
	switch name {
	case "cmd.exe":
		return exec.Command(shellPath, "/K")
	case "powershell.exe", "pwsh.exe":
		return exec.Command(shellPath, "-NoLogo", "-NoExit")
	default:
		return exec.Command(shellPath)
	}
}

// The `handleSessionRequests` function is responsible for handling incoming SSH session requests. It
// takes two parameters: `in`, which is a channel of `*ssh.Request` objects representing the incoming
// requests, and `channel`, which is an `ssh.Channel` object representing the SSH channel for the
// session.
func (s *session) handleSessionRequests(in <-chan *ssh.Request, channel ssh.Channel) {
	defer func() {
		s.Close()
		channel.Close()
	}()

	// Handle Ctrl+C signal
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT)
		for range sigChan {
			// Send Ctrl+C to shell
			if s.pty != nil {
				_, _ = s.pty.Write([]byte{3})
			} else if s.conPTY != nil {
				_, _ = s.conPTY.Write([]byte{3})
			}
		}
	}()

	for req := range in {
		var err error
		switch req.Type {
		case "shell":
			if runtime.GOOS == "windows" {
				if s.ptyInitErr != nil || s.xshell == "" {
					if s.ptyInitErr != nil {
						log.Printf("[SSH] Failed to initialize shell session: %v", s.ptyInitErr)
					}
					_ = req.Reply(false, nil)
					_, _ = channel.Write([]byte("Failed to initialize default shell on endpoint.\r\n"))
					return
				}

				cmd := buildInteractiveShellCommand(s.xshell)
				cmd.Env = append(os.Environ(), "TERM=xterm", "SHELL="+s.xshell)

				conPTY, startErr := startConPTY(cmd, s.termCols, s.termRows)
				if startErr != nil {
					log.Printf("[SSH] Failed to start ConPTY shell (%s): %v", s.xshell, startErr)
					_ = req.Reply(false, nil)
					_, _ = channel.Write([]byte("Failed to start ConPTY shell on endpoint.\r\n"))
					return
				}
				s.conPTY = conPTY

				var once sync.Once
				closeSession := func() {
					_ = channel.Close()
					select {
					case s.exitChan <- true:
					default:
					}
				}

				go func() {
					_, _ = io.Copy(channel, s.conPTY)
					once.Do(closeSession)
				}()

				go func() {
					_, _ = io.Copy(s.conPTY, channel)
					once.Do(closeSession)
				}()

				go func() {
					_ = s.conPTY.Wait()
					once.Do(closeSession)
				}()

				_ = req.Reply(true, nil)
				_, _ = s.conPTY.Write([]byte("\r"))
				continue
			}

			if s.ptyInitErr != nil || s.xshell == "" || s.pty == nil || s.tty == nil {
				_ = req.Reply(false, nil)
				_, _ = channel.Write([]byte("Failed to initialize PTY/default shell on endpoint.\r\n"))
				return
			}

			cmd := exec.Command(s.xshell)
			cmd.Env = append(os.Environ(), "TERM=xterm", "SHELL="+s.xshell)
			err := PtyRun(cmd, s.tty)
			if err != nil {
				_ = req.Reply(false, nil)
				_, _ = channel.Write([]byte("Failed to start default shell on endpoint.\r\n"))
				// log.Echo().WithError(err).Error("could not run pty")
				return
			}

			// Teardown session
			var once sync.Once
			closeSession := func() {
				_ = channel.Close()
				select {
				case s.exitChan <- true:
				default:
				}
				// log.Debug("session closed")
			}

			// Pipe session to shell and vice versa
			go func() {
				_, _ = io.Copy(channel, s.pty)
				once.Do(closeSession)
			}()

			go func() {
				_, _ = io.Copy(s.pty, channel)
				once.Do(closeSession)
			}()

			// We don't accept any commands (Payload),
			// only the default shell.
			_ = req.Reply(true, nil)

		case "pty-req":
			if len(req.Payload) < 4 {
				_ = req.Reply(false, nil)
				continue
			}
			termLen := binary.BigEndian.Uint32(req.Payload[:4])
			dimsOffset := 4 + termLen
			if termLen > uint32(len(req.Payload)-4) || len(req.Payload) < int(dimsOffset)+8 {
				_ = req.Reply(false, nil)
				continue
			}
			// termEnv := string(req.Payload[4 : termLen+4])
			w, h := parseDims(req.Payload[dimsOffset:])
			if w > 0 {
				s.termCols = uint16(w)
			}
			if h > 0 {
				s.termRows = uint16(h)
			}
			if runtime.GOOS == "windows" {
				if s.conPTY != nil {
					_ = s.conPTY.Resize(s.termCols, s.termRows)
				}
				err = req.Reply(true, nil)
				continue
			}
			if s.pty != nil {
				SetWinsize(s.pty, w, h)
			}
			err = req.Reply(true, nil)
			// log.Debug("pty-req '%s'", termEnv)

		case "window-change":
			if len(req.Payload) < 8 {
				_ = req.Reply(false, nil)
				continue
			}
			w, h := parseDims(req.Payload)
			if w > 0 {
				s.termCols = uint16(w)
			}
			if h > 0 {
				s.termRows = uint16(h)
			}
			if runtime.GOOS == "windows" {
				if s.conPTY != nil {
					_ = s.conPTY.Resize(s.termCols, s.termRows)
				}
				err = req.Reply(true, nil)
				continue
			}
			if s.pty != nil {
				SetWinsize(s.pty, w, h)
			}
			// log.Debug("declining %s request...", req.Type)
			err = req.Reply(true, nil)

		case "exec":
			var payload = struct{ Value string }{}
			cErr := ssh.Unmarshal(req.Payload, &payload)
			if cErr != nil {
				req.Reply(false, nil)
				return
			}
			req.Reply(true, nil)
			s.dispatchCommand(payload.Value, &stringWriter{channel})

			//TODO: Fix error handling and report the proper status back
			status := struct{ Status uint32 }{uint32(0)}
			//TODO: I think this is how we shut down a shell as well?
			channel.SendRequest("exit-status", false, ssh.Marshal(status))
			return

		case "subsystem":
			subsystem, parseErr := parseSubsystemPayload(req.Payload)
			if parseErr != nil {
				err = req.Reply(false, nil)
				continue
			}
			if subsystem == "sftp" {
				// log.Warn("sftp request")
				err = req.Reply(true, nil)
				if err != nil {
					return
				}
				// Serve SFTP in-place. Returning immediately would trigger deferred
				// channel/session close and break directory listings for clients.
				s.handleSftp(channel)
			} else {
				err = req.Reply(false, nil)
			}
			return

		case "tcpip-forward":
			// tcpip-forward is a global request (connection-level), not a session request.
			err = req.Reply(false, nil)

		case "cancel-tcpip-forward":
			// cancel-tcpip-forward is a global request (connection-level), not a session request.
			err = req.Reply(false, nil)

		case "direct-tcpip":
			// direct-tcpip is a channel type, not a session request.
			err = req.Reply(false, nil)

		case "forwarded-tcpip":
			// forwarded-tcpip is a channel type, not a session request.
			err = req.Reply(false, nil)

		case "exit-status":
			req.Reply(true, nil)
			select {
			case s.exitChan <- true:
			default:
			}
			return

		default:
			// log.Echo().WithField("request", req.Type).Debug("Rejected unknown request")
			err = req.Reply(false, nil)
		}

		if err != nil {
			// log.Echo().WithError(err).Info("Error handling ssh session requests")
			return
		}
	}
}

func parseSubsystemPayload(payload []byte) (string, error) {
	var req struct {
		Name string
	}
	if err := ssh.Unmarshal(payload, &req); err != nil {
		return "", err
	}
	if req.Name == "" {
		return "", errors.New("empty subsystem request")
	}
	return req.Name, nil
}

// Start assigns a pseudo-terminal tty os.File to c.Stdin, c.Stdout,
// and c.Stderr, calls c.Start, and returns the File of the tty's
// corresponding pty.
func PtyRun(c *exec.Cmd, tty *os.File) (err error) {
	defer tty.Close()
	c.Stdout = tty
	c.Stdin = tty
	c.Stderr = tty
	return c.Start()
}

// parseDims extracts two uint32s from the provided buffer.
func parseDims(b []byte) (uint32, uint32) {
	if len(b) < 8 {
		return 0, 0
	}
	w := binary.BigEndian.Uint32(b)
	h := binary.BigEndian.Uint32(b[4:])
	return w, h
}

// Winsize stores the Height and Width of a terminal.
type Winsize struct {
	Height uint16
	Width  uint16
}

// SetWinsize sets the size of the given pty.
func SetWinsize(t *os.File, w, h uint32) {
	ws := &pty.Winsize{Rows: uint16(h), Cols: uint16(w)}
	pty.Setsize(t, ws)
}
