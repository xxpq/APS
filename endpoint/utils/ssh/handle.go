package ssh

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os/exec"
	"runtime"
	"strconv"
	"sync"
	"time"

	"aps/endpoint/utils/ssh/shlex"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// The `handleChannels` function is responsible for handling incoming SSH channels. It receives a
// channel of `ssh.NewChannel` objects and creates a limited goroutine pool to handle each channel
// concurrently. It then checks the type of each channel and delegates the handling to the appropriate
// function (`handleSessionChannel`, `handleDirectTcpip`, `handleForwardedTcpip`, or
// `handleUnknownChannel`).
func (s *session) handleChannels(chans <-chan ssh.NewChannel) {
	pool := make(chan struct{}, 10)
	for newChannel := range chans {
		pool <- struct{}{}
		go func(newChannel ssh.NewChannel) {
			defer func() {
				<-pool
			}()
			switch newChannel.ChannelType() {
			case "session":
				s.handleSessionChannel(newChannel)
			case "direct-tcpip":
				s.handleDirectTcpip(newChannel)
			case "forwarded-tcpip":
				s.handleForwardedTcpip(newChannel)
			default:
				s.handleUnknownChannel(newChannel)
			}
		}(newChannel)
	}
}

// The `handleSessionChannel` function is responsible for handling incoming SSH session channels. It
// accepts a `ssh.NewChannel` object and performs the necessary operations to handle the session
// channel. This includes accepting the channel, handling session requests, and managing the
// communication between the client and the server.
func (s *session) handleSessionChannel(newChannel ssh.NewChannel) {
	// log.Echo().WithField("channelType", newChannel.ChannelType()).Debug("accept ssh session channel")
	channel, requests, err := newChannel.Accept()
	if err != nil {
		// log.Echo().WithError(err).Warn("could not accept channel")
		return
	}
	go s.handleSessionRequests(requests, channel)
}

// The `handleUnknownChannel` function is responsible for handling incoming SSH channels with unknown
// channel types. It accepts a `ssh.NewChannel` object and rejects the channel with an "unknown channel
// type" error message.
func (s *session) handleUnknownChannel(newChannel ssh.NewChannel) {
	// log.Echo().WithField("channelType", newChannel.ChannelType()).Error("unknown channel type")
	newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
}

// The `handleDirectTcpip` function is responsible for handling incoming SSH direct-tcpip channels. It
// accepts a `ssh.NewChannel` object and performs the necessary operations to handle the direct-tcpip
// channel. This includes accepting the channel, extracting the destination and origin addresses and
// ports from the channel's extra data, dialing the local address, and managing the communication
// between the client and the server.
func (s *session) handleDirectTcpip(newChannel ssh.NewChannel) {
	var payload struct {
		DestAddr   string
		DestPort   uint32
		OriginAddr string
		OriginPort uint32
	}
	if err := ssh.Unmarshal(newChannel.ExtraData(), &payload); err != nil {
		// log.Echo().WithError(err).Error("could not unmarshal direct-tcpip request")
		_ = newChannel.Reject(ssh.ConnectionFailed, "invalid direct-tcpip payload")
		return
	}

	// s.l
	// 	"dest_addr":   payload.DestAddr,
	// 	"dest_port":   payload.DestPort,
	// 	"origin_addr": payload.OriginAddr,
	// 	"origin_port": payload.OriginPort,
	// }).Trace("direct-tcpip request")

	dest := net.JoinHostPort(payload.DestAddr, strconv.Itoa(int(payload.DestPort)))
	dialer := net.Dialer{Timeout: 10 * time.Second}
	localConn, err := dialer.Dial("tcp", dest)
	if err != nil {
		// log.Echo().WithError(err).Error("could not dial local address")
		_ = newChannel.Reject(ssh.ConnectionFailed, "failed to connect destination")
		return
	}

	channel, requests, err := newChannel.Accept()
	if err != nil {
		_ = localConn.Close()
		return
	}
	go ssh.DiscardRequests(requests)

	pipeChannelAndConn(channel, localConn)
}

// The `handleForwardedTcpip` function is responsible for handling incoming SSH forwarded-tcpip
// channels. It accepts a `ssh.NewChannel` object and performs the necessary operations to handle the
// forwarded-tcpip channel. This includes accepting the channel, extracting the destination and origin
// addresses and ports from the channel's extra data, listening on the local address, and managing the
// communication between the client and the server. It also adds a firewall rule to allow traffic on
// the specified destination port.
func (s *session) handleForwardedTcpip(newChannel ssh.NewChannel) {
	var payload struct {
		DestAddr   string
		DestPort   uint32
		OriginAddr string
		OriginPort uint32
	}
	if err := ssh.Unmarshal(newChannel.ExtraData(), &payload); err != nil {
		_ = newChannel.Reject(ssh.ConnectionFailed, "invalid forwarded-tcpip payload")
		return
	}

	dest := net.JoinHostPort(payload.DestAddr, strconv.Itoa(int(payload.DestPort)))
	dialer := net.Dialer{Timeout: 10 * time.Second}
	localConn, err := dialer.Dial("tcp", dest)
	if err != nil {
		_ = newChannel.Reject(ssh.ConnectionFailed, "failed to connect destination")
		return
	}

	channel, requests, err := newChannel.Accept()
	if err != nil {
		_ = localConn.Close()
		return
	}
	go ssh.DiscardRequests(requests)

	pipeChannelAndConn(channel, localConn)
}

// The `handleSftp` function is responsible for handling an SSH session that is used for SFTP (SSH File
// Transfer Protocol). It takes an `ssh.Channel` object as a parameter, which represents the SFTP
// session channel.
func (s *session) handleSftp(channel ssh.Channel) {
	// log.Debug("sftp session started")
	server, err := sftp.NewServer(
		channel, sftp.WithAllocator(),
	)
	if err != nil {
		// log.Echo().WithError(err).Error("could not create sftp server")
		return
	}
	if err = server.Serve(); err == io.EOF {
		err = nil
	}
	if err != nil {
		// log.Echo().WithError(err).Error("sftp server exited with error")
		return
	}
	// log.Debug("sftp session ended")
}

// The `dispatchCommand` function is responsible for executing a command received from the SSH client.
// It takes the command line as a string and a `StringWriter` interface, which is used to write the
// output of the command.
func (s *session) dispatchCommand(line string, w StringWriter) {
	args, err := shlex.Split(line, true)
	if err != nil {
		// log.Echo().WithError(err).Error("failed to split command")
		return
	}

	if len(args) == 0 {
		dumpCommands(s.commands, w)
		return
	}

	c, err := lookupCommand(s.commands, args[0])
	if err != nil {
		// log.Echo().WithError(err).Error("failed to find command")
		return
	}

	if cancel != nil {
		cancel()
	}

	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()

	if c == nil {
		if len(line) == 0 {
			dumpCommands(s.commands, w)
			return
		}

		err = s.execSystemCommand(ctx, w, line)
		if err != nil {
			// log.Echo().WithError(err).Error("failed to execute system command")
		} else {
			// log.Echo().WithField("cmd", line).Warn("executed syscall command via ssh")
		}
		return
	}

	err = execCommand(c, args[1:], w)
	if err != nil {
		// log.Echo().WithError(err).Error("failed to execute inner command")
	} else {
		// log.Echo().WithField("cmd", line).Warn("executed inner command via ssh")
	}

}

// The `Close()` function is a method of the `session` struct. It is responsible for closing the SSH
// connection and signaling the `exitChan` channel to indicate that the session has ended.
func (s *session) Close() {
	s.mu.Lock()
	for key, listener := range s.forwardedTCPPorts {
		_ = listener.Close()
		delete(s.forwardedTCPPorts, key)
	}
	for key, listener := range s.directTCPPorts {
		_ = listener.Close()
		delete(s.directTCPPorts, key)
	}
	s.mu.Unlock()

	if s.conPTY != nil {
		_ = s.conPTY.Close()
		s.conPTY = nil
	}
	if s.pty != nil {
		_ = s.pty.Close()
		s.pty = nil
	}
	if s.tty != nil {
		_ = s.tty.Close()
		s.tty = nil
	}
	s.c.Close()
	select {
	case s.exitChan <- true:
	default:
	}
}

// The `execSystemCommand` function is responsible for executing a system command received from the SSH
// client. It takes the command line as a string, a `StringWriter` interface to write the output of the
// command, and a `context.Context` object for managing the execution context.
func (s *session) execSystemCommand(ctx context.Context, w StringWriter, line string) error {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		exec.Command("cmd", "/C", "chcp 65001").Run()
		cmd = exec.CommandContext(ctx, "cmd", "/C", line)
	} else {
		cmd = exec.CommandContext(ctx, "sh", "-c", line)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = cmd.Stdout

	var wg sync.WaitGroup
	wg.Add(1)
	go func(wg *sync.WaitGroup) {
		defer wg.Done()
		stdReader := bufio.NewReader(stdout)
		for {
			select {
			case <-ctx.Done():
				if ctx.Err() != nil {
					w.WriteLine(fmt.Sprintf("Closed: %q", ctx.Err()))
					// log.Echo().WithField("cmd", line).Debug("Closed: %q", ctx.Err())
				} else {
					w.Write("Closed")
					// log.Echo().WithField("cmd", line).Debug("Closed")
				}
				return
			default:
				readString, err := stdReader.ReadString('\n')
				if err != nil || err == io.EOF {
					return
				}
				w.Write(readString)
				// log.Echo().WithField("cmd", line).Debug(readString)
			}
		}
	}(&wg)
	err = cmd.Start()
	wg.Wait()
	return err

}
