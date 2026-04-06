package ssh

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"sync"

	"aps/endpoint/utils/ssh/radix"

	"golang.org/x/crypto/ssh"
)

// The SSH type represents a server that handles SSH connections and commands.
// @property config - A pointer to an instance of the ssh.ServerConfig struct, which contains the
// server's configuration settings.
// @property l - The "l" property is a logger object that is used for logging messages and events in
// the SSH server.
// @property trustedKeys - The `trustedKeys` property is a map that stores the authorized keys for each
// user. It is a nested map where the outer map's key is the username and the inner map's key is the
// authorized key string. The inner map's value is a boolean indicating whether the key is trusted or
// not
// @property commands - The `commands` property is a radix tree that stores the available commands for
// the SSH server. A radix tree, also known as a Patricia trie, is a data structure that allows
// efficient storage and retrieval of key-value pairs. In this case, the keys are the command names and
// the values are the
// @property listener - The `listener` property is a `net.Listener` object that represents the network
// listener for the SSH server. It is responsible for accepting incoming connections and creating new
// sessions for each connection.
// @property connsLock - connsLock is a mutex that is used to lock the conns map and the counter to
// avoid concurrent map access. It ensures that only one goroutine can access the conns map or modify
// the counter at a time, preventing any race conditions.
// @property conns - A map that stores active SSH connections. The key is an integer representing the
// connection ID, and the value is a pointer to a session object.
// @property {int} counter - The `counter` property is an integer that keeps track of the number of
// connections made to the SSH server. It is used to assign a unique identifier to each connection.
type SSH struct {
	config *ssh.ServerConfig

	// Map of user -> authorized keys
	trustedKeys map[string]map[string]bool
	// Map of user -> password
	trustedPasswords map[string]string
	trustedKeysLock  sync.RWMutex

	// List of available commands
	// helpCommand *Command
	commands *radix.Tree
	listener net.Listener

	// Locks the conns/counter to avoid concurrent map access
	connsLock sync.Mutex
	conns     map[int]*session
	counter   int
}

// NewServer Create a new ssh server rigged with default commands and prepares to listen
func NewServer() (*SSH, error) {
	s := &SSH{
		trustedKeys:      make(map[string]map[string]bool),
		trustedPasswords: make(map[string]string),
		commands:         radix.New(),
		conns:            make(map[int]*session),
	}

	s.config = &ssh.ServerConfig{
		PasswordCallback:  s.matchPassword,
		PublicKeyCallback: s.matchPubKey,
		//TODO: AuthLogCallback: s.authAttempt,
		//TODO: version string
		ServerVersion: "SSH-2.0-APS",
	}

	s.RegisterCommand(&Command{
		Name:             "help",
		ShortDescription: "prints available commands or help <command> for specific usage info",
		Callback: func(a any, args []string, w StringWriter) error {
			return helpCallback(s.commands, args, w)
		},
	})

	return s, nil
}

// The `SetHostKey` function is used to set the host key for the SSH server. The host key is a
// cryptographic key pair that is used to authenticate the server to the client during the SSH
// handshake process.
func (s *SSH) SetHostKey(pointPrivateKey []byte) error {
	private, err := ssh.ParsePrivateKey(pointPrivateKey)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %s", err)
	}

	s.config.AddHostKey(private)
	return nil
}

// ClearAuthorizedKeys clears the authorized keys for the SSHServer.
//
// It takes no parameters.
// It does not return anything.
func (s *SSH) ClearAuthorizedKeys() {
	s.trustedKeysLock.Lock()
	defer s.trustedKeysLock.Unlock()
	s.trustedKeys = make(map[string]map[string]bool)
}

// ClearAuthorizedPasswords clears configured password credentials.
func (s *SSH) ClearAuthorizedPasswords() {
	s.trustedKeysLock.Lock()
	defer s.trustedKeysLock.Unlock()
	s.trustedPasswords = make(map[string]string)
}

// AddAuthorizedKey adds a ssh public key for a user
func (s *SSH) AddAuthorizedKey(user, pubKey string) error {
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubKey))
	if err != nil {
		return err
	}

	s.trustedKeysLock.Lock()
	defer s.trustedKeysLock.Unlock()

	tk, ok := s.trustedKeys[user]
	if !ok {
		tk = make(map[string]bool)
		s.trustedKeys[user] = tk
	}

	tk[string(pk.Marshal())] = true
	// log.Echo().WithField("key", pubKey[:25]+"..."+pubKey[len(pubKey)-25:]).WithField("user", user).Warn("Authorized ssh key")
	return nil
}

// SetAuthorizedPassword sets password authentication for a user.
func (s *SSH) SetAuthorizedPassword(user, password string) {
	s.trustedKeysLock.Lock()
	defer s.trustedKeysLock.Unlock()
	s.trustedPasswords[user] = password
}

// DeleteUser removes a user from the authorized keys
func (s *SSH) DeleteUser(user string) {
	s.trustedKeysLock.Lock()
	defer s.trustedKeysLock.Unlock()
	delete(s.trustedKeys, user)
	delete(s.trustedPasswords, user)
	// log.Echo().WithField("user", user).Warn("Deleted ssh user")
}

// RegisterCommand adds a command that can be run by a user, by default only `help` is available
func (s *SSH) RegisterCommand(c *Command) {
	s.commands.Insert(c.Name, c)
}

// Run begins listening and accepting connections
func (s *SSH) Run(addr string) error {
	var err error
	s.listener, err = net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	// log.Echo().WithField("listen", addr).Info("SSH server is listening")

	// Run loops until there is an error
	s.run()
	s.closeSessions()

	// log.Info("SSH server stopped listening")
	// We don't return an error because run logs for us
	return nil
}

// The `run()` function is responsible for accepting incoming SSH connections and creating new sessions
// for each connection. It runs in a loop and listens for new connections using the `Accept()` method
// of the `net.Listener` object. Once a new connection is accepted, it performs the SSH handshake and
// creates a new session object to handle the connection. The session object is then added to the
// `conns` map, which stores active SSH connections. Finally, the function spawns goroutines to handle
// requests and close the session when it is finished.
func (s *SSH) run() {
	for {
		c, err := s.listener.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				// log.Echo().WithError(err).Warn("Error in listener, shutting down")
			}
			return
		}

		conn, chans, reqs, err := ssh.NewServerConn(c, s.config)
		fp := ""
		if conn != nil {
			fp = conn.Permissions.Extensions["fp"]
		}

		if err != nil {
			// l := log.Echo().WithError(err).WithField("from", c.RemoteAddr())
			if conn != nil {
				// l = l.Echo().WithField("user", conn.User())
				_ = conn.Close()
			}
			if fp != "" {
				// l = l.Echo().WithField("fingerprint", fp)
			}
			// l.Warn("Failed to handshake")
			continue
		}

		// l := log.Echo().WithField("user", conn.User()).WithField("from", c.RemoteAddr().String())
		// l.Echo().WithField("fingerprint", fp).Warn("User logged in ssh")

		session := NewSession(s.commands, conn, chans)
		s.connsLock.Lock()
		s.counter++
		counter := s.counter
		s.conns[counter] = session
		s.connsLock.Unlock()

		go session.handleGlobalRequests(reqs)
		go func() {
			<-session.exitChan
			// log.Echo().WithField("id", counter).Debug("Closing conn")
			s.connsLock.Lock()
			delete(s.conns, counter)
			s.connsLock.Unlock()
		}()
	}
}

// The `Stop()` function is used to stop the SSH server. It closes the listener, which causes all
// sessions to terminate as well. This function is called when the SSH server needs to be shut down or
// stopped.
func (s *SSH) Stop() {
	// Close the listener, this will cause all session to terminate as well, see SSHServer.Run
	if s.listener != nil {
		if err := s.listener.Close(); err != nil {
			// log.Echo().WithError(err).Warn("Failed to close the ssh listener")
		}
	}
}

// The `closeSessions()` function is used to close all active SSH sessions in the SSH server. It
// iterates over the `conns` map, which stores active SSH connections, and calls the `Close()` method
// on each session object to terminate the session. This function is typically called when the SSH
// server needs to be stopped or shut down.
func (s *SSH) closeSessions() {
	s.connsLock.Lock()
	for _, c := range s.conns {
		c.Close()
	}
	s.connsLock.Unlock()
}

// The `matchPubKey` function is a callback function that is used to match and validate the public key
// provided by the client during the SSH handshake process. It takes two parameters: `c
// ssh.ConnMetadata`, which contains metadata about the SSH connection, and `pubKey ssh.PublicKey`,
// which is the public key provided by the client.
func (s *SSH) matchPubKey(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
	pk := string(pubKey.Marshal())
	fp := ssh.FingerprintSHA256(pubKey)

	s.trustedKeysLock.RLock()
	defer s.trustedKeysLock.RUnlock()

	tk, ok := s.trustedKeys[c.User()]
	if !ok {
		return nil, fmt.Errorf("unknown user %s", c.User())
	}

	_, ok = tk[pk]
	if !ok {
		return nil, fmt.Errorf("unknown public key for %s (%s)", c.User(), fp)
	}

	return &ssh.Permissions{
		// Record the public key used for authentication.
		Extensions: map[string]string{
			"fp":   fp,
			"user": c.User(),
		},
	}, nil
}

// The `matchPassword` function validates password login against configured SSH users.
func (s *SSH) matchPassword(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
	s.trustedKeysLock.RLock()
	expected, ok := s.trustedPasswords[c.User()]
	s.trustedKeysLock.RUnlock()
	if !ok {
		return nil, fmt.Errorf("unknown user %s", c.User())
	}
	if subtle.ConstantTimeCompare([]byte(expected), pass) != 1 {
		return nil, fmt.Errorf("invalid password for %s", c.User())
	}

	return &ssh.Permissions{
		Extensions: map[string]string{
			"user": c.User(),
		},
	}, nil
}
