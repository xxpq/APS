package ssh

import (
	"context"

	"aps/endpoint/utils/ssh/radix"

	"golang.org/x/crypto/ssh"
)

var (
	ctx    context.Context
	cancel context.CancelFunc
)

// The function creates a new session for handling SSH connections and channels.
func NewSession(commands *radix.Tree, conn *ssh.ServerConn, chans <-chan ssh.NewChannel) *session {
	s := &session{
		commands: commands,
		c:        conn,
		exitChan: make(chan bool, 1),
	}

	if err := s.initPty(); err != nil {
		s.ptyInitErr = err
	}

	go s.handleChannels(chans)
	return s
}
