//go:build !windows
// +build !windows

package ssh

import (
	"errors"
	"os/exec"
)

func startConPTY(_ *exec.Cmd, _ uint16, _ uint16) (conPTYSession, error) {
	return nil, errors.New("conpty is only available on windows")
}
