//go:build windows
// +build windows

package ssh

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

type windowsConPTY struct {
	inWriter  *os.File
	outReader *os.File
	ptyIn     windows.Handle
	ptyOut    windows.Handle
	pseudo    windows.Handle
	process   windows.Handle
	closeOnce sync.Once
}

func (c *windowsConPTY) Read(p []byte) (int, error) {
	return c.outReader.Read(p)
}

func (c *windowsConPTY) Write(p []byte) (int, error) {
	return c.inWriter.Write(p)
}

func (c *windowsConPTY) Wait() error {
	if c.process == 0 {
		return io.ErrClosedPipe
	}
	_, err := windows.WaitForSingleObject(c.process, windows.INFINITE)
	return err
}

func (c *windowsConPTY) Close() error {
	var firstErr error
	c.closeOnce.Do(func() {
		if c.inWriter != nil {
			if err := c.inWriter.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		if c.outReader != nil {
			if err := c.outReader.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		if c.ptyIn != 0 {
			if err := windows.CloseHandle(c.ptyIn); err != nil && firstErr == nil {
				firstErr = err
			}
			c.ptyIn = 0
		}
		if c.ptyOut != 0 {
			if err := windows.CloseHandle(c.ptyOut); err != nil && firstErr == nil {
				firstErr = err
			}
			c.ptyOut = 0
		}
		if c.pseudo != 0 {
			windows.ClosePseudoConsole(c.pseudo)
			c.pseudo = 0
		}
		if c.process != 0 {
			if err := windows.CloseHandle(c.process); err != nil && firstErr == nil {
				firstErr = err
			}
			c.process = 0
		}
	})
	return firstErr
}

func (c *windowsConPTY) Resize(cols, rows uint16) error {
	if cols == 0 {
		cols = 120
	}
	if rows == 0 {
		rows = 30
	}
	if c.pseudo == 0 {
		return io.ErrClosedPipe
	}
	coord := windows.Coord{
		X: int16(cols),
		Y: int16(rows),
	}
	return windows.ResizePseudoConsole(c.pseudo, coord)
}

func startConPTY(cmd *exec.Cmd, cols uint16, rows uint16) (conPTYSession, error) {
	if cmd == nil {
		return nil, errors.New("nil command")
	}

	if cols == 0 {
		cols = 120
	}
	if rows == 0 {
		rows = 30
	}

	cmdLine, err := composeConPTYCommandLine(cmd)
	if err != nil {
		return nil, err
	}

	var inRead, inWrite windows.Handle
	if err := windows.CreatePipe(&inRead, &inWrite, nil, 0); err != nil {
		return nil, fmt.Errorf("create conpty input pipe: %w", err)
	}
	var outRead, outWrite windows.Handle
	if err := windows.CreatePipe(&outRead, &outWrite, nil, 0); err != nil {
		_ = windows.CloseHandle(inRead)
		_ = windows.CloseHandle(inWrite)
		return nil, fmt.Errorf("create conpty output pipe: %w", err)
	}

	coord := windows.Coord{X: int16(cols), Y: int16(rows)}
	var pseudo windows.Handle
	if err := windows.CreatePseudoConsole(coord, inRead, outWrite, 0, &pseudo); err != nil {
		_ = windows.CloseHandle(inRead)
		_ = windows.CloseHandle(inWrite)
		_ = windows.CloseHandle(outRead)
		_ = windows.CloseHandle(outWrite)
		return nil, fmt.Errorf("create pseudoconsole: %w", err)
	}

	attrList, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		windows.ClosePseudoConsole(pseudo)
		_ = windows.CloseHandle(inRead)
		_ = windows.CloseHandle(inWrite)
		_ = windows.CloseHandle(outRead)
		_ = windows.CloseHandle(outWrite)
		return nil, fmt.Errorf("create proc thread attribute list: %w", err)
	}
	defer attrList.Delete()

	if err := attrList.Update(
		windows.PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
		unsafe.Pointer(pseudo),
		unsafe.Sizeof(pseudo),
	); err != nil {
		windows.ClosePseudoConsole(pseudo)
		_ = windows.CloseHandle(inRead)
		_ = windows.CloseHandle(inWrite)
		_ = windows.CloseHandle(outRead)
		_ = windows.CloseHandle(outWrite)
		return nil, fmt.Errorf("update pseudoconsole proc attribute: %w", err)
	}

	var si windows.StartupInfoEx
	si.Cb = uint32(unsafe.Sizeof(si))
	si.ProcThreadAttributeList = attrList.List()

	cmdLinePtr, err := windows.UTF16PtrFromString(cmdLine)
	if err != nil {
		windows.ClosePseudoConsole(pseudo)
		_ = windows.CloseHandle(inRead)
		_ = windows.CloseHandle(inWrite)
		_ = windows.CloseHandle(outRead)
		_ = windows.CloseHandle(outWrite)
		return nil, fmt.Errorf("encode command line: %w", err)
	}

	var cwdPtr *uint16
	if cmd.Dir != "" {
		cwdPtr, err = windows.UTF16PtrFromString(cmd.Dir)
		if err != nil {
			windows.ClosePseudoConsole(pseudo)
			_ = windows.CloseHandle(inRead)
			_ = windows.CloseHandle(inWrite)
			_ = windows.CloseHandle(outRead)
			_ = windows.CloseHandle(outWrite)
			return nil, fmt.Errorf("encode cwd: %w", err)
		}
	}

	var pi windows.ProcessInformation
	creationFlags := uint32(windows.EXTENDED_STARTUPINFO_PRESENT)
	if err := windows.CreateProcess(
		nil,
		cmdLinePtr,
		nil,
		nil,
		false,
		creationFlags,
		nil,
		cwdPtr,
		&si.StartupInfo,
		&pi,
	); err != nil {
		windows.ClosePseudoConsole(pseudo)
		_ = windows.CloseHandle(inRead)
		_ = windows.CloseHandle(inWrite)
		_ = windows.CloseHandle(outRead)
		_ = windows.CloseHandle(outWrite)
		return nil, fmt.Errorf("start conpty process: %w", err)
	}
	_ = windows.CloseHandle(pi.Thread)

	return &windowsConPTY{
		inWriter:  os.NewFile(uintptr(inWrite), "conpty-in"),
		outReader: os.NewFile(uintptr(outRead), "conpty-out"),
		ptyIn:     inRead,
		ptyOut:    outWrite,
		pseudo:    pseudo,
		process:   pi.Process,
	}, nil
}

func composeConPTYCommandLine(cmd *exec.Cmd) (string, error) {
	args := cmd.Args
	if len(args) == 0 {
		if cmd.Path == "" {
			return "", errors.New("empty command path")
		}
		args = []string{cmd.Path}
	}
	return windows.ComposeCommandLine(args), nil
}
