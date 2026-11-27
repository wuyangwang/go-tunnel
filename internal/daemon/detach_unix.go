//go:build !windows

package daemon

import (
	"os"
	"os/exec"
	"syscall"
)

// detach puts the child in a new session so it survives parent exit.
func detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}

// signalStop asks the process to terminate gracefully.
func signalStop(p *os.Process) error {
	return p.Signal(syscall.SIGTERM)
}

// alivePID reports whether pid is a live process.
func alivePID(pid int) bool {
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return p.Signal(syscall.Signal(0)) == nil
}
