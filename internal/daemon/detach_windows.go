//go:build windows

package daemon

import (
	"os"
	"os/exec"
	"syscall"
)

const (
	detachedProcess                = 0x00000008
	processQueryLimitedInformation = 0x00001000
	stillActive                    = 259
)

// detach starts the child detached from the console.
func detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP | detachedProcess,
	}
}

// signalStop terminates the process. Windows has no SIGTERM delivery to
// Go programs, so this is a hard kill.
func signalStop(p *os.Process) error {
	return p.Kill()
}

// alivePID reports whether pid is a live process.
func alivePID(pid int) bool {
	h, err := syscall.OpenProcess(processQueryLimitedInformation, false, uint32(pid))
	if err != nil {
		return false
	}
	defer syscall.CloseHandle(h)
	var code uint32
	if err := syscall.GetExitCodeProcess(h, &code); err != nil {
		return false
	}
	return code == stillActive
}
