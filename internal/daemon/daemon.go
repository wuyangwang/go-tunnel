// Package daemon implements simple background process management for
// the GoTunnel binaries: start, stop, restart, status and log.
//
// PID files and logs live in ~/.gotunnel/<binary-name>.{pid,log}.
// The child process runs the normal binary with stdout/stderr appended
// to the log file, detached from the terminal.
package daemon

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Manager manages one named binary.
type Manager struct {
	Name    string
	Dir     string
	PIDFile string
	LogFile string
}

// New creates a Manager for name, creating ~/.gotunnel if needed.
func New(name string) (*Manager, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(home, ".gotunnel")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Manager{
		Name:    name,
		Dir:     dir,
		PIDFile: filepath.Join(dir, name+".pid"),
		LogFile: filepath.Join(dir, name+".log"),
	}, nil
}

// IsCommand reports whether s is a daemon subcommand.
func IsCommand(s string) bool {
	switch s {
	case "start", "stop", "restart", "status", "log", "logs":
		return true
	}
	return false
}

// Handle runs a daemon subcommand. args are extra arguments after the
// subcommand (passed through to the child on start/restart; -f on log).
func (m *Manager) Handle(cmd string, args []string) error {
	switch cmd {
	case "start":
		return m.Start(args)
	case "stop":
		return m.Stop()
	case "restart":
		_ = m.Stop()
		return m.Start(args)
	case "status":
		return m.Status()
	case "log", "logs":
		follow := false
		for _, a := range args {
			if a == "-f" || a == "--follow" {
				follow = true
			}
		}
		return m.Log(follow)
	default:
		return fmt.Errorf("unknown daemon command %q", cmd)
	}
}

// Start launches the binary detached with args and records its PID.
func (m *Manager) Start(args []string) error {
	if pid, ok := m.readPID(); ok && alivePID(pid) {
		return fmt.Errorf("%s already running (pid %d)", m.Name, pid)
	}

	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(exe, args...)
	detach(cmd)

	logFile, err := os.OpenFile(m.LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer logFile.Close()
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Stdin = nil

	if err := cmd.Start(); err != nil {
		return err
	}
	pid := cmd.Process.Pid
	if err := os.WriteFile(m.PIDFile, []byte(strconv.Itoa(pid)), 0o600); err != nil {
		return err
	}
	fmt.Printf("%s started (pid %d). log: %s\n", m.Name, pid, m.LogFile)
	return nil
}

// Stop stops a running instance.
func (m *Manager) Stop() error {
	pid, ok := m.readPID()
	if !ok {
		return fmt.Errorf("%s is not running (no pid file)", m.Name)
	}
	if !alivePID(pid) {
		_ = os.Remove(m.PIDFile)
		return fmt.Errorf("%s is not running (stale pid %d)", m.Name, pid)
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	if err := signalStop(proc); err != nil {
		return err
	}
	_ = os.Remove(m.PIDFile)
	fmt.Printf("%s stopped (pid %d)\n", m.Name, pid)
	return nil
}

// Status prints whether the binary is running.
func (m *Manager) Status() error {
	pid, ok := m.readPID()
	if !ok || !alivePID(pid) {
		fmt.Printf("%s is not running\n", m.Name)
		return nil
	}
	fmt.Printf("%s is running (pid %d)\n", m.Name, pid)
	return nil
}

// Log prints the log file; if follow is true, keeps printing appended data.
func (m *Manager) Log(follow bool) error {
	f, err := os.Open(m.LogFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("no log file yet: %s", m.LogFile)
		}
		return err
	}
	defer f.Close()
	if _, err := io.Copy(os.Stdout, f); err != nil {
		return err
	}
	if !follow {
		return nil
	}
	buf := make([]byte, 64*1024)
	for {
		n, err := f.Read(buf)
		if n > 0 {
			_, _ = os.Stdout.Write(buf[:n])
		}
		if err != nil && err != io.EOF {
			return err
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func (m *Manager) readPID() (int, bool) {
	data, err := os.ReadFile(m.PIDFile)
	if err != nil || len(strings.TrimSpace(string(data))) == 0 {
		return 0, false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	return pid, err == nil && pid > 0
}
