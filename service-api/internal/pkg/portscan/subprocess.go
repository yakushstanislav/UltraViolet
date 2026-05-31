package portscan

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"
)

// LineEmitter is what a Subprocess passes to its ParseLine callback: the
// callback parses one raw stdout line and emits zero or more OpenPort
// values through this function. Sending respects the cancellation of the
// context the Subprocess was started with.
type LineEmitter func(OpenPort)

// Subprocess is the shared scaffolding used by CLI-backed Discoverers
// (masscan, zmap, …). It owns the exec lifecycle, stderr capture, and the
// bufio.Scanner loop, leaving callers to supply the per-tool parser.
type Subprocess struct {
	// Name is the short tool label used in wrapped errors ("masscan", "zmap").
	Name string
	// Binary is the executable to run.
	Binary string
	// Args are the arguments passed to Binary.
	Args []string
	// ParseLine parses one raw stdout line and emits OpenPorts via emit.
	// It must not retain ctx beyond the call.
	ParseLine func(ctx context.Context, line string, emit LineEmitter)
}

// Run launches the subprocess and returns a Stream of OpenPorts plus a
// Wait that blocks until the process exits and reports any failure.
func (s Subprocess) Run(ctx context.Context) (*Stream, error) {
	cmd := exec.CommandContext(ctx, s.Binary, s.Args...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("can't pipe %s stdout: %w", s.Name, err)
	}

	// Cap stderr capture so a runaway masscan/zmap can't OOM the process by
	// blasting gigabytes of debug output. 1 MB keeps enough context for any
	// realistic diagnostic — the actual failure summary is always in the
	// first few KB anyway.
	stderrBuf := &cappedBuffer{cap: 1024 * 1024}

	cmd.Stderr = stderrBuf

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("can't start %s: %w", s.Name, err)
	}

	out := make(chan OpenPort, 256)

	var wg sync.WaitGroup

	wg.Add(1)

	go func() {
		defer wg.Done()
		defer close(out)

		emit := func(op OpenPort) {
			select {
			case <-ctx.Done():
			case out <- op:
			}
		}

		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

		for sc.Scan() {
			s.ParseLine(ctx, sc.Text(), emit)
		}

		_ = sc.Err()
	}()

	wait := func() error {
		wg.Wait()

		waitErr := cmd.Wait()
		if waitErr != nil {
			if msg := strings.TrimSpace(stderrBuf.String()); msg != "" {
				return fmt.Errorf("%s: %s: %w", s.Name, msg, waitErr)
			}

			return fmt.Errorf("%s failed: %w", s.Name, waitErr)
		}

		return ctx.Err()
	}

	return &Stream{Ports: out, Wait: wait}, nil
}

// cappedBuffer accepts up to cap bytes of subprocess stderr; further writes
// are silently dropped. Implements only what cmd.Stderr (io.Writer) needs.
type cappedBuffer struct {
	cap int
	buf bytes.Buffer
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if c.buf.Len() >= c.cap {
		return len(p), nil
	}

	remaining := c.cap - c.buf.Len()
	if len(p) <= remaining {
		return c.buf.Write(p)
	}

	if _, err := c.buf.Write(p[:remaining]); err != nil {
		return 0, err
	}

	return len(p), nil
}

func (c *cappedBuffer) String() string { return c.buf.String() }

// WriteIPListFile creates an OS temp file (using the given filename
// pattern, e.g. "uv-masscan-targets-*.txt") and writes the provided IPv4
// addresses one per line. It returns the file path; the caller owns the
// file and is responsible for removal.
func WriteIPListFile(pattern string, ips []netip.Addr) (string, error) {
	f, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", fmt.Errorf("can't create temp IP list: %w", err)
	}

	w := strings.Builder{}

	for _, ip := range ips {
		w.WriteString(ip.String())
		w.WriteByte('\n')
	}

	if _, err := f.WriteString(w.String()); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())

		return "", fmt.Errorf("can't write IP list: %w", err)
	}

	if err := f.Close(); err != nil {
		_ = os.Remove(f.Name())

		return "", fmt.Errorf("can't close IP list: %w", err)
	}

	return f.Name(), nil
}
