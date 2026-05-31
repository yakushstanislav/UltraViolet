package probe

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
)

func init() {
	// 22 — IANA-assigned SSH.
	// 2222 — most common alt port (DirectAdmin, OpenWrt, GitLab SSH, IoT).
	Register(probeSSH, 22, 2222)
}

// probeSSH connects to the target, captures the server version string, host
// key fingerprint and kex algorithms via an SSH handshake. Authentication is
// expected to fail; the host key callback fires before auth so the key is
// captured regardless of the auth outcome.
func probeSSH(ctx context.Context, s *Stack, target Target) (*Result, error) {
	tcpConn, err := s.dialTCP(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("can't dial SSH target: %w", err)
	}

	defer func() { _ = tcpConn.Close() }()

	rec := &sshRecordingConn{Conn: tcpConn}

	var capturedKey ssh.PublicKey

	sshCfg := &ssh.ClientConfig{
		User: "probe",
		Auth: []ssh.AuthMethod{ssh.Password("")},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			capturedKey = key

			return nil
		},
	}

	// Auth failure is expected and intentional — the key exchange (and
	// therefore HostKeyCallback) completes before authentication.
	_, _, _, _ = ssh.NewClientConn(rec, target.IP.String(), sshCfg)

	recorded := rec.bytes()

	serverVersion := sshParseVersionString(recorded)

	result := &Result{
		Target:   target,
		Protocol: "ssh",
		Banner:   serverVersion,
	}

	if !strings.HasPrefix(serverVersion, "SSH-") {
		return result, nil
	}

	kexAlgs, hostKeyAlgs := sshParseKexInit(recorded)

	sshInfo := &SSHResult{
		ServerVersion:     serverVersion,
		KexAlgorithms:     kexAlgs,
		HostKeyAlgorithms: hostKeyAlgs,
	}

	if capturedKey != nil {
		sshInfo.HostKeyType = capturedKey.Type()
		sshInfo.HostKeyFingerprint = ssh.FingerprintSHA256(capturedKey)
	}

	result.SSH = sshInfo

	return result, nil
}

// sshRecordingConn wraps a net.Conn and buffers every byte read from the
// remote side so we can parse SSH packets after the library handshake.
type sshRecordingConn struct {
	net.Conn
	mu  sync.Mutex
	buf bytes.Buffer
}

func (r *sshRecordingConn) Read(b []byte) (int, error) {
	n, err := r.Conn.Read(b)

	if n > 0 {
		r.mu.Lock()
		r.buf.Write(b[:n])
		r.mu.Unlock()
	}

	return n, err
}

func (r *sshRecordingConn) bytes() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()

	out := make([]byte, r.buf.Len())
	copy(out, r.buf.Bytes())

	return out
}

// sshParseVersionString returns the server's version string (first line of
// the SSH exchange, stripped of the trailing CR/LF).
func sshParseVersionString(data []byte) string {
	idx := bytes.IndexByte(data, '\n')
	if idx < 0 {
		return strings.TrimRight(string(data), "\r\n")
	}

	return strings.TrimRight(string(data[:idx]), "\r")
}

// sshParseKexInit extracts kex_algorithms and server_host_key_algorithms from
// the server's SSH_MSG_KEXINIT binary packet in the raw recorded bytes.
func sshParseKexInit(data []byte) ([]string, []string) {
	// Skip the version string line.
	idx := bytes.IndexByte(data, '\n')
	if idx < 0 {
		return nil, nil
	}

	data = data[idx+1:]

	// SSH binary packet: uint32 packet_length, byte padding_length, payload...
	if len(data) < 6 {
		return nil, nil
	}

	pktLen := int(binary.BigEndian.Uint32(data[0:4]))
	if pktLen < 1 || len(data) < 4+pktLen {
		return nil, nil
	}

	padLen := int(data[4])
	payloadEnd := 4 + pktLen - padLen

	if payloadEnd > len(data) || payloadEnd < 6 {
		return nil, nil
	}

	payload := data[5:payloadEnd]

	// SSH_MSG_KEXINIT = 20; skip msg type (1 byte) + cookie (16 bytes).
	if len(payload) < 17 || payload[0] != 20 {
		return nil, nil
	}

	kexAlgs, rest := sshParseNameList(payload[17:])
	hostKeyAlgs, _ := sshParseNameList(rest)

	return kexAlgs, hostKeyAlgs
}

// sshParseNameList decodes one SSH name-list (uint32 length + comma-separated
// ASCII) and returns the entries alongside the unconsumed tail of data.
func sshParseNameList(data []byte) ([]string, []byte) {
	if len(data) < 4 {
		return nil, data
	}

	n := int(binary.BigEndian.Uint32(data[0:4]))
	data = data[4:]

	if len(data) < n {
		return nil, data
	}

	list := string(data[:n])
	data = data[n:]

	if list == "" {
		return nil, data
	}

	return strings.Split(list, ","), data
}
