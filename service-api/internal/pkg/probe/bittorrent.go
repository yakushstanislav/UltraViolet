package probe

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
)

const productBitTorrent = "bittorrent"

var bittorrentPstr = []byte("BitTorrent protocol")

func init() {
	Register(probeBitTorrent, 6699)
}

// probeBitTorrent sends a BEP 3 handshake and treats a matching reply as proof.
func probeBitTorrent(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialTCP(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("can't dial BitTorrent target: %w", err)
	}

	defer func() { _ = conn.Close() }()

	handshake := make([]byte, 0, 68)
	handshake = append(handshake, byte(len(bittorrentPstr)))
	handshake = append(handshake, bittorrentPstr...)
	handshake = append(handshake, make([]byte, 8)...) // reserved

	infoHash := make([]byte, 20)
	peerID := make([]byte, 20)

	_, _ = rand.Read(infoHash)
	_, _ = rand.Read(peerID)

	handshake = append(handshake, infoHash...)
	handshake = append(handshake, peerID...)

	if _, writeErr := conn.Write(handshake); writeErr != nil {
		return nil, fmt.Errorf("can't send BitTorrent handshake: %w", writeErr)
	}

	reply := make([]byte, 68)

	n, err := io.ReadFull(conn, reply)
	if err != nil || n < 20 {
		return &Result{Target: target, Protocol: protocolTCP}, nil
	}

	if reply[0] != byte(len(bittorrentPstr)) {
		return &Result{Target: target, Protocol: protocolTCP, Banner: string(reply[:min(n, 32)])}, nil
	}

	if !bytesEqual(reply[1:1+len(bittorrentPstr)], bittorrentPstr) {
		return &Result{Target: target, Protocol: protocolTCP}, nil
	}

	fp := &FingerprintResult{
		Product: productBitTorrent,
		RawJSON: mustMarshalJSON(map[string]any{
			"info_hash": hex.EncodeToString(reply[1+len(bittorrentPstr)+8 : 1+len(bittorrentPstr)+8+20]),
		}),
	}

	return &Result{
		Target:      target,
		Protocol:    productBitTorrent,
		Banner:      "BitTorrent protocol",
		Fingerprint: fp,
	}, nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}
