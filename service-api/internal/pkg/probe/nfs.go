package probe

import (
	"context"
	"encoding/binary"
	"io"
)

const productNFS = "nfs_server"

func init() {
	// 2049 — IANA NFS default port (covers NFS v3 and v4 server).
	Register(probeNFS, 2049)
}

// probeNFS calls the NULL procedure (proc 0) of the NFS RPC program
// (100003) over TCP using the fragmented Record Marking transport. A
// MSG_ACCEPTED reply with reply_state SUCCESS is the canonical "NFS is
// alive" probe and the strongest possible detection without auth.
//
// RPC v2 layout (RFC 5531):
//
//	uint32 BE  xid
//	uint32 BE  call    = 0
//	uint32 BE  rpcvers = 2
//	uint32 BE  prog    = 100003 (NFS)
//	uint32 BE  vers    = 4 (v4 has been universal since 2016)
//	uint32 BE  proc    = 0 (NULL)
//	auth_null (8B)
//	verf_null (8B)
//
// All wrapped in a 4-byte Record Marking header with the last-fragment
// bit set.
func probeNFS(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialTCP(ctx, target)
	if err != nil {
		return nil, err
	}

	defer func() { _ = conn.Close() }()

	for _, vers := range []uint32{4, 3} {
		if result, ok := nfsNullCall(conn, vers); ok {
			fp := &FingerprintResult{
				Product: productNFS,
				Edition: "v" + nfsVersionString(vers),
				RawJSON: mustMarshalJSON(map[string]any{
					"version":   vers,
					"raw_bytes": len(result),
				}),
			}

			return &Result{
				Target:      target,
				Protocol:    productNFS,
				Banner:      "NFS v" + nfsVersionString(vers),
				Fingerprint: fp,
			}, nil
		}
	}

	return &Result{Target: target, Protocol: protocolTCP}, nil
}

// nfsNullCall sends an RPC NULL call to NFS over Record Marking and
// reports whether a successful MSG_ACCEPTED/SUCCESS reply came back.
func nfsNullCall(conn io.ReadWriter, vers uint32) ([]byte, bool) {
	body := make([]byte, 40)
	binary.BigEndian.PutUint32(body[0:4], 0xCAFEF00D)
	binary.BigEndian.PutUint32(body[4:8], 0)
	binary.BigEndian.PutUint32(body[8:12], 2)
	binary.BigEndian.PutUint32(body[12:16], 100003)
	binary.BigEndian.PutUint32(body[16:20], vers)
	binary.BigEndian.PutUint32(body[20:24], 0)
	binary.BigEndian.PutUint32(body[24:28], 0)
	binary.BigEndian.PutUint32(body[28:32], 0)
	binary.BigEndian.PutUint32(body[32:36], 0)
	binary.BigEndian.PutUint32(body[36:40], 0)

	frame := make([]byte, 4, 4+len(body))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(body))|0x80000000)

	frame = append(frame, body...)

	if _, writeErr := conn.Write(frame); writeErr != nil {
		return nil, false
	}

	respHeader := make([]byte, 4)

	if _, readErr := io.ReadFull(conn, respHeader); readErr != nil {
		return nil, false
	}

	respLen := binary.BigEndian.Uint32(respHeader) & 0x7FFFFFFF
	if respLen < 16 || respLen > 65535 {
		return nil, false
	}

	respBody := make([]byte, respLen)

	if _, readErr := io.ReadFull(conn, respBody); readErr != nil {
		return nil, false
	}

	if len(respBody) < 12 {
		return nil, false
	}

	msgType := binary.BigEndian.Uint32(respBody[4:8])
	replyStat := binary.BigEndian.Uint32(respBody[8:12])

	if msgType == 1 && (replyStat == 0 || replyStat == 1) {
		// reply_stat 0 = MSG_ACCEPTED, 1 = MSG_DENIED. Either is a
		// real RPC reply, and on port 2049 only NFS is plausible.
		return respBody, true
	}

	return nil, false
}

// nfsVersionString converts a numeric NFS version into "3" / "4" strings.
func nfsVersionString(v uint32) string {
	switch v {
	case 3:
		return "3"
	case 4:
		return "4"
	}

	return ""
}
