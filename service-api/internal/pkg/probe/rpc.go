package probe

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"time"
)

const (
	productSunRPC = "sunrpc"
	productMSRPC  = "msrpc"
	productRstatd = "rstatd"
)

func init() {
	// 111 — SunRPC / rpcbind / portmapper. Universally present on AIX,
	// Solaris and Linux NFS hosts; the DUMP procedure (#4) returns the
	// list of locally registered RPC programs, which is a goldmine for
	// downstream CVE matching (NFS, NIS, statd, lockd, mountd, …).
	Register(probeSunRPC, 111)

	// 135 — Microsoft RPC endpoint mapper (epmapper). Returned by every
	// Windows host since NT 4.0. The static endpoints in the 1025–1027
	// and 49152–49158 ranges are the most common DCOM/RPCSS sub-services
	// (svchost, lsass, services.exe, eventlog). 32768–32771 cover the
	// Solaris / Linux glibc dynamic RPC range, which still speaks the
	// ONC-RPC dialect probeSunRPC handles. Registering both probes makes
	// "open TCP port on Windows" and "open TCP port on Solaris" yield a
	// product fingerprint instead of a generic banner.
	Register(probeMSRPC, 135, 1025, 1026, 1027, 49155, 49156, 49157, 49158)
	Register(probeSunRPC, 32768, 32769, 32770, 32771)

	// 1110 — rstatd (ONC-RPC program 100001). Port 4045 is probed as rsync.
	Register(probeRstatd, 1110)
}

// ---------------------------------------------------------------------------
// SunRPC / rpcbind portmapper (port 111, RFC 1833).
//
// Wire format (record-marked over TCP, RFC 5531):
//
//	[ 4-byte record marker: high bit = "last fragment" | length ]
//	[ XID                                                   ]
//	[ MSG_TYPE (0 = CALL)                                   ]
//	[ RPC_VERSION (2)                                       ]
//	[ PROGRAM   (100000 = portmapper)                       ]
//	[ VERSION   (2)                                         ]
//	[ PROCEDURE (4 = PMAPPROC_DUMP)                         ]
//	[ AUTH_NULL  flavor=0 length=0                          ]
//	[ AUTH_NULL  flavor=0 length=0  (verifier)              ]
//
// The reply carries an XDR-encoded linked list of (program, version,
// protocol, port) tuples — we don't decode it fully, we just confirm the
// reply shape and count tuples for the fingerprint payload.
// ---------------------------------------------------------------------------

func probeSunRPC(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialTCP(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("can't dial SunRPC target: %w", err)
	}

	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(s.probeTimeout(ctx)))

	if _, writeErr := conn.Write(sunrpcPortmapDumpCall()); writeErr != nil {
		return nil, fmt.Errorf("can't send portmap DUMP: %w", writeErr)
	}

	header := make([]byte, 4)
	if _, readErr := io.ReadFull(conn, header); readErr != nil {
		return &Result{Target: target, Protocol: protocolTCP}, nil
	}

	length := int(binary.BigEndian.Uint32(header) & 0x7FFFFFFF)
	if length < 24 || length > 1<<20 {
		return &Result{Target: target, Protocol: protocolTCP}, nil
	}

	body := make([]byte, length)
	if _, readErr := io.ReadFull(conn, body); readErr != nil {
		return &Result{Target: target, Protocol: protocolTCP}, nil
	}

	if !sunrpcIsAcceptedReply(body) {
		return &Result{Target: target, Protocol: protocolTCP, Banner: hex.EncodeToString(body[:min(len(body), 64)])}, nil
	}

	programs := sunrpcParseDump(body)

	fp := &FingerprintResult{
		Product: productSunRPC,
		RawJSON: mustMarshalJSON(map[string]any{
			"programs": programs,
			"count":    len(programs),
		}),
	}

	return &Result{
		Target:      target,
		Protocol:    productSunRPC,
		Banner:      "rpcbind portmapper",
		Fingerprint: fp,
	}, nil
}

func probeRstatd(ctx context.Context, s *Stack, target Target) (*Result, error) {
	return probeSunRPCNull(ctx, s, target, 100001, []uint32{3, 2, 1}, productRstatd, "rpc.rstatd")
}

// probeSunRPCNull issues RPC NULL (procedure 0) against a fixed program and
// treats MSG_ACCEPTED as proof the service is listening.
func probeSunRPCNull(
	ctx context.Context,
	s *Stack,
	target Target,
	program uint32,
	versions []uint32,
	product string,
	banner string,
) (*Result, error) {
	for _, vers := range versions {
		conn, err := s.dialTCP(ctx, target)
		if err != nil {
			return nil, fmt.Errorf("can't dial SunRPC service target: %w", err)
		}

		_ = conn.SetDeadline(time.Now().Add(s.probeTimeout(ctx)))

		accepted := sunrpcNullExchange(conn, program, vers)

		_ = conn.Close()

		if !accepted {
			continue
		}

		fp := &FingerprintResult{
			Product: product,
			Edition: "v" + nfsVersionString(vers),
			RawJSON: mustMarshalJSON(map[string]any{
				"program": program,
				"version": vers,
			}),
		}

		return &Result{
			Target:      target,
			Protocol:    product,
			Banner:      banner,
			Fingerprint: fp,
		}, nil
	}

	return &Result{Target: target, Protocol: protocolTCP}, nil
}

func sunrpcNullExchange(conn io.ReadWriter, program, version uint32) bool {
	if _, writeErr := conn.Write(sunrpcNullCall(program, version)); writeErr != nil {
		return false
	}

	header := make([]byte, 4)
	if _, readErr := io.ReadFull(conn, header); readErr != nil {
		return false
	}

	length := int(binary.BigEndian.Uint32(header) & 0x7FFFFFFF)
	if length < 24 || length > 1<<20 {
		return false
	}

	body := make([]byte, length)
	if _, readErr := io.ReadFull(conn, body); readErr != nil {
		return false
	}

	return sunrpcIsAcceptedReply(body)
}

func sunrpcNullCall(program, version uint32) []byte {
	const (
		xid             = 0x55564100
		msgTypeCall     = 0
		rpcVersion      = 2
		procedureNull   = 0
		authFlavorNull  = 0
		authLengthEmpty = 0
	)

	payload := make([]byte, 0, 44)
	payload = binary.BigEndian.AppendUint32(payload, xid)
	payload = binary.BigEndian.AppendUint32(payload, msgTypeCall)
	payload = binary.BigEndian.AppendUint32(payload, rpcVersion)
	payload = binary.BigEndian.AppendUint32(payload, program)
	payload = binary.BigEndian.AppendUint32(payload, version)
	payload = binary.BigEndian.AppendUint32(payload, procedureNull)
	payload = binary.BigEndian.AppendUint32(payload, authFlavorNull)
	payload = binary.BigEndian.AppendUint32(payload, authLengthEmpty)
	payload = binary.BigEndian.AppendUint32(payload, authFlavorNull)
	payload = binary.BigEndian.AppendUint32(payload, authLengthEmpty)

	marker := uint32(len(payload)) | 0x80000000

	out := make([]byte, 0, 4+len(payload))
	out = binary.BigEndian.AppendUint32(out, marker)
	out = append(out, payload...)

	return out
}

func sunrpcPortmapDumpCall() []byte {
	const (
		xid             = 0x55564000
		msgTypeCall     = 0
		rpcVersion      = 2
		programPortmap  = 100000
		programVersion  = 2
		procedureDump   = 4
		authFlavorNull  = 0
		authLengthEmpty = 0
	)

	payload := make([]byte, 0, 44)
	payload = binary.BigEndian.AppendUint32(payload, xid)
	payload = binary.BigEndian.AppendUint32(payload, msgTypeCall)
	payload = binary.BigEndian.AppendUint32(payload, rpcVersion)
	payload = binary.BigEndian.AppendUint32(payload, programPortmap)
	payload = binary.BigEndian.AppendUint32(payload, programVersion)
	payload = binary.BigEndian.AppendUint32(payload, procedureDump)
	payload = binary.BigEndian.AppendUint32(payload, authFlavorNull)
	payload = binary.BigEndian.AppendUint32(payload, authLengthEmpty)
	payload = binary.BigEndian.AppendUint32(payload, authFlavorNull)
	payload = binary.BigEndian.AppendUint32(payload, authLengthEmpty)

	marker := uint32(len(payload)) | 0x80000000

	out := make([]byte, 0, 4+len(payload))
	out = binary.BigEndian.AppendUint32(out, marker)
	out = append(out, payload...)

	return out
}

// sunrpcIsAcceptedReply checks the reply header: XID + msg_type(1=REPLY) +
// reply_stat(0=MSG_ACCEPTED) + auth_flavor(0) + auth_length(0) + accept_stat(0).
func sunrpcIsAcceptedReply(body []byte) bool {
	if len(body) < 24 {
		return false
	}

	msgType := binary.BigEndian.Uint32(body[4:8])
	replyStat := binary.BigEndian.Uint32(body[8:12])
	acceptStat := binary.BigEndian.Uint32(body[20:24])

	return msgType == 1 && replyStat == 0 && acceptStat == 0
}

// sunrpcParseDump walks the linked list of (prog, vers, prot, port) entries
// returned by PMAPPROC_DUMP. Each entry is 5 uint32: value-follows flag + the
// four fields. Bounded to 256 entries so a malicious peer can't exhaust the
// probe budget.
func sunrpcParseDump(body []byte) []map[string]any {
	const headerSize = 24

	if len(body) <= headerSize {
		return nil
	}

	out := make([]map[string]any, 0, 16)
	cursor := headerSize

	for range 256 {
		if cursor+4 > len(body) {
			break
		}

		valueFollows := binary.BigEndian.Uint32(body[cursor : cursor+4])
		cursor += 4

		if valueFollows == 0 {
			break
		}

		if cursor+16 > len(body) {
			break
		}

		entry := map[string]any{
			"program":  binary.BigEndian.Uint32(body[cursor : cursor+4]),
			"version":  binary.BigEndian.Uint32(body[cursor+4 : cursor+8]),
			"protocol": binary.BigEndian.Uint32(body[cursor+8 : cursor+12]),
			"port":     binary.BigEndian.Uint32(body[cursor+12 : cursor+16]),
		}

		out = append(out, entry)
		cursor += 16
	}

	return out
}

// ---------------------------------------------------------------------------
// Microsoft RPC endpoint mapper (port 135, DCE/RPC over TCP).
//
// We send a minimal Bind PDU asking to bind to the epmapper interface
// (E1AF8308-5D1F-11C9-91A4-08002B14A0FA, version 3.0). Every Windows host
// either accepts (Bind_ack) or rejects (Bind_nak). Either reply confirms
// MSRPC; the rest is left to operator follow-up (impacket-rpcdump for the
// actual endpoint list, which we don't replicate to keep the probe cheap).
// ---------------------------------------------------------------------------

func probeMSRPC(ctx context.Context, s *Stack, target Target) (*Result, error) {
	conn, err := s.dialTCP(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("can't dial MSRPC target: %w", err)
	}

	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(s.probeTimeout(ctx)))

	if _, writeErr := conn.Write(msrpcBindEpmapper()); writeErr != nil {
		return nil, fmt.Errorf("can't send MSRPC bind: %w", writeErr)
	}

	header := make([]byte, 16)
	if _, readErr := io.ReadFull(conn, header); readErr != nil {
		return &Result{Target: target, Protocol: protocolTCP}, nil
	}

	if header[0] != 0x05 {
		return &Result{Target: target, Protocol: protocolTCP, Banner: hex.EncodeToString(header)}, nil
	}

	pduType := header[2]

	frag := binary.LittleEndian.Uint16(header[8:10])
	if frag < 16 || frag > 4096 {
		return &Result{Target: target, Protocol: protocolTCP}, nil
	}

	body := make([]byte, int(frag)-16)
	if len(body) > 0 {
		_, _ = io.ReadFull(conn, body)
	}

	// 0x0C = Bind_ack, 0x0D = Bind_nak — both prove the host speaks MSRPC.
	if pduType != 0x0C && pduType != 0x0D {
		return &Result{Target: target, Protocol: protocolTCP, Banner: hex.EncodeToString(header)}, nil
	}

	pduName := "bind_ack"
	if pduType == 0x0D {
		pduName = "bind_nak"
	}

	fp := &FingerprintResult{
		Product: productMSRPC,
		RawJSON: mustMarshalJSON(map[string]any{
			"pdu_type":   pduName,
			"frag_bytes": int(frag),
			"endpoint":   "e1af8308-5d1f-11c9-91a4-08002b14a0fa@3.0",
		}),
	}

	return &Result{
		Target:      target,
		Protocol:    productMSRPC,
		Banner:      "MSRPC " + pduName,
		Fingerprint: fp,
	}, nil
}

// msrpcBindEpmapper builds a 72-byte DCE/RPC Bind PDU (call_id 1) asking
// for the epmapper abstract syntax with the NDR 2.0 transfer syntax. The
// constants are taken from MS-RPCE §2.2.3 and §A; values are baked in
// because we never need to vary them.
func msrpcBindEpmapper() []byte {
	header := []byte{
		0x05, 0x00, // rpc_vers + minor (5.0)
		0x0B,                   // PDU type = BIND
		0x03,                   // pfc_flags = first + last frag
		0x10, 0x00, 0x00, 0x00, // data representation (little-endian, ASCII, IEEE float)
		0x48, 0x00, // frag_length = 72
		0x00, 0x00, // auth_length = 0
		0x01, 0x00, 0x00, 0x00, // call_id = 1
	}

	body := []byte{
		0xB8, 0x10, // max_xmit_frag = 4280
		0xB8, 0x10, // max_recv_frag = 4280
		0x00, 0x00, 0x00, 0x00, // assoc_group_id
		0x01,             // num_ctx_items
		0x00, 0x00, 0x00, // padding
		0x00, 0x00, // context_id = 0
		0x01, 0x00, // num_trans_items
		// epmapper abstract syntax (UUID + version 3.0)
		0x08, 0x83, 0xAF, 0xE1,
		0x1F, 0x5D,
		0xC9, 0x11,
		0x91, 0xA4,
		0x08, 0x00, 0x2B, 0x14, 0xA0, 0xFA,
		0x03, 0x00, 0x00, 0x00, // version 3.0
		// NDR 2.0 transfer syntax (UUID + version 2.0)
		0x04, 0x5D, 0x88, 0x8A,
		0xEB, 0x1C,
		0xC9, 0x11,
		0x9F, 0xE8,
		0x08, 0x00, 0x2B, 0x10, 0x48, 0x60,
		0x02, 0x00, 0x00, 0x00, // version 2.0
	}

	out := make([]byte, 0, len(header)+len(body))
	out = append(out, header...)
	out = append(out, body...)

	return out
}
