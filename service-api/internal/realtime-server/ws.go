package realtimeserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/gofrs/uuid/v5"
	"go.uber.org/zap"

	realtimedto "github.com/yakushstanislav/UltraViolet/service-api/internal/dto/realtime"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/http-server/handler/middleware/cors"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/auth"
	"github.com/yakushstanislav/UltraViolet/service-api/internal/pkg/events"
)

const (
	wsPingInterval    = 30 * time.Second
	wsReadTimeout     = 65 * time.Second
	clientSubprotocol = "uv-token.v1"
	frontendIDPrefix  = "uv-frontend.v1."
)

var defaultBroadcastTypes = []string{"scan.status", "alert.fired", "risk.event"}

var scanScopedTypes = []string{
	"scan.status",
	"scan.stats",
	"scan.snapshot",
	"scan.delta",
}

type wsClientMessage struct {
	Op     string `json:"op"`
	ScanID uint64 `json:"scan_id"`
	Token  string `json:"token,omitempty"`
}

type wsHandler struct {
	auth         auth.Config
	cors         cors.Config
	allowedRoles map[auth.Role]struct{}
	eventsBus    events.Bus
	logger       *zap.SugaredLogger
}

func newWSHandler(
	authConfig auth.Config,
	corsConfig cors.Config,
	allowedRoles map[auth.Role]struct{},
	eventsBus events.Bus,
	logger *zap.SugaredLogger,
) *wsHandler {
	return &wsHandler{
		auth:         authConfig,
		cors:         corsConfig,
		allowedRoles: allowedRoles,
		eventsBus:    eventsBus,
		logger:       logger,
	}
}

// extractToken returns the access token taken from the Sec-WebSocket-Protocol
// header if present (preferred path), otherwise from the ?access_token= query
// param (legacy, deprecated). viaHeader reports which slot was used.
func extractToken(r *http.Request) (token string, viaHeader bool) {
	header := r.Header.Get("Sec-WebSocket-Protocol")
	if header != "" {
		for _, raw := range strings.Split(header, ",") {
			part := strings.TrimSpace(raw)
			if part == "" || part == clientSubprotocol || strings.HasPrefix(part, frontendIDPrefix) {
				continue
			}

			return part, true
		}
	}

	return r.URL.Query().Get("access_token"), false
}

func (h *wsHandler) serve(w http.ResponseWriter, r *http.Request) {
	rawToken, viaHeader := extractToken(r)
	if rawToken == "" {
		w.WriteHeader(http.StatusUnauthorized)

		return
	}

	if !viaHeader {
		h.logger.Warnw("WebSocket token via ?access_token= is deprecated, switch to Sec-WebSocket-Protocol")
	}

	claims, err := auth.ParseAccessToken(h.auth.JWTSecret, rawToken)
	if err != nil || claims.Role == "" || claims.UserID == 0 {
		w.WriteHeader(http.StatusUnauthorized)

		return
	}

	if _, ok := h.allowedRoles[claims.Role]; !ok {
		w.WriteHeader(http.StatusForbidden)

		return
	}

	ctx := auth.WithRole(r.Context(), claims.Role)
	ctx = auth.WithUserID(ctx, claims.UserID)

	originPatterns := cors.OriginPatterns(&h.cors)

	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Time{})
	_ = rc.SetWriteDeadline(time.Time{})

	acceptOpts := &websocket.AcceptOptions{
		OriginPatterns: originPatterns,
	}
	if viaHeader {
		acceptOpts.Subprotocols = []string{clientSubprotocol}
	}

	conn, err := websocket.Accept(w, r, acceptOpts)
	if err != nil {
		h.logger.Warnw("Can't upgrade WebSocket", zap.Error(err))

		return
	}

	connID := uuid.Must(uuid.NewV4()).String()

	session := newWSSession(ctx, h.eventsBus, connID, claims)
	defer session.close()

	readCtx, cancelRead := context.WithCancel(ctx)
	defer cancelRead()

	writeCtx, cancelWrite := context.WithCancel(ctx)
	defer cancelWrite()

	var writeWG sync.WaitGroup

	writeWG.Add(1)

	go func() {
		defer writeWG.Done()
		defer cancelRead()
		defer func() {
			_ = conn.Close(websocket.StatusInternalError, "write loop exit")
		}()

		h.wsWriteLoop(writeCtx, conn, session)
	}()

	h.wsReadLoop(readCtx, conn, session)

	cancelWrite()

	_ = conn.Close(websocket.StatusNormalClosure, "")

	writeWG.Wait()
}

func (h *wsHandler) wsReadLoop(
	ctx context.Context,
	conn *websocket.Conn,
	session *wsSession,
) {
	conn.SetReadLimit(4096)

	for {
		readCtx, cancel := context.WithTimeout(ctx, wsReadTimeout)

		_, payload, err := conn.Read(readCtx)

		cancel()

		if err != nil {
			if websocket.CloseStatus(err) == websocket.StatusNormalClosure {
				return
			}

			h.logger.Debugw("WebSocket read ended", zap.Error(err))

			return
		}

		var msg wsClientMessage

		if err := json.Unmarshal(payload, &msg); err != nil {
			continue
		}

		switch msg.Op {
		case "ping":
			session.enqueue([]byte(`{"op":"pong"}`))
		case "subscribe":
			if msg.ScanID > 0 {
				session.subscribeScan(msg.ScanID)
			}
		case "unsubscribe":
			if msg.ScanID > 0 {
				session.unsubscribeScan(msg.ScanID)
			}
		case "refresh":
			if !h.handleRefresh(conn, session, msg.Token) {
				return
			}
		}
	}
}

// handleRefresh validates a refresh token and swaps it into the session.
// Returns false when the read loop should exit (after sending a close frame).
func (h *wsHandler) handleRefresh(conn *websocket.Conn, session *wsSession, rawToken string) bool {
	if rawToken == "" {
		_ = conn.Close(websocket.StatusPolicyViolation, "missing token")

		return false
	}

	newClaims, err := auth.ParseAccessToken(h.auth.JWTSecret, rawToken)
	if err != nil || newClaims.UserID == 0 || newClaims.Role == "" {
		h.logger.Debugw("WS refresh failed: invalid token", zap.Error(err))

		_ = conn.Close(websocket.StatusPolicyViolation, "invalid token")

		return false
	}

	if _, ok := h.allowedRoles[newClaims.Role]; !ok {
		_ = conn.Close(websocket.StatusPolicyViolation, "role not allowed")

		return false
	}

	if err := session.replaceClaims(newClaims); err != nil {
		h.logger.Debugw("WS refresh rejected", zap.Error(err))

		_ = conn.Close(websocket.StatusPolicyViolation, "refresh rejected")

		return false
	}

	return true
}

func (h *wsHandler) wsWriteLoop(
	ctx context.Context,
	conn *websocket.Conn,
	session *wsSession,
) {
	pingTicker := time.NewTicker(wsPingInterval)
	defer pingTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case payload := <-session.outbound:
			writeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)

			err := conn.Write(writeCtx, websocket.MessageText, payload)

			cancel()

			if err != nil {
				h.logger.Debugw("WebSocket write failed", zap.Error(err))

				return
			}
		case evt := <-session.events:
			envelope := realtimedto.Event{
				Type:   evt.Type,
				Ts:     evt.Ts,
				ScanID: evt.ScanID,
				Data:   evt.Data,
			}

			payload, err := json.Marshal(envelope)
			if err != nil {
				continue
			}

			writeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)

			err = conn.Write(writeCtx, websocket.MessageText, payload)

			cancel()

			if err != nil {
				h.logger.Debugw("WebSocket write failed", zap.Error(err))

				return
			}
		case <-pingTicker.C:
			if expiry := session.expiry(); !expiry.IsZero() && time.Now().After(expiry) {
				h.logger.Debugw("WebSocket token expired", zap.Uint64("user_id", session.userID()))

				_ = conn.Close(websocket.StatusPolicyViolation, "token expired")

				return
			}

			pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)

			err := conn.Ping(pingCtx)

			cancel()

			if err != nil {
				h.logger.Debugw("WebSocket ping failed", zap.Error(err))

				return
			}
		}
	}
}

type wsSession struct {
	eventsBus events.Bus
	connID    string

	authMu     sync.RWMutex
	authClaims *auth.AccessClaims

	mu          sync.Mutex
	broadcast   <-chan events.Event
	unsubAll    func()
	scanSubs    map[uint64]func()
	events      chan events.Event
	outbound    chan []byte
	relayCancel context.CancelFunc
}

func newWSSession(
	parent context.Context,
	eventsBus events.Bus,
	connID string,
	claims *auth.AccessClaims,
) *wsSession {
	s := &wsSession{
		eventsBus:  eventsBus,
		connID:     connID,
		authClaims: claims,
		scanSubs:   make(map[uint64]func()),
		events:     make(chan events.Event, 128),
		outbound:   make(chan []byte, 16),
	}

	ch, unsub := eventsBus.Subscribe(0, defaultBroadcastTypes, connID)
	s.broadcast = ch
	s.unsubAll = unsub

	relayCtx, cancel := context.WithCancel(parent)
	s.relayCancel = cancel

	go s.relay(relayCtx)

	return s
}

func (s *wsSession) expiry() time.Time {
	s.authMu.RLock()
	defer s.authMu.RUnlock()

	if s.authClaims == nil || s.authClaims.ExpiresAt == nil {
		return time.Time{}
	}

	return s.authClaims.ExpiresAt.Time
}

func (s *wsSession) userID() uint64 {
	s.authMu.RLock()
	defer s.authMu.RUnlock()

	if s.authClaims == nil {
		return 0
	}

	return s.authClaims.UserID
}

// replaceClaims swaps in newer claims. Refuses when the new claims describe a
// different user — the refresh flow must not be used to hop identity.
func (s *wsSession) replaceClaims(c *auth.AccessClaims) error {
	if c == nil {
		return errors.New("nil claims")
	}

	s.authMu.Lock()
	defer s.authMu.Unlock()

	if s.authClaims != nil && s.authClaims.UserID != c.UserID {
		return errors.New("user id mismatch")
	}

	s.authClaims = c

	return nil
}

func (s *wsSession) relay(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case evt, ok := <-s.broadcast:
			if !ok {
				return
			}

			s.pushEvent(evt)
		}
	}
}

func (s *wsSession) pushEvent(evt events.Event) {
	select {
	case s.events <- evt:
	default:
	}
}

func (s *wsSession) subscribeScan(scanID uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.scanSubs[scanID]; exists {
		return
	}

	ch, unsub := s.eventsBus.Subscribe(scanID, scanScopedTypes, s.connID)
	s.scanSubs[scanID] = unsub

	go func() {
		for evt := range ch {
			s.pushEvent(evt)
		}
	}()
}

func (s *wsSession) unsubscribeScan(scanID uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	unsub, ok := s.scanSubs[scanID]
	if !ok {
		return
	}

	unsub()

	delete(s.scanSubs, scanID)
}

func (s *wsSession) enqueue(payload []byte) {
	select {
	case s.outbound <- payload:
	default:
	}
}

func (s *wsSession) close() {
	s.relayCancel()

	if s.unsubAll != nil {
		s.unsubAll()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for scanID, unsub := range s.scanSubs {
		unsub()

		delete(s.scanSubs, scanID)
	}
}
