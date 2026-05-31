package screenshot

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/coder/websocket"
)

// browserVersion is the subset of /json/version we need to reach the browser
// debugger WebSocket endpoint.
type browserVersion struct {
	WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
}

// cdpMessage is one envelope on the bidirectional CDP stream.
// Requests carry id+method+params, responses carry id+result|error and
// events carry method+params; the sessionId routes per-target traffic when
// flatten mode is enabled.
type cdpMessage struct {
	ID        int             `json:"id,omitempty"`
	Method    string          `json:"method,omitempty"`
	Params    json.RawMessage `json:"params,omitempty"`
	Result    json.RawMessage `json:"result,omitempty"`
	Error     *cdpError       `json:"error,omitempty"`
	SessionID string          `json:"sessionId,omitempty"`
}

type cdpError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *cdpError) Error() string {
	return fmt.Sprintf("cdp error %d: %s", e.Code, e.Message)
}

// discoverBrowserWS asks the headless-Chromium HTTP endpoint for the
// browser-level WebSocket URL. The returned URL is the only well-known entry
// point — per-target endpoints are obtained later via Target.attachToTarget.
func discoverBrowserWS(ctx context.Context, base string) (string, error) {
	endpoint, err := url.Parse(strings.TrimRight(base, "/") + "/json/version")
	if err != nil {
		return "", fmt.Errorf("can't parse chromium URL: %w", err)
	}

	switch endpoint.Scheme {
	case "ws":
		endpoint.Scheme = "http"
	case "wss":
		endpoint.Scheme = "https"
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), http.NoBody)
	if err != nil {
		return "", fmt.Errorf("can't build chromium discovery request: %w", err)
	}

	// headless-shell listens on loopback; socat exposes :9222. Chrome rejects
	// discovery when Host is the Docker service name (M113+).
	req.Host = "127.0.0.1"

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("can't reach chromium: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("chromium /json/version returned %d", resp.StatusCode)
	}

	var version browserVersion

	if err := json.NewDecoder(resp.Body).Decode(&version); err != nil {
		return "", fmt.Errorf("can't decode chromium /json/version: %w", err)
	}

	if version.WebSocketDebuggerURL == "" {
		return "", errors.New("chromium /json/version did not return a webSocketDebuggerUrl")
	}

	return rewriteBrowserWS(version.WebSocketDebuggerURL, base)
}

// rewriteBrowserWS maps Chrome's loopback debugger URL onto the configured
// service endpoint (e.g. http://chromium:9222).
func rewriteBrowserWS(wsURL, base string) (string, error) {
	ws, err := url.Parse(wsURL)
	if err != nil {
		return "", fmt.Errorf("can't parse chromium WebSocket URL: %w", err)
	}

	b, err := url.Parse(strings.TrimRight(base, "/"))
	if err != nil {
		return "", fmt.Errorf("can't parse chromium base URL: %w", err)
	}

	switch b.Scheme {
	case "http":
		ws.Scheme = "ws"
	case "https":
		ws.Scheme = "wss"
	case "ws", "wss":
		ws.Scheme = b.Scheme
	default:
		return "", fmt.Errorf("unsupported chromium URL scheme %q", b.Scheme)
	}

	ws.Host = b.Host

	return ws.String(), nil
}

// cdpSession is one logical CDP connection. The browser endpoint is shared,
// targets are spun up per render. The session is not safe for concurrent use
// from multiple goroutines.
type cdpSession struct {
	conn   *websocket.Conn
	nextID int
}

func dialCDP(ctx context.Context, wsURL string) (*cdpSession, error) {
	conn, resp, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		Host: "127.0.0.1",
	})
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}

	if err != nil {
		return nil, fmt.Errorf("can't dial chromium WebSocket: %w", err)
	}

	// CDP frames carry full JSON payloads (incl. base64 screenshots);
	// disable the small built-in read limit so large messages aren't
	// truncated.
	conn.SetReadLimit(-1)

	return &cdpSession{conn: conn}, nil
}

func (s *cdpSession) close() {
	if s == nil || s.conn == nil {
		return
	}

	_ = s.conn.Close(websocket.StatusNormalClosure, "")
}

// send writes one CDP frame. params and sessionID may be empty.
func (s *cdpSession) send(ctx context.Context, method string, params any, sessionID string) (int, error) {
	s.nextID++

	msg := cdpMessage{
		ID:        s.nextID,
		Method:    method,
		SessionID: sessionID,
	}

	if params != nil {
		raw, err := json.Marshal(params)
		if err != nil {
			return 0, fmt.Errorf("can't marshal CDP params for %s: %w", method, err)
		}

		msg.Params = raw
	}

	payload, err := json.Marshal(msg)
	if err != nil {
		return 0, fmt.Errorf("can't marshal CDP frame for %s: %w", method, err)
	}

	if err := s.conn.Write(ctx, websocket.MessageText, payload); err != nil {
		return 0, fmt.Errorf("can't write CDP frame for %s: %w", method, err)
	}

	return msg.ID, nil
}

// awaitResponse drains the WebSocket until a frame with the given id arrives
// or ctx expires. Events seen along the way are reported through onEvent so
// callers can wait for Page.loadEventFired in parallel.
func (s *cdpSession) awaitResponse(ctx context.Context, id int, onEvent func(string, json.RawMessage)) (json.RawMessage, error) {
	for {
		_, raw, err := s.conn.Read(ctx)
		if err != nil {
			return nil, fmt.Errorf("can't read CDP frame: %w", err)
		}

		var msg cdpMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			return nil, fmt.Errorf("can't decode CDP frame: %w", err)
		}

		if msg.ID == 0 && msg.Method != "" {
			if onEvent != nil {
				onEvent(msg.Method, msg.Params)
			}

			continue
		}

		if msg.ID != id {
			continue
		}

		if msg.Error != nil {
			return nil, msg.Error
		}

		return msg.Result, nil
	}
}

// call issues one request/response round trip and ignores events.
func (s *cdpSession) call(ctx context.Context, method string, params any, sessionID string) (json.RawMessage, error) {
	id, err := s.send(ctx, method, params, sessionID)
	if err != nil {
		return nil, err
	}

	return s.awaitResponse(ctx, id, nil)
}

// callAndWaitEvent issues a request and additionally watches the event stream
// until eventMethod is observed on the same session. The CDP request response
// usually returns before the event fires (e.g. Page.navigate returns the
// frameId immediately but load happens later).
func (s *cdpSession) callAndWaitEvent(ctx context.Context, method string, params any, sessionID, eventMethod string) error {
	id, err := s.send(ctx, method, params, sessionID)
	if err != nil {
		return err
	}

	var (
		gotResponse bool
		gotEvent    bool
	)

	for !gotResponse || !gotEvent {
		_, raw, err := s.conn.Read(ctx)
		if err != nil {
			return fmt.Errorf("can't read CDP frame: %w", err)
		}

		var msg cdpMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			return fmt.Errorf("can't decode CDP frame: %w", err)
		}

		if msg.ID == id {
			if msg.Error != nil {
				return msg.Error
			}

			gotResponse = true

			continue
		}

		if msg.Method == eventMethod && msg.SessionID == sessionID {
			gotEvent = true
		}
	}

	return nil
}
