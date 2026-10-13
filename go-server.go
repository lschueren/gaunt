package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Minimal WebSocket implementation (RFC 6455) built on the standard library,
// so the server has zero external dependencies.
// ---------------------------------------------------------------------------

const wsMagic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

const (
	opContinuation = 0x0
	opText         = 0x1
	opBinary       = 0x2
	opClose        = 0x8
	opPing         = 0x9
	opPong         = 0xA
)

type wsConn struct {
	conn net.Conn
	r    *bufio.Reader
	wmu  sync.Mutex
}

func isWebSocket(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

func upgrade(w http.ResponseWriter, r *http.Request) (*wsConn, error) {
	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		return nil, errors.New("missing Sec-WebSocket-Key")
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, errors.New("connection does not support hijacking")
	}
	conn, brw, err := hj.Hijack()
	if err != nil {
		return nil, err
	}
	sum := sha1.Sum([]byte(key + wsMagic))
	accept := base64.StdEncoding.EncodeToString(sum[:])
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
	if _, err := brw.WriteString(resp); err != nil {
		conn.Close()
		return nil, err
	}
	if err := brw.Flush(); err != nil {
		conn.Close()
		return nil, err
	}
	return &wsConn{conn: conn, r: brw.Reader}, nil
}

func (c *wsConn) readMessage() ([]byte, error) {
	var msg []byte
	for {
		b0, err := c.r.ReadByte()
		if err != nil {
			return nil, err
		}
		b1, err := c.r.ReadByte()
		if err != nil {
			return nil, err
		}
		fin := b0&0x80 != 0
		opcode := b0 & 0x0f
		masked := b1&0x80 != 0
		length := int64(b1 & 0x7f)

		switch length {
		case 126:
			var l uint16
			if err := binary.Read(c.r, binary.BigEndian, &l); err != nil {
				return nil, err
			}
			length = int64(l)
		case 127:
			var l uint64
			if err := binary.Read(c.r, binary.BigEndian, &l); err != nil {
				return nil, err
			}
			length = int64(l)
		}
		if length < 0 || length > 1<<20 {
			return nil, errors.New("frame too large")
		}

		var mask [4]byte
		if masked {
			if _, err := io.ReadFull(c.r, mask[:]); err != nil {
				return nil, err
			}
		}
		payload := make([]byte, length)
		if _, err := io.ReadFull(c.r, payload); err != nil {
			return nil, err
		}
		if masked {
			for i := range payload {
				payload[i] ^= mask[i%4]
			}
		}

		switch opcode {
		case opText, opBinary, opContinuation:
			msg = append(msg, payload...)
			if fin {
				return msg, nil
			}
		case opClose:
			c.writeFrame(opClose, nil)
			return nil, io.EOF
		case opPing:
			c.writeFrame(opPong, payload)
		case opPong:
			// ignore
		default:
			return nil, errors.New("unsupported opcode")
		}
	}
}

func (c *wsConn) writeFrame(opcode byte, payload []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()

	n := len(payload)
	out := make([]byte, 0, n+10)
	out = append(out, 0x80|opcode)
	switch {
	case n < 126:
		out = append(out, byte(n))
	case n <= 65535:
		out = append(out, 126, byte(n>>8), byte(n))
	default:
		out = append(out, 127)
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], uint64(n))
		out = append(out, b[:]...)
	}
	out = append(out, payload...)

	c.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err := c.conn.Write(out)
	return err
}

func (c *wsConn) writeText(payload []byte) error { return c.writeFrame(opText, payload) }

func (c *wsConn) close() error {
	c.writeFrame(opClose, nil)
	return c.conn.Close()
}

// ---------------------------------------------------------------------------
// Hub: the shared social space. Each connected player lives here until they
// step into the portal and descend (solo) into the Gauntlet.
// ---------------------------------------------------------------------------

const (
	zoneHub     = "hub"
	zoneDungeon = "dungeon"

	// World extents of the shared hub, in pixels. Kept in sync with the
	// client's HUB_W / HUB_H.
	hubW = 40 * 32
	hubH = 28 * 32

	maxNameLen = 16
	maxChatLen = 120
)

type player struct {
	id   string
	name string
	x    float64
	y    float64
	dir  string
	zone string
	hue  int
	conn *wsConn
}

type hub struct {
	mu      sync.Mutex
	players map[string]*player
}

func newHub() *hub {
	return &hub{players: make(map[string]*player)}
}

func randomID() string {
	var b [4]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func marshal(v interface{}) []byte {
	b, _ := json.Marshal(v)
	return b
}

// broadcast sends raw bytes to every player, optionally filtered by zone and
// excluding one id. It never holds the hub lock while writing.
func (h *hub) broadcast(filterZone, exceptID string, data []byte) {
	h.mu.Lock()
	targets := make([]*player, 0, len(h.players))
	for id, p := range h.players {
		if exceptID != "" && id == exceptID {
			continue
		}
		if filterZone != "" && p.zone != filterZone {
			continue
		}
		targets = append(targets, p)
	}
	h.mu.Unlock()

	for _, p := range targets {
		p.conn.writeText(data)
	}
}

func (p *player) entry() map[string]interface{} {
	return map[string]interface{}{
		"id":   p.id,
		"name": p.name,
		"x":    p.x,
		"y":    p.y,
		"dir":  p.dir,
		"zone": p.zone,
		"hue":  p.hue,
	}
}

func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func sanitizeName(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return -1
		}
		return r
	}, s)
	if s == "" {
		s = "Wanderer"
	}
	if len(s) > maxNameLen {
		s = s[:maxNameLen]
	}
	return s
}

func sanitizeChat(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > maxChatLen {
		s = s[:maxChatLen]
	}
	return s
}

type clientMsg struct {
	T    string  `json:"t"`
	Name string  `json:"name"`
	X    float64 `json:"x"`
	Y    float64 `json:"y"`
	Dir  string  `json:"dir"`
	Text string  `json:"text"`
}

// serve runs the read loop for one connected socket.
func (h *hub) serve(conn *wsConn) {
	p := &player{
		id:   randomID(),
		dir:  "down",
		zone: zoneHub,
		hue:  int(time.Now().UnixNano()%360) ^ int(randomByte())<<2,
		conn: conn,
		x:    hubW / 2,
		y:    hubH/2 + 160,
	}

	// Periodic pings keep idle connections (e.g. a player deep in the
	// Gauntlet who sends no updates) from being reaped by proxies/NAT.
	done := make(chan struct{})
	defer close(done)
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				if err := conn.writeFrame(opPing, nil); err != nil {
					conn.conn.Close()
					return
				}
			}
		}
	}()

	registered := false
	defer func() {
		if registered {
			h.mu.Lock()
			delete(h.players, p.id)
			h.mu.Unlock()
			h.broadcast("", "", marshal(map[string]interface{}{"t": "leave", "id": p.id}))
		}
		conn.close()
	}()

	for {
		raw, err := conn.readMessage()
		if err != nil {
			return
		}
		var m clientMsg
		if err := json.Unmarshal(raw, &m); err != nil {
			continue
		}

		switch m.T {
		case "join":
			if registered {
				continue
			}
			p.name = sanitizeName(m.Name)
			registered = true

			h.mu.Lock()
			h.players[p.id] = p
			others := make([]map[string]interface{}, 0, len(h.players))
			for id, op := range h.players {
				if id == p.id || op.zone != p.zone {
					continue
				}
				others = append(others, op.entry())
			}
			welcome := marshal(map[string]interface{}{
				"t":       "welcome",
				"id":      p.id,
				"name":    p.name,
				"hue":     p.hue,
				"x":       p.x,
				"y":       p.y,
				"players": others,
			})
			joinMsg := marshal(map[string]interface{}{"t": "join", "p": p.entry()})
			zone := p.zone
			h.mu.Unlock()

			conn.writeText(welcome)
			h.broadcast(zone, p.id, joinMsg)

		case "pos":
			if !registered {
				continue
			}
			h.mu.Lock()
			p.x = clamp(m.X, 16, hubW-16)
			p.y = clamp(m.Y, 16, hubH-16)
			p.dir = m.Dir
			msg := marshal(map[string]interface{}{
				"t":    "pos",
				"id":   p.id,
				"x":    p.x,
				"y":    p.y,
				"dir":  p.dir,
				"zone": p.zone,
			})
			zone := p.zone
			h.mu.Unlock()
			h.broadcast(zone, p.id, msg)

		case "chat":
			if !registered {
				continue
			}
			text := sanitizeChat(m.Text)
			if text == "" {
				continue
			}
			h.broadcast(p.zone, "", marshal(map[string]interface{}{
				"t":    "chat",
				"id":   p.id,
				"name": p.name,
				"text": text,
				"zone": p.zone,
			}))

		case "enter":
			if !registered || p.zone == zoneDungeon {
				continue
			}
			h.mu.Lock()
			p.zone = zoneDungeon
			msg := marshal(map[string]interface{}{
				"t":    "pos",
				"id":   p.id,
				"x":    p.x,
				"y":    p.y,
				"dir":  p.dir,
				"zone": p.zone,
			})
			h.mu.Unlock()
			h.broadcast(zoneHub, p.id, msg)

		case "exit":
			if !registered || p.zone == zoneHub {
				continue
			}
			h.mu.Lock()
			p.zone = zoneHub
			p.x = hubW/2 + 64
			p.y = hubH/2 + 160
			others := make([]map[string]interface{}, 0, len(h.players))
			for id, op := range h.players {
				if id == p.id || op.zone != zoneHub {
					continue
				}
				others = append(others, op.entry())
			}
			joinMsg := marshal(map[string]interface{}{"t": "join", "p": p.entry()})
			h.mu.Unlock()

			conn.writeText(marshal(map[string]interface{}{"t": "sync", "players": others}))
			h.broadcast(zoneHub, p.id, joinMsg)
		}
	}
}

func randomByte() byte {
	var b [1]byte
	rand.Read(b[:])
	return b[0]
}

// ---------------------------------------------------------------------------
// HTTP entry point.
// ---------------------------------------------------------------------------

func main() {
	h := newHub()

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		if !isWebSocket(r) {
			http.Error(w, "expected websocket", http.StatusBadRequest)
			return
		}
		conn, err := upgrade(w, r)
		if err != nil {
			log.Println("websocket upgrade failed:", err)
			return
		}
		log.Printf("player connected from %s", r.RemoteAddr)
		h.serve(conn)
		log.Printf("player disconnected from %s", r.RemoteAddr)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		http.ServeFile(w, r, "index.html")
	})

	certPath := "etc/letsencrypt/live/schueren.digital/fullchain.pem"
	keyPath := "etc/letsencrypt/live/schueren.digital/privkey.pem"

	if fileExists(certPath) && fileExists(keyPath) {
		log.Println("Starting secure Go server on :443")
		if err := http.ListenAndServeTLS(":443", certPath, keyPath, mux); err != nil {
			log.Fatal(err)
		}
		return
	}

	addr := os.Getenv("ADDR")
	if addr == "" {
		addr = ":8080"
	}
	log.Println("No TLS certificate found; starting plain HTTP server on", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}
