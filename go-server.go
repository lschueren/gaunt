package main

import (
	"bufio"
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"math"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strconv"
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

	// World extents of the Gauntlet, in pixels. Kept in sync with the
	// client's WORLD_W / WORLD_H.
	dungeonW = 40 * 32
	dungeonH = 30 * 32

	// Gauntlet layout, in tiles. Kept in sync with the client's MAP_W/MAP_H.
	mapW = 40
	mapH = 30
	// Tile size and entity radii, in pixels (client TILE / r).
	tileSize     = 32
	enemyRadius  = 11
	playerRadius = 11

	// The Gauntlet is simulated here and snapshotted to every player below.
	maxEnemies  = 34
	dungeonTick = 50 * time.Millisecond
	snapEvery   = 2 // one state snapshot every N ticks → 10 Hz

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
	dead bool
	// gold and upg live here while the player is connected; the store
	// persists them so progress survives a logout.
	gold int
	upg  map[string]int
	// weps is the set of weapon types this player has bought, wepCur the one
	// they are holding. The Gold Bolt ("bolt") is always owned.
	weps    map[string]bool
	wepCur  string
	conn *wsConn
}

// ownsWeapon reports whether a player has bought a weapon type. Everyone owns
// the free starter Gold Bolt.
func (p *player) ownsWeapon(id string) bool {
	return id == "bolt" || (p.weps != nil && p.weps[id])
}

// ownedWeapons lists every weapon type the player can switch to, in catalogue
// order, so the client's 1-9 shortcuts and the shop render deterministically.
func (p *player) ownedWeapons() []string {
	out := make([]string, 0, len(weaponDefs))
	for _, def := range weaponDefs {
		if p.ownsWeapon(def.id) {
			out = append(out, def.id)
		}
	}
	return out
}

type hub struct {
	mu      sync.Mutex
	players map[string]*player

	// store is the tiny account database backing logins and saved progress.
	store *store

	// dungeon is the single shared Gauntlet. It lives while at least one
	// player is inside and is discarded as soon as the last one leaves, so
	// the next group starts a fresh run.
	dungeon *dungeon
}

func newHub(dbPath string) *hub {
	return &hub{players: make(map[string]*player), store: newStore(dbPath)}
}

func randomID() string {
	var b [4]byte
	crand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// randomSeed returns a non-zero 32-bit seed for the shared Gauntlet map.
func randomSeed() uint32 {
	var b [4]byte
	crand.Read(b[:])
	s := binary.LittleEndian.Uint32(b[:])
	if s == 0 {
		s = 1
	}
	return s
}

// anyInZone reports whether at least one player is currently in the zone.
// Callers must hold the hub lock.
func (h *hub) anyInZone(zone string) bool {
	for _, p := range h.players {
		if p.zone == zone {
			return true
		}
	}
	return false
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

// maxRelayShots caps how many bolts one player can report per update.
const maxRelayShots = 128

// relayShots validates the bolts a client reports about itself: a bounded
// list of [id, x, y] entries, each clamped to the Gauntlet's bounds, plus an
// optional fourth element: the shooter's look index, which the receiving
// clients resolve against their shared catalogue of looks. JSON cannot carry
// NaN/Infinities, so every number parsed here is already finite.
func relayShots(in [][]float64) [][]float64 {
	out := make([][]float64, 0, len(in))
	for i, s := range in {
		if i >= maxRelayShots {
			break
		}
		if len(s) < 3 {
			continue
		}
		shot := []float64{s[0], clamp(s[1], 0, dungeonW), clamp(s[2], 0, dungeonH)}
		if len(s) >= 4 {
			shot = append(shot, math.Trunc(clamp(s[3], 0, 4095)))
		}
		out = append(out, shot)
	}
	return out
}

type clientMsg struct {
	T    string  `json:"t"`
	Name string  `json:"name"`
	Pass string  `json:"pass"` // password for signup/login
	Up   string  `json:"up"`   // upgrade id for buy
	// Id names a weapon type for the buyw (buy weapon) and wield (equip
	// weapon) messages.
	Id   string  `json:"id"`
	X    float64 `json:"x"`
	Y    float64 `json:"y"`
	Dir  string  `json:"dir"`
	Text string  `json:"text"`
	// Zone is the scene the sending client believes it is in ("hub" or
	// "dungeon"); it stops a client that has not yet received the dungeon
	// reply from dragging its avatar around below.
	Zone string `json:"zone"`
	// I is the id of an entity the client is reporting damage to (hit/hitg).
	I int `json:"i"`
	// D is the damage amount of such a report.
	D float64 `json:"d"`
	// Sh are the bolts the sender is currently firing, as [id, x, y, look]
	// entries (the look index is optional and always clamped). The shooter
	// simulates them itself; the list is relayed to everyone else in the
	// Gauntlet so all players see the same gunfire.
	Sh [][]float64 `json:"sh"`
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
			if !h.anyInZone(zoneDungeon) {
				h.dungeon = nil
			}
			h.mu.Unlock()
			h.persistPlayer(p)
			h.store.flush()
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
		case "signup", "login":
			if registered {
				continue
			}
			if strings.TrimSpace(m.Name) == "" {
				conn.writeText(authFail("enter a username"))
				continue
			}
			if len(m.Pass) < 4 {
				conn.writeText(authFail("password must be at least 4 characters"))
				continue
			}
			name := sanitizeName(m.Name)
			var acc account
			var err error
			if m.T == "signup" {
				acc, err = h.store.create(name, m.Pass)
			} else {
				acc, err = h.store.auth(name, m.Pass)
			}
			if err != nil {
				conn.writeText(authFail(err.Error()))
				continue
			}
			registered = true
			h.startSession(conn, p, acc)

		case "buy":
			if !registered {
				continue
			}
			h.mu.Lock()
			var wallet []byte
			if def, ok := upgradeByID(m.Up); ok {
				lvl := p.upg[m.Up]
				if lvl < def.max {
					if cost := def.base + def.step*lvl; p.gold >= cost {
						p.gold -= cost
						p.upg[m.Up] = lvl + 1
						wallet = walletMsg(p)
					}
				}
			}
			h.mu.Unlock()
			if wallet != nil {
				conn.writeText(wallet)
			}

		case "buyw":
			// Buying a weapon type: a one-off unlock, not a levelling upgrade.
			if !registered {
				continue
			}
			h.mu.Lock()
			var wallet []byte
			if def, ok := weaponByID(m.Id); ok && !p.ownsWeapon(def.id) {
				if p.gold >= def.cost {
					p.gold -= def.cost
					if p.weps == nil {
						p.weps = map[string]bool{}
					}
					p.weps[def.id] = true
					// A fresh gun is immediately put in your hands.
					p.wepCur = def.id
					wallet = walletMsg(p)
				}
			}
			h.mu.Unlock()
			if wallet != nil {
				conn.writeText(wallet)
			}

		case "wield":
			// Switching between weapon types you already own. Free, instant.
			if !registered {
				continue
			}
			h.mu.Lock()
			var wallet []byte
			if p.ownsWeapon(m.Id) && p.wepCur != m.Id {
				p.wepCur = m.Id
				wallet = walletMsg(p)
			}
			h.mu.Unlock()
			if wallet != nil {
				conn.writeText(wallet)
			}

		case "pos":
			if !registered {
				continue
			}
			h.mu.Lock()
			// A client still in the village may keep reporting hub
			// positions for the moment between its "enter" and our reply;
			// ignore those so it does not dart around below.
			if p.zone == zoneDungeon && m.Zone == zoneHub {
				h.mu.Unlock()
				continue
			}
			if p.zone == zoneDungeon {
				p.x = clamp(m.X, 16, dungeonW-16)
				p.y = clamp(m.Y, 16, dungeonH-16)
			} else {
				p.x = clamp(m.X, 16, hubW-16)
				p.y = clamp(m.Y, 16, hubH-16)
			}
			p.dir = m.Dir
			entry := map[string]interface{}{
				"t":    "pos",
				"id":   p.id,
				"x":    p.x,
				"y":    p.y,
				"dir":  p.dir,
				"zone": p.zone,
			}
			// Along with its own position a Gauntlet player reports the bolts
			// it is firing, so the other players below can draw them too.
			if p.zone == zoneDungeon {
				entry["sh"] = relayShots(m.Sh)
			}
			msg := marshal(entry)
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
			if !registered {
				continue
			}
			h.mu.Lock()
			fresh := p.zone != zoneDungeon
			if fresh {
				p.zone = zoneDungeon
				p.dead = false
				p.x = dungeonW / 2
				p.y = dungeonH / 2
			}
			if h.dungeon == nil {
				h.dungeon = newDungeon(randomSeed())
			}
			// Rebuilt on every request so a retried "enter" (whose first
			// reply was lost on the wire) still lands the player below.
			dungeonMsg, stateMsg := h.dungeonInfo(p)
			leaveHub := marshal(map[string]interface{}{
				"t":    "pos",
				"id":   p.id,
				"x":    p.x,
				"y":    p.y,
				"dir":  p.dir,
				"zone": p.zone,
			})
			joinMsg := marshal(map[string]interface{}{"t": "join", "p": p.entry()})
			h.mu.Unlock()

			conn.writeText(dungeonMsg)
			conn.writeText(stateMsg)
			if fresh {
				// Tell the other Gauntlet players (still in the hub) that
				// this player has left the village, then tell the descended
				// players that a new adventurer joined them.
				h.broadcast(zoneHub, p.id, leaveHub)
				h.broadcast(zoneDungeon, p.id, joinMsg)
			}

		case "exit":
			if !registered || p.zone == zoneHub {
				continue
			}
			h.mu.Lock()
			p.zone = zoneHub
			p.dead = false
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
			empty := !h.anyInZone(zoneDungeon)
			if empty {
				h.dungeon = nil
			}
			h.mu.Unlock()

			conn.writeText(marshal(map[string]interface{}{"t": "sync", "players": others}))
			h.broadcast(zoneHub, p.id, joinMsg)
			// Let whoever is still in the Gauntlet know this player left it.
			h.broadcast(zoneDungeon, p.id, marshal(map[string]interface{}{"t": "leave", "id": p.id}))

		case "dead":
			// A fallen adventurer is no longer a target until they return
			// to the village.
			if !registered {
				continue
			}
			h.mu.Lock()
			p.dead = true
			h.mu.Unlock()
			// Whoever is still below should stop drawing their bolts.
			h.broadcast(zoneDungeon, p.id, marshal(map[string]interface{}{
				"t": "shots", "id": p.id,
			}))

		case "hit", "hitg":
			// Bolt collisions are detected by the shooting client (it sees
			// its own bolts), but the damage is applied here so everyone in
			// the Gauntlet agrees on what is still alive.
			if !registered || p.zone != zoneDungeon {
				continue
			}
			var evs []dEvent
			h.mu.Lock()
			if h.dungeon != nil {
				var reward int
				if m.T == "hit" {
					evs, reward = h.dungeon.hurtEnemy(m.I, m.D, p.id)
				} else {
					evs, reward = h.dungeon.hurtGenerator(m.I, m.D, p.id)
				}
				if reward > 0 {
					p.gold += int(math.Round(float64(reward) * p.goldMult()))
					evs = append(evs, dEvent{only: p.id, data: walletMsg(p)})
				}
			}
			h.mu.Unlock()
			h.emit(evs)
		}
	}
}

func randomByte() byte {
	var b [1]byte
	crand.Read(b[:])
	return b[0]
}

func authFail(err string) []byte {
	return marshal(map[string]interface{}{"t": "authfail", "err": err})
}

// walletMsg tells one client its authoritative gold, upgrade levels and
// which weapon types it owns (plus the one it is holding).
func walletMsg(p *player) []byte {
	return marshal(map[string]interface{}{
		"t": "wallet", "gold": p.gold, "upg": p.upg,
		"wep": p.ownedWeapons(), "wield": p.wepCur,
	})
}

// goldMult is the Greed Sigil: the one upgrade the server has to simulate
// itself, because gold lives in the wallet only the server owns.
func (p *player) goldMult() float64 {
	if p == nil || p.upg == nil {
		return 1
	}
	return math.Pow(1.5, float64(p.upg["greed"]))
}

// startSession registers an authenticated socket as a player and hands the
// client its welcome, restoring the saved position and wallet.
func (h *hub) startSession(conn *wsConn, p *player, acc account) {
	p.name = acc.Name
	p.hue = acc.Hue
	p.gold = acc.Gold
	p.upg = map[string]int{"dmg": 0, "rate": 0, "multi": 0}
	for k, v := range acc.Upgrades {
		p.upg[k] = v
	}
	// Weapon types: everyone owns the Gold Bolt, and an account only keeps a
	// different selection if it actually bought that type.
	p.weps = map[string]bool{}
	for _, w := range acc.Weapons {
		if _, ok := weaponByID(w); ok {
			p.weps[w] = true
		}
	}
	p.wepCur = "bolt"
	if acc.Weapon != "" && p.ownsWeapon(acc.Weapon) {
		p.wepCur = acc.Weapon
	}
	if acc.Zone == zoneHub {
		p.x = clamp(acc.X, 16, hubW-16)
		p.y = clamp(acc.Y, 16, hubH-16)
	} else {
		// A run does not survive a logout, so a returning adventurer comes
		// back to the village.
		p.x = float64(hubW)/2 + 64
		p.y = float64(hubH)/2 + 160
	}
	p.zone = zoneHub
	p.dir = "down"

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
		"gold":    p.gold,
		"upg":     p.upg,
		"wep":     p.ownedWeapons(),
		"wield":   p.wepCur,
	})
	joinMsg := marshal(map[string]interface{}{"t": "join", "p": p.entry()})
	h.mu.Unlock()

	conn.writeText(welcome)
	h.broadcast(zoneHub, p.id, joinMsg)
}

// persistPlayer snapshots one player's live state into the store. It is used
// when a socket drops; the periodic persistLoop covers connected players.
func (h *hub) persistPlayer(p *player) {
	h.store.saveProfile(p.name, p.zone, p.x, p.y, p.gold, p.upg, p.ownedWeapons(), p.wepCur)
}

// ---------------------------------------------------------------------------
// The Gauntlet: the shared dungeon, simulated here so that every player
// below sees the same monsters, generators, pickups and exit. Clients keep
// full control of their own hero (and detect their own bolt collisions),
// but everything else in this zone is owned by the server and pushed out as
// state snapshots plus one-off events.
// ---------------------------------------------------------------------------

// enemySpec mirrors the ENEMY table in index.html.
type enemySpec struct {
	hp    int
	speed float64
	dmg   int
	shot  float64 // ranged attack range in pixels; 0 = melee only
	gold  int     // gold awarded to the player who lands the killing blow
}

var enemyTypes = map[string]enemySpec{
	"grunt": {hp: 34, speed: 64, dmg: 9, shot: 0, gold: 5},
	"ghost": {hp: 22, speed: 98, dmg: 6, shot: 0, gold: 7},
	"demon": {hp: 70, speed: 54, dmg: 16, shot: 330, gold: 12},
}

// Weapon upgrades bought with gold in the village shop. The client keeps a
// matching table for display; these values are the authority.
type upgradeDef struct {
	id         string
	max        int
	base, step int
}

var upgradeDefs = []upgradeDef{
	{id: "dmg", max: 8, base: 40, step: 30},
	{id: "rate", max: 6, base: 60, step: 50},
	{id: "multi", max: 4, base: 140, step: 120},
	{id: "hot", max: 5, base: 50, step: 40},
	{id: "long", max: 5, base: 45, step: 35},
	{id: "cal", max: 4, base: 70, step: 60},
	{id: "rail", max: 4, base: 220, step: 180},
	{id: "bounce", max: 4, base: 180, step: 150},
	{id: "guide", max: 3, base: 300, step: 250},
	{id: "lucky", max: 5, base: 120, step: 100},
	{id: "heart", max: 4, base: 150, step: 120},
	{id: "boots", max: 4, base: 130, step: 110},
	{id: "orb", max: 4, base: 260, step: 200},
	{id: "paran", max: 2, base: 200, step: 150},
	{id: "chain", max: 3, base: 350, step: 300},
	{id: "vamp", max: 5, base: 160, step: 120},
	{id: "venom", max: 3, base: 200, step: 160},
	{id: "napalm", max: 3, base: 200, step: 160},
	{id: "hollow", max: 3, base: 260, step: 220},
	{id: "greed", max: 3, base: 300, step: 250},
	{id: "choke", max: 3, base: 60, step: 50},
	{id: "stubby", max: 2, base: 90, step: 70},
	{id: "bass", max: 3, base: 150, step: 120},
	{id: "chip", max: 3, base: 170, step: 130},
	{id: "shotgun", max: 1, base: 120, step: 0},
	{id: "spiral", max: 1, base: 180, step: 0},
	{id: "wall", max: 1, base: 160, step: 0},
	{id: "laser", max: 1, base: 500, step: 0},
	{id: "mine", max: 1, base: 240, step: 0},
	{id: "burst", max: 1, base: 200, step: 0},
	{id: "cross", max: 1, base: 220, step: 0},
	{id: "wave", max: 1, base: 340, step: 0},
	{id: "seek", max: 1, base: 420, step: 0},
	{id: "boom", max: 1, base: 280, step: 0},
	{id: "banana", max: 1, base: 45, step: 0},
	{id: "pizza", max: 1, base: 55, step: 0},
	{id: "bagu", max: 1, base: 60, step: 0},
	{id: "egg", max: 1, base: 50, step: 0},
	{id: "cheese", max: 1, base: 70, step: 0},
	{id: "donut", max: 1, base: 65, step: 0},
	{id: "avo", max: 1, base: 55, step: 0},
	{id: "taco", max: 1, base: 80, step: 0},
	{id: "hotdog", max: 1, base: 60, step: 0},
	{id: "candy", max: 1, base: 60, step: 0},
	{id: "cookie", max: 1, base: 58, step: 0},
	{id: "corn", max: 1, base: 95, step: 0},
	{id: "frog", max: 1, base: 110, step: 0},
	{id: "bee", max: 1, base: 120, step: 0},
	{id: "rat", max: 1, base: 100, step: 0},
	{id: "crab", max: 1, base: 105, step: 0},
	{id: "fish", max: 1, base: 65, step: 0},
	{id: "snail", max: 1, base: 90, step: 0},
	{id: "octo", max: 1, base: 130, step: 0},
	{id: "worm", max: 1, base: 70, step: 0},
	{id: "duck", max: 1, base: 115, step: 0},
	{id: "bat", max: 1, base: 125, step: 0},
	{id: "spider", max: 1, base: 100, step: 0},
	{id: "ghost", max: 1, base: 120, step: 0},
	{id: "sword", max: 1, base: 130, step: 0},
	{id: "axe", max: 1, base: 140, step: 0},
	{id: "dagger", max: 1, base: 100, step: 0},
	{id: "hammer", max: 1, base: 150, step: 0},
	{id: "wrench", max: 1, base: 110, step: 0},
	{id: "bomb", max: 1, base: 180, step: 0},
	{id: "dart", max: 1, base: 200, step: 0},
	{id: "anchor", max: 1, base: 190, step: 0},
	{id: "syringe", max: 1, base: 150, step: 0},
	{id: "pill", max: 1, base: 130, step: 0},
	{id: "mush", max: 1, base: 145, step: 0},
	{id: "cactus", max: 1, base: 105, step: 0},
	{id: "tree", max: 1, base: 115, step: 0},
	{id: "flower", max: 1, base: 75, step: 0},
	{id: "clover", max: 1, base: 120, step: 0},
	{id: "seed", max: 1, base: 65, step: 0},
	{id: "pump", max: 1, base: 100, step: 0},
	{id: "leaf", max: 1, base: 60, step: 0},
	{id: "rock", max: 1, base: 125, step: 0},
	{id: "rocket", max: 1, base: 130, step: 0},
	{id: "comet", max: 1, base: 140, step: 0},
	{id: "planet", max: 1, base: 160, step: 0},
	{id: "moon", max: 1, base: 95, step: 0},
	{id: "star", max: 1, base: 150, step: 0},
	{id: "spark", max: 1, base: 110, step: 0},
	{id: "fire", max: 1, base: 190, step: 0},
	{id: "ice", max: 1, base: 105, step: 0},
	{id: "drop", max: 1, base: 50, step: 0},
	{id: "rainbow", max: 1, base: 170, step: 0},
	{id: "eye", max: 1, base: 160, step: 0},
	{id: "brain", max: 1, base: 320, step: 0},
	{id: "valentine", max: 1, base: 200, step: 0},
	{id: "crystal", max: 1, base: 180, step: 0},
	{id: "crown", max: 1, base: 210, step: 0},
	{id: "wand", max: 1, base: 250, step: 0},
	{id: "orb2", max: 1, base: 300, step: 0},
	{id: "potion", max: 1, base: 230, step: 0},
	{id: "alien", max: 1, base: 190, step: 0},
	{id: "robot", max: 1, base: 200, step: 0},
	{id: "clown", max: 1, base: 160, step: 0},
	{id: "devil", max: 1, base: 260, step: 0},
	{id: "dracula", max: 1, base: 210, step: 0},
	{id: "brick", max: 1, base: 90, step: 0},
	{id: "tp", max: 1, base: 55, step: 0},
	{id: "spoon", max: 1, base: 85, step: 0},
	{id: "money", max: 1, base: 75, step: 0},
	{id: "dice", max: 1, base: 220, step: 0},
	{id: "card", max: 1, base: 120, step: 0},
	{id: "pawn", max: 1, base: 80, step: 0},
	{id: "yoyo", max: 1, base: 140, step: 0},
	{id: "disco", max: 1, base: 150, step: 0},
	{id: "balloon", max: 1, base: 105, step: 0},
	{id: "battery", max: 1, base: 100, step: 0},
	{id: "watch", max: 1, base: 90, step: 0},
	{id: "paint", max: 1, base: 70, step: 0},
	{id: "gift", max: 1, base: 95, step: 0},
	{id: "bell", max: 1, base: 70, step: 0},
	{id: "candle", max: 1, base: 120, step: 0},
	{id: "warn", max: 1, base: 85, step: 0},
	{id: "nuke", max: 1, base: 280, step: 0},
	{id: "guitar", max: 1, base: 150, step: 0},
	{id: "horn", max: 1, base: 135, step: 0},
	{id: "book", max: 1, base: 110, step: 0},
	{id: "pencil", max: 1, base: 60, step: 0},
	{id: "magnet", max: 1, base: 175, step: 0},
	{id: "bone", max: 1, base: 100, step: 0},
	{id: "kiss", max: 1, base: 130, step: 0},
	{id: "bulb", max: 1, base: 115, step: 0},
	{id: "puzzle", max: 1, base: 95, step: 0},
	{id: "umbrel", max: 1, base: 100, step: 0},
	{id: "kite", max: 1, base: 75, step: 0},
	{id: "coin", max: 1, base: 80, step: 0},
	{id: "ufo", max: 1, base: 170, step: 0},
	{id: "cat", max: 1, base: 145, step: 0},
	{id: "cloud", max: 1, base: 125, step: 0},
	{id: "sun", max: 1, base: 240, step: 0},
	{id: "hole", max: 1, base: 330, step: 0},
}

func upgradeByID(id string) (upgradeDef, bool) {
	for _, def := range upgradeDefs {
		if def.id == id {
			return def, true
		}
	}
	return upgradeDef{}, false
}

// Weapon types are a separate axis from upgrades: buying one unlocks a whole
// new gun (its own sprite, movement pattern and base damage on the client).
// The server only has to know the price to validate the purchase and the fact
// that the Gold Bolt is the free starter everyone owns — the bullets stay
// client-authoritative, so the stats live in index.html.
type weaponDef struct {
	id   string
	cost int
}

var weaponDefs = []weaponDef{
	{id: "bolt", cost: 0},
	{id: "scatter", cost: 150},
	{id: "salvo", cost: 200},
	{id: "cyclone", cost: 250},
	{id: "barrage", cost: 300},
	{id: "crosscore", cost: 350},
	{id: "minelayer", cost: 400},
	{id: "boomer", cost: 450},
	{id: "shockwave", cost: 550},
	{id: "seeker", cost: 650},
	{id: "beam", cost: 800},
}

func weaponByID(id string) (weaponDef, bool) {
	for _, def := range weaponDefs {
		if def.id == id {
			return def, true
		}
	}
	return weaponDef{}, false
}

type dEnemy struct {
	id      int
	typ     string
	x, y    float64
	hp      int
	maxHp   int
	speed   float64
	dmg     int
	shot    float64
	dir     string
	shootCd float64
	lastHit time.Time
}

type dGen struct {
	id    int
	typ   string
	x, y  float64
	hp    int
	maxHp int
	timer float64
	alive bool
}

type dPick struct {
	id   int
	typ  string
	x, y float64
}

type dFoe struct {
	id     int
	x, y   float64
	vx, vy float64
	dmg    int
	life   float64
}

// dEvent is a message produced by the simulation. Events are flushed once
// the hub lock has been released; only == "" means "everyone below".
type dEvent struct {
	only string
	data []byte
}

type dungeon struct {
	seed  uint32
	level int
	rnd   *rand.Rand
	grid  [][]int

	enemies []*dEnemy
	gens    []*dGen
	picks   []*dPick
	foes    []*dFoe
	byEnemy map[int]*dEnemy
	byGen   map[int]*dGen
	nextID  int
	// stateSeq numbers the snapshots so a client can drop a stale one.
	stateSeq int

	exitX, exitY float64
	exitActive   bool
	hasKey       bool
	foodT        float64
	genEvery     float64
	touchCd      map[string]float64
}

func newDungeon(seed uint32) *dungeon {
	d := &dungeon{seed: seed}
	d.startLevel(1)
	return d
}

// newID hands out ids that are never reused for the lifetime of the dungeon,
// so clients can tell a genuinely new entity apart from a stale snapshot.
func (d *dungeon) newID() int {
	d.nextID++
	return d.nextID
}

// r1 rounds to one decimal to keep the state snapshots small.
func r1(v float64) float64 { return math.Round(v*10) / 10 }

func (d *dungeon) startLevel(n int) {
	d.level = n
	d.rnd = rand.New(rand.NewSource(int64(d.seed)*31 + int64(n)))
	d.buildGrid()

	d.enemies = nil
	d.gens = nil
	d.picks = nil
	d.foes = nil
	d.byEnemy = make(map[int]*dEnemy)
	d.byGen = make(map[int]*dGen)
	d.touchCd = make(map[string]float64)
	d.exitActive = false
	d.hasKey = false

	count := 2 + n
	if count > 6 {
		count = 6
	}
	for i := 0; i < count; i++ {
		x, y := d.randomOpen(220)
		hp := int(math.Round(70 + float64(n)*18))
		g := &dGen{
			id: d.newID(), typ: d.pickType(), x: x, y: y,
			hp: hp, maxHp: hp, timer: 1.2 + d.rnd.Float64()*1.5, alive: true,
		}
		d.gens = append(d.gens, g)
		d.byGen[g.id] = g
	}
	d.genEvery = math.Max(1.3, 2.7-float64(n)*0.12)

	d.exitX, d.exitY = d.randomOpen(340)
	for j := 0; j < 2+n%2; j++ {
		x, y := d.randomOpen(140)
		d.picks = append(d.picks, &dPick{id: d.newID(), typ: "treasure", x: x, y: y})
	}
	d.foodT = 3
}

// buildGrid lays out the walls for one floor of the Gauntlet.
func (d *dungeon) buildGrid() {
	g := make([][]int, mapH)
	for y := 0; y < mapH; y++ {
		row := make([]int, mapW)
		for x := 0; x < mapW; x++ {
			if x == 0 || y == 0 || x == mapW-1 || y == mapH-1 {
				row[x] = 1
			}
		}
		g[y] = row
	}
	for yy := 3; yy < mapH-2; yy += 3 {
		for xx := 3; xx < mapW-2; xx += 3 {
			if d.rnd.Float64() >= 0.4 {
				continue
			}
			size := 1
			if d.rnd.Float64() < 0.35 {
				size = 2
			}
			for dy := 0; dy < size; dy++ {
				for dx := 0; dx < size; dx++ {
					if yy+dy < mapH-1 && xx+dx < mapW-1 {
						g[yy+dy][xx+dx] = 1
					}
				}
			}
		}
	}
	clearArea(g, mapW>>1, mapH>>1, 3)
	d.grid = g
}

func clearArea(g [][]int, tx, ty, rad int) {
	for y := ty - rad; y <= ty+rad; y++ {
		for x := tx - rad; x <= tx+rad; x++ {
			if x > 0 && y > 0 && x < mapW-1 && y < mapH-1 {
				g[y][x] = 0
			}
		}
	}
}

// gridString serialises the layout for the client, row by row.
func (d *dungeon) gridString() string {
	var b strings.Builder
	b.Grow(mapW * mapH)
	for y := 0; y < mapH; y++ {
		for x := 0; x < mapW; x++ {
			if d.grid[y][x] == 1 {
				b.WriteByte('1')
			} else {
				b.WriteByte('0')
			}
		}
	}
	return b.String()
}

func (d *dungeon) solid(tx, ty int) bool {
	if tx < 0 || ty < 0 || tx >= mapW || ty >= mapH {
		return true
	}
	return d.grid[ty][tx] == 1
}

func (d *dungeon) solidAt(x, y float64) bool {
	return d.solid(int(math.Floor(x/tileSize)), int(math.Floor(y/tileSize)))
}

func (d *dungeon) collides(x, y, r float64) bool {
	x0 := int(math.Floor((x - r) / tileSize))
	x1 := int(math.Floor((x + r) / tileSize))
	y0 := int(math.Floor((y - r) / tileSize))
	y1 := int(math.Floor((y + r) / tileSize))
	for ty := y0; ty <= y1; ty++ {
		for tx := x0; tx <= x1; tx++ {
			if d.solid(tx, ty) {
				return true
			}
		}
	}
	return false
}

// moveXY applies one movement step, one axis at a time, exactly like the
// client's moveEnt.
func (d *dungeon) moveXY(x, y, r, dx, dy float64) (float64, float64) {
	if !d.collides(x+dx, y, r) {
		x += dx
	}
	if !d.collides(x, y+dy, r) {
		y += dy
	}
	return x, y
}

func (d *dungeon) isOpen(tx, ty int) bool {
	return tx > 0 && ty > 0 && tx < mapW-1 && ty < mapH-1 && d.grid[ty][tx] == 0
}

// randomOpen picks a free spot at least minDist pixels from the spawn point
// in the middle of the map.
func (d *dungeon) randomOpen(minDist float64) (float64, float64) {
	cx := float64(dungeonW) / 2
	cy := float64(dungeonH) / 2
	for i := 0; i < 800; i++ {
		tx := 2 + int(d.rnd.Float64()*float64(mapW-4))
		ty := 2 + int(d.rnd.Float64()*float64(mapH-4))
		if !d.isOpen(tx, ty) {
			continue
		}
		px := float64(tx)*tileSize + tileSize/2
		py := float64(ty)*tileSize + tileSize/2
		if math.Hypot(px-cx, py-cy) < minDist {
			continue
		}
		return px, py
	}
	return cx, cy
}

// pickType chooses a monster for a generator, weighted by floor depth.
func (d *dungeon) pickType() string {
	r := d.rnd.Float64()
	if d.level <= 1 {
		if r < 0.82 {
			return "grunt"
		}
		return "ghost"
	}
	if d.level <= 3 {
		if r < 0.55 {
			return "grunt"
		}
		if r < 0.85 {
			return "ghost"
		}
		return "demon"
	}
	if r < 0.4 {
		return "grunt"
	}
	if r < 0.72 {
		return "ghost"
	}
	return "demon"
}

func (d *dungeon) spawnEnemy(x, y float64, typ string) {
	spec, ok := enemyTypes[typ]
	if !ok {
		typ = "grunt"
		spec = enemyTypes["grunt"]
	}
	mul := 1 + float64(d.level-1)*0.16
	hp := int(math.Round(float64(spec.hp) * mul))
	e := &dEnemy{
		id: d.newID(), typ: typ, x: x, y: y,
		hp: hp, maxHp: hp,
		speed:   spec.speed * (1 + float64(d.level-1)*0.03),
		dmg:     spec.dmg,
		shot:    spec.shot,
		dir:     "down",
		shootCd: 1 + d.rnd.Float64(),
	}
	d.enemies = append(d.enemies, e)
	d.byEnemy[e.id] = e
}

// hurtEnemy applies a client-reported bolt hit. It returns the events the
// rest of the Gauntlet has to hear about and, when the hit is fatal, the gold
// the killer earns.
func (d *dungeon) hurtEnemy(id int, dmg float64, by string) ([]dEvent, int) {
	e := d.byEnemy[id]
	if e == nil {
		return nil, 0
	}
	e.hp -= int(math.Round(clamp(dmg, 0, 150)))
	e.lastHit = time.Now()
	if e.hp > 0 {
		return nil, 0
	}
	delete(d.byEnemy, id)
	for i, cur := range d.enemies {
		if cur == e {
			d.enemies = append(d.enemies[:i], d.enemies[i+1:]...)
			break
		}
	}
	return []dEvent{{data: marshal(map[string]interface{}{
		"t": "kill", "i": e.id, "x": r1(e.x), "y": r1(e.y), "tp": e.typ, "by": by,
	})}}, enemyTypes[e.typ].gold
}

// hurtGenerator applies a client-reported bolt hit against a generator. The
// last one to fall drops the key. It reports the gold the killer earns.
func (d *dungeon) hurtGenerator(id int, dmg float64, by string) ([]dEvent, int) {
	g := d.byGen[id]
	if g == nil || !g.alive {
		return nil, 0
	}
	g.hp -= int(math.Round(clamp(dmg, 0, 150)))
	if g.hp > 0 {
		return nil, 0
	}
	g.hp = 0
	g.alive = false
	evs := []dEvent{{data: marshal(map[string]interface{}{
		"t": "gendead", "i": g.id, "x": r1(g.x), "y": r1(g.y), "by": by,
	})}}
	const reward = 5
	for _, other := range d.gens {
		if other.alive {
			return evs, reward
		}
	}
	if !d.hasKey {
		d.picks = append(d.picks, &dPick{id: d.newID(), typ: "key", x: g.x, y: g.y})
	}
	return evs, reward
}

// step advances the shared simulation by dt and reports what happened.
func (d *dungeon) step(dt float64, players []*player) []dEvent {
	var evs []dEvent

	for id, cd := range d.touchCd {
		if cd <= dt {
			delete(d.touchCd, id)
		} else {
			d.touchCd[id] = cd - dt
		}
	}

	for _, e := range d.enemies {
		var tgt *player
		best := math.MaxFloat64
		for _, p := range players {
			dd := (p.x-e.x)*(p.x-e.x) + (p.y-e.y)*(p.y-e.y)
			if dd < best {
				best = dd
				tgt = p
			}
		}
		if tgt == nil {
			continue
		}
		ang := math.Atan2(tgt.y-e.y, tgt.x-e.x)
		vx, vy := math.Cos(ang), math.Sin(ang)
		e.x, e.y = d.moveXY(e.x, e.y, enemyRadius, vx*e.speed*dt, vy*e.speed*dt)
		if math.Abs(vx) > math.Abs(vy) {
			if vx < 0 {
				e.dir = "left"
			} else {
				e.dir = "right"
			}
		} else {
			if vy < 0 {
				e.dir = "up"
			} else {
				e.dir = "down"
			}
		}

		if e.shot > 0 {
			e.shootCd -= dt
			if e.shootCd <= 0 && math.Hypot(tgt.x-e.x, tgt.y-e.y) < e.shot {
				e.shootCd = 2.1 + d.rnd.Float64()
				d.foes = append(d.foes, &dFoe{
					id: d.newID(), x: e.x, y: e.y,
					vx: vx * 230, vy: vy * 230, dmg: 11, life: 2.2,
				})
			}
		}

		if d.touchCd[tgt.id] <= 0 &&
			math.Hypot(tgt.x-e.x, tgt.y-e.y) < enemyRadius+playerRadius {
			d.touchCd[tgt.id] = 0.8
			evs = append(evs, dEvent{only: tgt.id, data: marshal(map[string]interface{}{
				"t": "hurt", "d": e.dmg, "tp": e.typ,
			})})
		}
	}

	for i := len(d.foes) - 1; i >= 0; i-- {
		f := d.foes[i]
		f.x += f.vx * dt
		f.y += f.vy * dt
		f.life -= dt
		dead := f.life <= 0 || d.solidAt(f.x, f.y)
		if !dead {
			for _, p := range players {
				if math.Hypot(f.x-p.x, f.y-p.y) < playerRadius+7 {
					evs = append(evs, dEvent{only: p.id, data: marshal(map[string]interface{}{
						"t": "hurt", "d": f.dmg,
					})})
					dead = true
					break
				}
			}
		}
		if dead {
			d.foes = append(d.foes[:i], d.foes[i+1:]...)
		}
	}

	for _, g := range d.gens {
		if !g.alive {
			continue
		}
		g.timer -= dt
		if g.timer <= 0 {
			g.timer = d.genEvery
			if len(d.enemies) < maxEnemies {
				d.spawnEnemy(g.x+d.rnd.Float64()*20-10, g.y+d.rnd.Float64()*20-10, g.typ)
			}
		}
	}

	for i := len(d.picks) - 1; i >= 0; i-- {
		pk := d.picks[i]
		for _, p := range players {
			if math.Hypot(pk.x-p.x, pk.y-p.y) < 16+playerRadius {
				evs = append(evs, dEvent{data: marshal(map[string]interface{}{
					"t": "pickup", "i": pk.id, "tp": pk.typ,
					"x": r1(pk.x), "y": r1(pk.y), "by": p.id,
				})})
				if pk.typ == "key" {
					d.hasKey = true
					d.exitActive = true
				} else if pk.typ == "treasure" {
					p.gold += int(math.Round(10 * p.goldMult()))
					evs = append(evs, dEvent{only: p.id, data: walletMsg(p)})
				}
				d.picks = append(d.picks[:i], d.picks[i+1:]...)
				break
			}
		}
	}

	d.foodT -= dt
	if d.foodT <= 0 {
		d.foodT = 7
		food := 0
		for _, pk := range d.picks {
			if pk.typ == "food" {
				food++
			}
		}
		if food < 4 {
			x, y := d.randomOpen(150)
			d.picks = append(d.picks, &dPick{id: d.newID(), typ: "food", x: x, y: y})
		}
	}

	// Any living player standing on the exit takes the whole group deeper.
	if d.exitActive {
		for _, p := range players {
			if math.Hypot(p.x-d.exitX, p.y-d.exitY) < 20 {
				for _, all := range players {
					all.x = float64(dungeonW) / 2
					all.y = float64(dungeonH) / 2
				}
				d.startLevel(d.level + 1)
				evs = append(evs, dEvent{data: d.levelMsg()})
				evs = append(evs, dEvent{data: d.stateMsg()})
				return evs
			}
		}
	}

	return evs
}

// stateMsg is the full picture of the Gauntlet, sent ~10 times a second.
func (d *dungeon) stateMsg() []byte {
	d.stateSeq++
	enemies := make([]map[string]interface{}, 0, len(d.enemies))
	for _, e := range d.enemies {
		flashed := time.Since(e.lastHit) < 150*time.Millisecond
		enemies = append(enemies, map[string]interface{}{
			"i": e.id, "tp": e.typ, "x": r1(e.x), "y": r1(e.y),
			"d": e.dir, "h": e.hp, "hm": e.maxHp, "f": flashed,
		})
	}
	gens := make([]map[string]interface{}, 0, len(d.gens))
	for _, g := range d.gens {
		gens = append(gens, map[string]interface{}{
			"i": g.id, "x": r1(g.x), "y": r1(g.y),
			"h": g.hp, "hm": g.maxHp, "a": g.alive, "tp": g.typ,
		})
	}
	picks := make([]map[string]interface{}, 0, len(d.picks))
	for _, p := range d.picks {
		picks = append(picks, map[string]interface{}{
			"i": p.id, "tp": p.typ, "x": r1(p.x), "y": r1(p.y),
		})
	}
	foes := make([]map[string]interface{}, 0, len(d.foes))
	for _, f := range d.foes {
		foes = append(foes, map[string]interface{}{
			"i": f.id, "x": r1(f.x), "y": r1(f.y),
		})
	}
	return marshal(map[string]interface{}{
		"t":   "state",
		"n":   d.stateSeq,
		"lv":  d.level,
		"e":   enemies,
		"g":   gens,
		"p":   picks,
		"fs":  foes,
		"ex":  map[string]interface{}{"x": r1(d.exitX), "y": r1(d.exitY), "on": d.exitActive},
		"key": d.hasKey,
	})
}

// levelMsg carries the new layout when the group descends one floor.
func (d *dungeon) levelMsg() []byte {
	return marshal(map[string]interface{}{
		"t": "level", "lv": d.level, "grid": d.gridString(),
	})
}

// runDungeon ticks the shared simulation and pushes it to everyone below.
func (h *hub) runDungeon() {
	t := time.NewTicker(dungeonTick)
	defer t.Stop()
	n := 0
	for range t.C {
		var evs []dEvent
		h.mu.Lock()
		if h.dungeon != nil {
			players := make([]*player, 0, len(h.players))
			for _, p := range h.players {
				if p.zone == zoneDungeon && !p.dead {
					players = append(players, p)
				}
			}
			if len(players) > 0 {
				evs = h.dungeon.step(dungeonTick.Seconds(), players)
				n++
				if n%snapEvery == 0 {
					evs = append(evs, dEvent{data: h.dungeon.stateMsg()})
				}
			}
		}
		h.mu.Unlock()
		h.emit(evs)
	}
}

// dungeonInfo builds the pair of frames a player needs on entering the
// Gauntlet: the map (seed, floor, wall grid, spawn point, companions) and the
// first state snapshot. Callers must hold h.mu.
func (h *hub) dungeonInfo(p *player) ([]byte, []byte) {
	d := h.dungeon
	others := make([]map[string]interface{}, 0, len(h.players))
	for id, op := range h.players {
		if id == p.id || op.zone != zoneDungeon {
			continue
		}
		others = append(others, op.entry())
	}
	return marshal(map[string]interface{}{
		"t":       "dungeon",
		"seed":    d.seed,
		"lv":      d.level,
		"grid":    d.gridString(),
		"x":       p.x,
		"y":       p.y,
		"players": others,
	}), d.stateMsg()
}

// emit delivers simulation results once the hub lock is no longer held.
func (h *hub) emit(evs []dEvent) {
	for _, e := range evs {
		if e.only != "" {
			h.sendOnly(e.only, e.data)
		} else {
			h.broadcast(zoneDungeon, "", e.data)
		}
	}
}

func (h *hub) sendOnly(id string, data []byte) {
	h.mu.Lock()
	p := h.players[id]
	h.mu.Unlock()
	if p != nil {
		p.conn.writeText(data)
	}
}

// ---------------------------------------------------------------------------
// Tiny account database. A flat JSON file is loaded into memory on boot and
// written back with an atomic rename, so reads are map lookups and there are
// no external dependencies. Passwords are stored as salted PBKDF2-HMAC-SHA256.
// ---------------------------------------------------------------------------

const (
	pbkdf2Iters = 100000
	pbkdf2Key   = 32
	saltLen     = 16
	minPassLen  = 4
)

type account struct {
	Name     string         `json:"name"`
	Salt     string         `json:"salt"`
	Hash     string         `json:"hash"`
	Gold     int            `json:"gold"`
	Upgrades map[string]int `json:"upgrades"`
	// Weapons is the set of weapon types this account has bought, Weapon the
	// one it last held. Both default to the free Gold Bolt.
	Weapons []string `json:"weapons,omitempty"`
	Weapon  string   `json:"weapon,omitempty"`
	Zone    string   `json:"zone"`
	X       float64  `json:"x"`
	Y       float64  `json:"y"`
	Hue     int      `json:"hue"`
}

type store struct {
	mu    sync.Mutex
	users map[string]*account
	path  string
	dirty bool
}

func newStore(path string) *store {
	s := &store{users: make(map[string]*account), path: path}
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &s.users)
	}
	if s.users == nil {
		s.users = make(map[string]*account)
	}
	return s
}

func newSalt() string {
	var b [saltLen]byte
	crand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// pbkdf2SHA256 derives a key with PBKDF2-HMAC-SHA256 (RFC 2898). The standard
// library ships the pieces but no helper, so it is assembled here.
func pbkdf2SHA256(pass, salt []byte) []byte {
	return pbkdf2SHA256Iter(pass, salt, pbkdf2Iters)
}

func pbkdf2SHA256Iter(pass, salt []byte, iters int) []byte {
	prf := hmac.New(sha256.New, pass)
	hLen := prf.Size()
	blocks := (pbkdf2Key + hLen - 1) / hLen
	dk := make([]byte, 0, blocks*hLen)
	var idx [4]byte
	for block := 1; block <= blocks; block++ {
		prf.Reset()
		prf.Write(salt)
		binary.BigEndian.PutUint32(idx[:], uint32(block))
		prf.Write(idx[:])
		u := prf.Sum(nil)
		t := make([]byte, len(u))
		copy(t, u)
		for i := 1; i < iters; i++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		dk = append(dk, t...)
	}
	return dk[:pbkdf2Key]
}

func hashPassword(pass, salt string) string {
	return hex.EncodeToString(pbkdf2SHA256([]byte(pass), []byte(salt)))
}

func (s *store) create(name, pass string) (account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[name]; ok {
		return account{}, errors.New("that username is already taken")
	}
	salt := newSalt()
	acc := account{
		Name:     name,
		Salt:     salt,
		Hash:     hashPassword(pass, salt),
		Gold:     0,
		Upgrades: map[string]int{"dmg": 0, "rate": 0, "multi": 0},
		Weapons:  []string{"bolt"},
		Weapon:   "bolt",
		Zone:     zoneHub,
		X:        float64(hubW)/2 + 64,
		Y:        float64(hubH)/2 + 160,
		Hue:      int(randomByte()) * 360 / 256,
	}
	s.users[name] = &acc
	s.dirty = true
	return acc, nil
}

func (s *store) auth(name, pass string) (account, error) {
	s.mu.Lock()
	var cp account
	ok := false
	if acc := s.users[name]; acc != nil {
		cp = *acc
		ok = true
	}
	s.mu.Unlock()
	if !ok {
		return account{}, errors.New("no account with that username")
	}
	if subtle.ConstantTimeCompare([]byte(hashPassword(pass, cp.Salt)), []byte(cp.Hash)) != 1 {
		return account{}, errors.New("incorrect password")
	}
	return cp, nil
}

// saveProfile folds a live player's state back into their account.
func (s *store) saveProfile(name, zone string, x, y float64, gold int, upg map[string]int, weapons []string, weapon string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	acc := s.users[name]
	if acc == nil {
		return
	}
	acc.Zone, acc.X, acc.Y, acc.Gold = zone, x, y, gold
	if upg != nil {
		acc.Upgrades = map[string]int{"dmg": 0, "rate": 0, "multi": 0}
		for k, v := range upg {
			acc.Upgrades[k] = v
		}
	}
	if weapons != nil {
		acc.Weapons = weapons
		acc.Weapon = weapon
	}
	s.dirty = true
}

// flush writes the in-memory database to disk if it changed. It clears the
// dirty flag under the lock before marshalling so a concurrent change is not
// lost: it simply leaves the flag set for the next flush.
func (s *store) flush() {
	s.mu.Lock()
	if !s.dirty {
		s.mu.Unlock()
		return
	}
	s.dirty = false
	b, err := json.MarshalIndent(s.users, "", "  ")
	s.mu.Unlock()
	if err != nil {
		log.Println("store: marshal failed:", err)
		return
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		log.Println("store: write failed:", err)
		return
	}
	if err := os.Rename(tmp, s.path); err != nil {
		log.Println("store: rename failed:", err)
	}
}

// persistLoop periodically saves every connected player's progress and flushes
// the database to disk.
func (h *hub) persistLoop() {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for range t.C {
		type snap struct {
			name, zone string
			x, y       float64
			gold       int
			upg        map[string]int
			weapons    []string
			weapon     string
		}
		h.mu.Lock()
		snaps := make([]snap, 0, len(h.players))
		for _, p := range h.players {
			u := make(map[string]int, len(p.upg))
			for k, v := range p.upg {
				u[k] = v
			}
			snaps = append(snaps, snap{p.name, p.zone, p.x, p.y, p.gold, u, p.ownedWeapons(), p.wepCur})
		}
		h.mu.Unlock()
		for _, sn := range snaps {
			h.store.saveProfile(sn.name, sn.zone, sn.x, sn.y, sn.gold, sn.upg, sn.weapons, sn.weapon)
		}
		h.store.flush()
	}
}

// ---------------------------------------------------------------------------
// HTTP entry point.
// ---------------------------------------------------------------------------

func main() {
	h := newHub("accounts.json")
	go h.runDungeon()
	go h.persistLoop()

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
	mux.Handle("/sprites/", http.StripPrefix("/sprites/", http.FileServer(http.Dir("sprites"))))
	mux.Handle("/audio/", http.StripPrefix("/audio/", http.FileServer(http.Dir("audio"))))

	// Self-hosted source downloads: /index.html and /go-server.go save to disk
	// rather than rendering, so anyone can grab a copy of the game. We read the
	// bytes ourselves instead of using http.ServeFile, because ServeFile
	// redirects any path ending in "index.html" to "./" and would never hand
	// the file over as a download.
	download := func(name, ctype string) {
		mux.HandleFunc("/"+name, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			data, err := os.ReadFile(name)
			if err != nil {
				http.NotFound(w, r)
				return
			}
			// no-store so a redeployed build is never masked by a cached copy.
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Content-Type", ctype)
			w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
			w.Header().Set("Content-Length", strconv.Itoa(len(data)))
			w.Write(data)
		})
	}
	download("index.html", "text/html; charset=utf-8")
	download("go-server.go", "text/plain; charset=utf-8")

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		// Phones cache aggressively; never serve a stale index.html so a
		// redeployed build (e.g. new touch controls) is picked up on reload.
		w.Header().Set("Cache-Control", "no-store")
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
