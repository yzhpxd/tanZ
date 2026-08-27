package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

type NodeInfo struct {
	NodeID          string  `json:"node_id"`
	DisplayName     string  `json:"-"`
	Tag             string  `json:"-"` // 分组标签 (由后台设置)
	IP              string  `json:"-"`
	IPv4            string  `json:"ipv4"`
	IPv6            string  `json:"ipv6"`
	CPUUsage        float64 `json:"cpu_usage"`
	MemUsage        float64 `json:"mem_usage"`
	DiskUsage       float64 `json:"disk_usage"`
	NetIn           uint64  `json:"net_in"`
	NetOut          uint64  `json:"net_out"`
	NetInTotal      uint64  `json:"-"` // 服务端累计下行流量 (bytes)
	NetOutTotal     uint64  `json:"-"` // 服务端累计上行流量 (bytes)
	Uptime          uint64  `json:"uptime"`
	Timestamp       int64   `json:"-"`
	LastSeen        string  `json:"-"`
	IsOnline        bool    `json:"-"`
	NotifiedOffline bool    `json:"-"`
}

type TagCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// NodeView 是 /api 接口返回的单台节点视图

type NodeView struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	IP         string  `json:"ip"`
	IPv4       string  `json:"ipv4"`
	IPv6       string  `json:"ipv6"`
	Online     bool    `json:"online"`
	Uptime     string  `json:"uptime"`
	CPU        float64 `json:"cpu"`
	Mem        float64 `json:"mem"`
	Disk       float64 `json:"disk"`
	NetInRate  string  `json:"net_in_rate"`
	NetOutRate string  `json:"net_out_rate"`
	LastSeen   string  `json:"last_seen"`
	Tag        string  `json:"tag"`
}

// DashData 是 /api 接口返回的完整仪表盘数据 (局部刷新用)

type DashData struct {
	Admin       bool       `json:"admin"`
	Total       int        `json:"total"`
	Online      int        `json:"online"`
	Offline     int        `json:"offline"`
	NetInRate   string     `json:"net_in_rate"`
	NetOutRate  string     `json:"net_out_rate"`
	NetInTotal  string     `json:"net_in_total"`
	NetOutTotal string     `json:"net_out_total"`
	Tags        []TagCount `json:"tags"`
	Nodes       []NodeView `json:"nodes"`
	GeoTotal    int        `json:"geo_total"`
	GeoResolved int        `json:"geo_resolved"`
	GeoError    string     `json:"geo_error"`
	GeoMiss     []string   `json:"geo_miss"`
}

type dashSnapshot struct {
	list        []*NodeInfo
	total       int
	online      int
	netInRate   uint64
	netOutRate  uint64
	netInTotal  uint64
	netOutTotal uint64
	tags        []TagCount
}

type PageData struct {
	Nodes          []*NodeInfo
	Tags           []TagCount
	TotalNodes     int
	OnlineNodes    int
	OfflineNodes   int
	NetInRateStr   string
	NetOutRateStr  string
	NetInTotalStr  string
	NetOutTotalStr string
	IsAdmin        bool
	AdminUser  string
	TOTPSecret string
	SiteName   string
	CustomCode string
	Favicon    string
	TGToken    string // TG Bot Token
	TGChatID   string // TG Chat ID
}

type AdminConfig struct {
	Username      string `json:"username"`
	PasswordHash  string `json:"password_hash"`
	TOTPEncrypted string `json:"totp_encrypted"`
	SiteName      string `json:"site_name"`
	CustomCode    string `json:"custom_code"`
	Favicon       string `json:"favicon"`
	TGToken       string `json:"tg_token"`   // TG Bot Token
	TGChatID      string `json:"tg_chat_id"` // TG Chat ID
}

type LoginData struct {
	Error    string
	Has2FA   bool
	SiteName string
	Favicon  string
}

type SecretConfig struct {
	SessionToken string `json:"session_token"`
	AESKey       string `json:"aes_key"`
}

// NodeTraffic 记录单个节点的累计流量，用于持久化

type NodeTraffic struct {
	NetInTotal  uint64 `json:"net_in_total"`
	NetOutTotal uint64 `json:"net_out_total"`
}

// IPGroupRule 按 IP 前缀自动分组规则 (ipgroups.json)

type IPGroupRule struct {
	Name     string   `json:"name"`
	Prefixes []string `json:"prefixes"`
}

var (
	nodesStatus = make(map[string]*NodeInfo)
	customNames = make(map[string]string)
	nodeOrder   = make([]string, 0)
	nodeStats   = make(map[string]*NodeTraffic)
	nodeTags    = make(map[string]string)
	mu          sync.Mutex
	namesFile   = "names.json"
	orderFile   = "order.json"
	statsFile   = "stats.json"
	tagsFile    = "tags.json"
	ipGroupsFile = "ipgroups.json"
	ipGroups     []IPGroupRule
	ipGroupsMod  time.Time
	ipGeo        = make(map[string]string) // ip -> 国家代码 (ipgeo.json 缓存)
	ipGeoFile    = "ipgeo.json"
	geoLastTry   time.Time                 // 上次调用 IP 归属地接口的时间 (失败后退避)
	geoRefresh   time.Time                 // 上次成功刷新缓存的时间
	geoTotal     int                       // 最近一次解析请求的 IP 数 (诊断)
	geoResolved  int                       // 其中成功数 (诊断)
	geoLastError string                    // 最近一次失败原因 (诊断)
	geoMiss      []string                  // 最近一次仍未识别的 IP 列表 (诊断)
	configFile  = "config.json"
	config      AdminConfig

	sessionAuthToken string
	aesSecretKey     []byte

	autoDetectedHost string // [新增] 用于存储自动探测到的当前服务端域名
)

// ==========================================
// 🔒 安全与加密算法区
// ==========================================

func loadSecrets() {
	b, err := os.ReadFile("secret.json")
	if err != nil {
		fmt.Println("初始化: 未找到 secret.json，正在自动生成安全密钥...")
		aesBytes := make([]byte, 16)
		rand.Read(aesBytes)
		newAESKey := hex.EncodeToString(aesBytes)

		tokenBytes := make([]byte, 24)
		rand.Read(tokenBytes)
		newSessionToken := "TzSession_" + hex.EncodeToString(tokenBytes)

		sec := SecretConfig{
			SessionToken: newSessionToken,
			AESKey:       newAESKey,
		}

		fileData, _ := json.MarshalIndent(sec, "", "  ")
		if err := os.WriteFile("secret.json", fileData, 0600); err != nil {
			fmt.Printf("🚨 严重警告: 无法保存 secret.json，请检查目录权限！(%v)\n", err)
			os.Exit(1)
		}

		sessionAuthToken = sec.SessionToken
		aesSecretKey = []byte(sec.AESKey)
		fmt.Println("✅ 安全密钥自动生成完毕！")
		return
	}

	var sec SecretConfig
	err = json.Unmarshal(b, &sec)
	if err != nil {
		fmt.Println("🚨 严重警告: secret.json 格式错误！请删除文件让其重新生成。")
		os.Exit(1)
	}
	if len(sec.AESKey) != 32 {
		fmt.Printf("🚨 严重警告: aes_key 长度必须是 32 字节，当前长度为 %d！请删除 secret.json 让程序重新生成。\n", len(sec.AESKey))
		os.Exit(1)
	}

	sessionAuthToken = sec.SessionToken
	aesSecretKey = []byte(sec.AESKey)
}

func hashPassword(plain string) string {
	h := sha256.New()
	h.Write([]byte(plain + "tz_salt_9982"))
	return hex.EncodeToString(h.Sum(nil))
}

func encryptAES(text string) string {
	if text == "" {
		return ""
	}
	c, _ := aes.NewCipher(aesSecretKey)
	gcm, _ := cipher.NewGCM(c)
	nonce := make([]byte, gcm.NonceSize())
	io.ReadFull(rand.Reader, nonce)
	sealed := gcm.Seal(nonce, nonce, []byte(text), nil)
	return base64.StdEncoding.EncodeToString(sealed)
}

func decryptAES(cryptoText string) string {
	if cryptoText == "" {
		return ""
	}
	data, err := base64.StdEncoding.DecodeString(cryptoText)
	if err != nil {
		return ""
	}
	c, _ := aes.NewCipher(aesSecretKey)
	gcm, _ := cipher.NewGCM(c)
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return ""
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return ""
	}
	return string(plain)
}

func loadConfig() {
	b, err := os.ReadFile(configFile)
	if err == nil {
		json.Unmarshal(b, &config)
	} else {
		config = AdminConfig{
			Username:      "admin",
			PasswordHash:  hashPassword("admin"),
			TOTPEncrypted: "",
			SiteName:      "服务器状态监控",
			CustomCode:    "",
			Favicon:       "",
			TGToken:       "",
			TGChatID:      "",
		}
		saveConfig()
	}
	if config.SiteName == "" {
		config.SiteName = "服务器状态监控"
	}
}

func saveConfig() { b, _ := json.MarshalIndent(config, "", "  "); os.WriteFile(configFile, b, 0644) }
func loadNames()  { b, err := os.ReadFile(namesFile); if err == nil { json.Unmarshal(b, &customNames) } }
func saveNames()  { b, _ := json.Marshal(customNames); os.WriteFile(namesFile, b, 0644) }
func loadOrder()  { b, err := os.ReadFile(orderFile); if err == nil { json.Unmarshal(b, &nodeOrder) } }
func saveOrder()  { b, _ := json.Marshal(nodeOrder); os.WriteFile(orderFile, b, 0644) }
func loadStats()  { b, err := os.ReadFile(statsFile); if err == nil { json.Unmarshal(b, &nodeStats) } }
func saveStats()  { b, _ := json.Marshal(nodeStats); os.WriteFile(statsFile, b, 0644) }
func loadTags()   { b, err := os.ReadFile(tagsFile); if err == nil { json.Unmarshal(b, &nodeTags) } }
func saveTags()   { b, _ := json.Marshal(nodeTags); os.WriteFile(tagsFile, b, 0644) }

// loadIPGroupsLocked 热加载 ipgroups.json (文件变更后自动重读), 必须在持有 mu 锁时调用
func loadIPGroupsLocked() {
	info, err := os.Stat(ipGroupsFile)
	if err != nil {
		return
	}
	if !info.ModTime().After(ipGroupsMod) {
		return
	}
	b, err := os.ReadFile(ipGroupsFile)
	if err != nil {
		return
	}
	// 兼容两种写法: 数组 [ {...} ] 或单个对象 {...}
	var raw json.RawMessage
	if json.Unmarshal(b, &raw) != nil {
		return
	}
	var rules []IPGroupRule
	if err := json.Unmarshal(raw, &rules); err != nil {
		var one IPGroupRule
		if err2 := json.Unmarshal(raw, &one); err2 != nil || one.Name == "" {
			return
		}
		rules = []IPGroupRule{one}
	}
	ipGroups = rules
	ipGroupsMod = info.ModTime()
}

// matchIPGroup 按 IP 前缀匹配自动分组名
func matchIPGroup(ip string) string {
	for _, g := range ipGroups {
		for _, p := range g.Prefixes {
			if p != "" && strings.HasPrefix(ip, p) {
				return g.Name
			}
		}
	}
	return ""
}

// effectiveTag 手动标签 > IP 前缀规则 > IP 归属地国家 > 名称国家代码
func effectiveTag(id string, info *NodeInfo) string {
	if t := nodeTags[id]; t != "" {
		return t
	}
	ip := info.IPv4
	if ip == "" {
		ip = info.IP
	}
	if g := matchIPGroup(ip); g != "" {
		return g
	}
	if g := geoGroup(ip); g != "" {
		return g
	}
	return nameGroup(info.DisplayName)
}

// countryCN 常用国家代码 -> 中文名 (未收录的代码直接使用原值)
var countryCN = map[string]string{
	"US": "美国", "JP": "日本", "HK": "香港", "SG": "新加坡", "DE": "德国",
	"FR": "法国", "GB": "英国", "RU": "俄罗斯", "TW": "台湾", "KR": "韩国",
	"CA": "加拿大", "AU": "澳大利亚", "NL": "荷兰", "IN": "印度", "VN": "越南",
	"TH": "泰国", "MY": "马来西亚", "ID": "印尼", "PH": "菲律宾", "IT": "意大利",
	"ES": "西班牙", "PL": "波兰", "SE": "瑞典", "FI": "芬兰", "CH": "瑞士",
	"BR": "巴西", "MX": "墨西哥", "ZA": "南非", "TR": "土耳其", "AE": "阿联酋",
	"UA": "乌克兰", "CZ": "捷克", "IE": "爱尔兰", "DK": "丹麦", "NO": "挪威",
	"AT": "奥地利", "BE": "比利时", "PT": "葡萄牙", "RO": "罗马尼亚", "GR": "希腊",
	"IL": "以色列", "AR": "阿根廷", "CL": "智利", "NZ": "新西兰", "CN": "中国",
	"MO": "澳门",
}

// nameCodeCN 节点名称中的国家代码 -> 中文名 (命名兜底, 如 oracle-jp-win)
var nameCodeCN = map[string]string{
	"jp": "日本", "id": "印尼", "us": "美国", "hk": "香港", "sg": "新加坡",
	"de": "德国", "fr": "法国", "gb": "英国", "kr": "韩国", "tw": "台湾",
	"ru": "俄罗斯", "ca": "加拿大", "au": "澳大利亚", "nl": "荷兰", "in": "印度",
	"vn": "越南", "th": "泰国", "my": "马来西亚", "ph": "菲律宾", "br": "巴西",
	"mx": "墨西哥", "tr": "土耳其", "ae": "阿联酋", "za": "南非", "il": "以色列",
	"ch": "瑞士", "se": "瑞典", "no": "挪威", "fi": "芬兰", "dk": "丹麦",
	"pl": "波兰", "cz": "捷克", "it": "意大利", "es": "西班牙", "pt": "葡萄牙",
	"gr": "希腊", "ie": "爱尔兰", "at": "奥地利", "be": "比利时", "cn": "中国",
	"mo": "澳门", "ar": "阿根廷", "cl": "智利", "nz": "新西兰", "ua": "乌克兰",
	"ro": "罗马尼亚", "bg": "保加利亚", "ir": "伊朗", "pk": "巴基斯坦", "bd": "孟加拉",
}

var nameCodeRe = regexp.MustCompile(`(?i)(^|[^a-z])(jp|id|us|hk|sg|de|fr|gb|kr|tw|ru|ca|au|nl|in|vn|th|my|ph|br|mx|tr|ae|za|il|ch|se|no|fi|dk|pl|cz|it|es|pt|gr|ie|at|be|cn|mo|ar|cl|nz|ua|ro|bg|ir|pk|bd)([^a-z]|$)`)

// nameGroup 从节点名称中提取国家代码作为最后兜底分组
func nameGroup(name string) string {
	m := nameCodeRe.FindStringSubmatch(name)
	if m == nil {
		return ""
	}
	if cn, ok := nameCodeCN[strings.ToLower(m[2])]; ok {
		return cn
	}
	return ""
}

// geoGroup 返回 IP 归属地分组名
func geoGroup(ip string) string {
	if ip == "" {
		return ""
	}
	code, ok := ipGeo[ip]
	if !ok || code == "" {
		return ""
	}
	if cn, ok := countryCN[code]; ok {
		return cn
	}
	return code
}

func loadIPGeo() {
	b, err := os.ReadFile(ipGeoFile)
	if err == nil {
		json.Unmarshal(b, &ipGeo)
	}
}

func saveIPGeo() {
	b, _ := json.Marshal(ipGeo)
	os.WriteFile(ipGeoFile, b, 0644)
}

// geoBatchIPAPI 批量查询 ip-api.com (免费版 HTTP, 45次/分钟, 100个IP/次)
func geoBatchIPAPI(need []string) bool {
	type geoReq struct {
		Query  string `json:"query"`
		Fields string `json:"fields"`
	}
	req := make([]geoReq, 0, len(need))
	for _, ip := range need {
		req = append(req, geoReq{Query: ip, Fields: "status,message,countryCode"})
	}
	body, err := json.Marshal(req)
	if err != nil {
		return false
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post("http://ip-api.com/batch", "application/json", bytes.NewBuffer(body))
	if err != nil {
		mu.Lock()
		geoLastError = "ip-api.com 不可达: " + err.Error()
		mu.Unlock()
		return false
	}
	defer resp.Body.Close()

	var results []struct {
		Status      string `json:"status"`
		CountryCode string `json:"countryCode"`
		Query       string `json:"query"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		mu.Lock()
		geoLastError = "ip-api.com 响应解析失败"
		mu.Unlock()
		return false
	}

	mu.Lock()
	changed := false
	for _, r := range results {
		if r.Status == "success" && r.CountryCode != "" && ipGeo[r.Query] != r.CountryCode {
			ipGeo[r.Query] = r.CountryCode
			changed = true
		}
	}
	if changed {
		saveIPGeo()
	}
	geoLastError = ""
	mu.Unlock()
	return true
}

// geoPerIP 单 IP 兜底查询 (urlTmpl 含 {ip} 占位, 并发 4)
func geoPerIP(urlTmpl string, need []string) {
	type result struct {
		ip, code string
	}
	results := make(chan result, len(need))
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for _, ip := range need {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			client := &http.Client{Timeout: 8 * time.Second}
			resp, err := client.Get(strings.Replace(urlTmpl, "{ip}", ip, 1))
			if err != nil {
				return
			}
			defer resp.Body.Close()
			var d struct {
				CountryCode string `json:"country_code"`
				Country     string `json:"country"`
			}
			if json.NewDecoder(resp.Body).Decode(&d) == nil {
				code := d.CountryCode
				if code == "" {
					code = d.Country
				}
				if code != "" {
					results <- result{ip, code}
				}
			}
		}(ip)
	}
	go func() {
		wg.Wait()
		close(results)
	}()
	changed := false
	for r := range results {
		mu.Lock()
		if ipGeo[r.ip] != r.code {
			ipGeo[r.ip] = r.code
			changed = true
		}
		mu.Unlock()
	}
	if changed {
		mu.Lock()
		saveIPGeo()
		mu.Unlock()
	}
}

// resolveGeo 批量解析未缓存的节点公网 IP (ip-api.com -> api.ip.sb -> ipwhois.app 兜底)
func resolveGeo() {
	mu.Lock()
	now := time.Now()
	need := make([]string, 0, 16)
	seen := make(map[string]bool)
	for _, info := range nodesStatus {
		ip := info.IPv4
		if ip == "" {
			ip = info.IP
		}
		if ip == "" || seen[ip] {
			continue
		}
		seen[ip] = true
		if _, ok := ipGeo[ip]; !ok {
			need = append(need, ip)
		}
	}
	// 已全部解析且超过 24 小时 -> 全量刷新一次
	if !geoRefresh.IsZero() && now.Sub(geoRefresh) > 24*time.Hour && len(need) == 0 && len(seen) > 0 {
		for ip := range seen {
			need = append(need, ip)
		}
	}
	rateOK := geoLastTry.IsZero() || now.Sub(geoLastTry) > 10*time.Second
	if rateOK {
		geoLastTry = now
	}
	mu.Unlock()

	if len(need) == 0 || !rateOK {
		return
	}
	if len(need) > 100 {
		need = need[:100]
	}

	geoBatchIPAPI(need)

	// 未解析的 IP 依次走 HTTPS 兜底源
	mu.Lock()
	var remain []string
	for _, ip := range need {
		if _, done := ipGeo[ip]; !done {
			remain = append(remain, ip)
		}
	}
	mu.Unlock()
	if len(remain) > 0 {
		geoPerIP("https://ipwhois.app/json/{ip}", remain)
		mu.Lock()
		var remain2 []string
		for _, ip := range remain {
			if _, done := ipGeo[ip]; !done {
				remain2 = append(remain2, ip)
			}
		}
		mu.Unlock()
		if len(remain2) > 0 {
			geoPerIP("https://ipinfo.io/{ip}/json", remain2)
		}
	}

	mu.Lock()
	resolved := 0
	var miss []string
	for _, ip := range need {
		if _, done := ipGeo[ip]; done {
			resolved++
		} else {
			miss = append(miss, ip)
		}
	}
	geoTotal = len(need)
	geoResolved = resolved
	geoMiss = miss
	geoRefresh = now
	if len(need) == resolved {
		geoLastError = ""
	}
	mu.Unlock()
	if len(miss) > 0 {
		fmt.Printf("[geo] 解析 %d 个 IP: 成功 %d, 未识别 %d 个: %v\n", len(need), resolved, len(miss), miss)
	} else {
		fmt.Printf("[geo] 解析 %d 个 IP: 全部成功\n", len(need))
	}
}

func checkAdminAuth(r *http.Request) bool {
	cookie, err := r.Cookie("admin_session")
	if err != nil {
		return false
	}
	return cookie.Value == sessionAuthToken
}

func verifyTOTP(secret string, userCode string) bool {
	if secret == "" {
		return true
	}
	secret = strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(secret, " ", ""), "=", ""))
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		key, err = base32.StdEncoding.DecodeString(secret)
		if err != nil {
			return false
		}
	}
	t := time.Now().Unix() / 30
	for i := int64(-1); i <= 1; i++ {
		if generateTOTP(key, t+i) == userCode {
			return true
		}
	}
	return false
}

func generateTOTP(key []byte, t int64) string {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(t))
	mac := hmac.New(sha1.New, key)
	mac.Write(buf)
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0xf
	value := int64(((int(sum[offset]) & 0x7f) << 24) | ((int(sum[offset+1]) & 0xff) << 16) | ((int(sum[offset+2]) & 0xff) << 8) | (int(sum[offset+3]) & 0xff))
	return fmt.Sprintf("%06d", value%1000000)
}

// ==========================================
// 📡 通知与状态巡检模块
// ==========================================

// 后台定时检查掉线状态 (15 秒)
func startOfflineChecker() {
	ticker := time.NewTicker(15 * time.Second)
	for range ticker.C {
		mu.Lock()
		tgToken := config.TGToken
		tgChatID := config.TGChatID
		serverDomain := autoDetectedHost // [新增] 读取自动探测的域名
		if serverDomain == "" {
			serverDomain = "Server" // 兜底：如果程序刚启动还没收到任何请求时的默认名字
		}
		mu.Unlock()

		if tgToken == "" || tgChatID == "" {
			continue // 未配置推送时跳过
		}

		now := time.Now().Unix()
		mu.Lock()
		for id, info := range nodesStatus {
			isOffline := (now - info.Timestamp) > 30

			if isOffline && !info.NotifiedOffline {
				info.NotifiedOffline = true
				name := info.DisplayName
				if name == "" {
					name = id
				}
				// [修改] 使用自动探测的域名
				msg := fmt.Sprintf("🚨 [%s] 节点掉线: [%s] 已失去连接！\nIP: %s", serverDomain, name, info.IP)
				go sendNotify(tgToken, tgChatID, msg)
			} else if !isOffline && info.NotifiedOffline {
				info.NotifiedOffline = false
				name := info.DisplayName
				if name == "" {
					name = id
				}
				// [修改] 使用自动探测的域名
				msg := fmt.Sprintf("✅ [%s] 节点恢复: [%s] 已重新连接！", serverDomain, name)
				go sendNotify(tgToken, tgChatID, msg)
			}
		}
		mu.Unlock()
	}
}

// 执行 Telegram 通知发送
func sendNotify(tgToken, tgChatID, msg string) error {
	// 彻底清理可能的不可见字符（防幽灵空格/回车等）
	tgToken = strings.TrimSpace(tgToken)
	tgChatID = strings.TrimSpace(tgChatID)
	tgChatID = strings.ReplaceAll(tgChatID, "\n", "")
	tgChatID = strings.ReplaceAll(tgChatID, "\r", "")
	tgChatID = strings.ReplaceAll(tgChatID, "\t", "")

	if tgToken == "" || tgChatID == "" {
		return fmt.Errorf("TG 机器人配置不完整")
	}

	// 改用更稳定的 POST + JSON 请求体方式
	target := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", tgToken)

	payload := map[string]interface{}{
		"chat_id": tgChatID,
		"text":    msg,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("JSON打包失败: %v", err)
	}

	req, err := http.NewRequest("POST", target, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("创建请求失败: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// 增加超时控制
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("网络请求失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		// 故意在报错中把 chat_id 用单引号括起来并输出长度，用于抓虫
		return fmt.Errorf("Telegram API 错误 (状态码: %d): %s\n[Debug] 实际发送的ChatID: '%s' (字符长度:%d)",
			resp.StatusCode, string(respBody), tgChatID, len(tgChatID))
	}
	return nil
}

// ==========================================
// 📄 HTML 模板定义
// ==========================================

const htmlTemplate = `
<!DOCTYPE html>
<html>
<head>
    <title>{{.SiteName}}</title>
    <link rel="icon" href="{{if .Favicon}}{{.Favicon}}{{else}}data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>🌍</text></svg>{{end}}">
    <style>
        body { font-family: Arial, sans-serif; background: #f4f6f9; margin: 40px; }
        .header-box { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
        .header-actions { display: flex; gap: 10px; align-items: center; }
        table { width: 100%; border-collapse: collapse; background: #fff; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #00add8; color: white; }
        tr:hover { background-color: #f5f5f5; }
        .online { color: #4caf50; font-weight: bold; }
        .offline { color: #f44336; font-weight: bold; }
        .editable { color: #00add8; cursor: pointer; border-bottom: 1px dashed #00add8; }
        .copy-btn, .action-btn { padding: 4px 10px; font-size: 0.85em; color: #555; background-color: #fff; border: 1px solid #ccc; border-radius: 4px; cursor: pointer; transition: all 0.2s; }
        .copy-btn { margin-left: 8px; padding: 2px 6px; }
        .copy-btn:hover, .action-btn:hover { background-color: #e0e0e0; }
        .login-btn { padding: 6px 14px; font-size: 0.95em; text-decoration: none; background-color: #00add8; color: white; border: none; border-radius: 4px; cursor: pointer;}
        .login-btn.logout { background-color: #e0e0e0; color: #333; }
        .login-btn.settings { background-color: #ff9800; color: #fff; border:none; }
        .login-btn.settings:hover { background-color: #e68a00; }
        .seq-num { display: inline-block; width: 20px; font-weight: bold; color: #555; }
        .drag-handle { cursor: grab; color: #aaa; margin-left: 5px; font-size: 18px; user-select: none; transition: color 0.2s; }
        .drag-handle:hover { color: #00add8; }
        .drag-handle:active { cursor: grabbing; }
        .draggable-row.dragging { opacity: 0.6; background-color: #e3f2fd; }
        .progress-bg { background-color: #e9ecef; border-radius: 4px; height: 6px; width: 100%; min-width: 80px; margin-top: 6px; overflow: hidden; }
        .progress-bar { height: 100%; border-radius: 4px; transition: width 0.5s ease, background-color 0.5s ease; min-width: 4px; }
        .val-text { font-size: 0.95em; color: #333; }
        .btn-delete { color: white; background-color: #ff5252; border: none; padding: 4px 10px; border-radius: 4px; cursor: pointer; transition: background 0.2s; font-size: 0.9em; }
        .btn-delete:hover { background-color: #d32f2f; }

        /* 统计概览卡片 */
        .stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 20px; }
        .stat-card { position: relative; overflow: hidden; background: #fff; border: 1px solid #edf0f4; border-radius: 10px; padding: 16px 20px 14px; box-shadow: 0 1px 2px rgba(15,23,42,0.05); transition: box-shadow 0.2s ease, transform 0.2s ease; }
        .stat-card:hover { box-shadow: 0 6px 16px rgba(15,23,42,0.08); transform: translateY(-1px); }
        .stat-label { font-size: 13px; color: #8a94a6; }
        .stat-value { margin-top: 5px; font-size: 30px; font-weight: 700; color: #1a2233; line-height: 1.15; font-variant-numeric: tabular-nums; }
        .stat-value-warn { color: #f44336; }
        .stat-card-icon { position: absolute; top: 14px; right: 14px; width: 30px; height: 30px; }
        .stat-card-watermark { position: absolute; right: -12px; bottom: -14px; width: 88px; height: 88px; opacity: 0.07; }
        .net-rows { margin-top: 6px; display: flex; flex-direction: column; gap: 6px; }
        .net-row { display: flex; align-items: baseline; justify-content: space-between; gap: 8px; }
        .net-rate { display: inline-flex; align-items: center; gap: 5px; font-size: 15px; font-weight: 600; color: #1a2233; font-variant-numeric: tabular-nums; }
        .net-arrow { width: 14px; height: 14px; }
        .net-total { font-size: 13px; color: #8a94a6; font-variant-numeric: tabular-nums; }
        @media (max-width: 960px) { .stats-grid { grid-template-columns: repeat(2, 1fr); } }
        @media (max-width: 560px) { .stats-grid { grid-template-columns: 1fr; } }
        @media (prefers-reduced-motion: reduce) { .stat-card { transition: none; } .stat-card:hover { transform: none; } }

        /* 筛选栏与标签 (基础样式, 自定义代码可覆盖) */
        .tz-filter { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; background: #fff; border: 1px solid #e8ebf0; border-radius: 10px; padding: 10px 16px; margin-bottom: 16px; }
        .tz-filter .f-label { display: inline-flex; align-items: center; gap: 6px; color: #8a94a6; font-size: 13px; margin-right: 6px; }
        .tz-filter .f-label svg { width: 14px; height: 14px; }
        .tz-tab { border: 1px solid #e8ebf0; background: #f8fafc; color: #6b7280; border-radius: 999px; padding: 4px 13px; font-size: 13px; cursor: pointer; transition: all .15s ease; }
        .tz-tab:hover { border-color: #3b82f6; color: #3b82f6; }
        .tz-tab.active { background: #eff6ff; border-color: #3b82f6; color: #3b82f6; font-weight: 600; box-shadow: 0 0 0 3px rgba(59,130,246,.12); }
        .tz-tab .n { opacity: .65; margin-left: 4px; font-variant-numeric: tabular-nums; }
        .tz-empty td { text-align: center; padding: 24px; color: #8a94a6; }
        .tz-node-tag { display: inline-block; margin-left: 8px; padding: 1px 8px; font-size: 11px; color: #3b82f6; background: #eff6ff; border-radius: 999px; vertical-align: middle; white-space: nowrap; }

        .modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); z-index: 1000; justify-content: center; align-items: center; }
        .modal-content { background: white; padding: 25px; border-radius: 8px; width: 400px; box-shadow: 0 4px 15px rgba(0,0,0,0.2); max-height: 90vh; overflow-y: auto; }
        .modal-content h3 { margin-top: 0; margin-bottom: 20px; text-align: center; }
        .modal-content label { display: block; margin-bottom: 5px; font-size: 0.9em; color: #555; font-weight: bold; }
        .modal-content input, .modal-content textarea { width: 100%; padding: 10px; margin-bottom: 15px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }
        .modal-content input[type="file"] { padding: 6px; margin-bottom: 5px; }
        .file-hint { font-size: 0.8em; color: #888; margin-bottom: 15px; line-height: 1.4; }
        .modal-content textarea { font-family: monospace; font-size: 0.85em; resize: vertical; }
        .modal-content button { width: 100%; padding: 10px; background: #00add8; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 1em; margin-top: 5px; }
        .modal-content button:hover { background: #008cae; }
        .close-btn { float: right; cursor: pointer; font-size: 1.5em; color: #888; line-height: 0.5; }
    </style>
    {{safeHTML .CustomCode}}
</head>
<body>
    <div class="header-box">
        <h2>
            {{if .Favicon}}<img src="{{.Favicon}}" style="height: 24px; vertical-align: middle; margin-right: 8px; border-radius: 4px;">{{end}}
            {{.SiteName}}
        </h2>
        <div class="header-actions">
            {{if .IsAdmin}} 
                <button class="btn-delete" onclick="batchDelete()" style="padding: 6px 14px; font-size: 0.95em;">🗑️ 批量删除</button>
                <button class="action-btn" onclick="copyAllIPs()">📄 复制全部IP</button>
                <button class="login-btn settings" onclick="openSettings()">⚙️ 系统设置</button>
                <a href="/logout" class="login-btn logout">退出管理</a> 
            {{else}} 
                <a href="/login" class="login-btn">管理登录</a> 
            {{end}}
        </div>
    </div>

    <svg width="0" height="0" style="position:absolute" aria-hidden="true">
        <defs>
            <symbol id="i-globe" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="12" cy="12" r="9"></circle>
                <path d="M3 12h18"></path>
                <path d="M12 3c2.5 2.6 3.8 5.6 3.8 9s-1.3 6.4-3.8 9c-2.5-2.6-3.8-5.6-3.8-9s1.3-6.4 3.8-9z"></path>
            </symbol>
            <symbol id="i-online" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="12" cy="12" r="9"></circle>
                <path d="M8.5 12.2l2.4 2.4 4.6-5"></path>
            </symbol>
            <symbol id="i-offline" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round">
                <circle cx="12" cy="12" r="9"></circle>
                <path d="M5.6 5.6l12.8 12.8"></path>
            </symbol>
            <symbol id="i-network" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">
                <path d="M12 5v14"></path>
                <path d="M7 9l5-4 5 4"></path>
                <path d="M7 15l5 4 5-4"></path>
            </symbol>
            <symbol id="i-arrow-up" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M12 19V5"></path>
                <path d="M5 12l7-7 7 7"></path>
            </symbol>
            <symbol id="i-arrow-down" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M12 5v14"></path>
                <path d="M19 12l-7 7-7-7"></path>
            </symbol>
        </defs>
    </svg>

    <div class="stats-grid">
        <div class="stat-card">
            <svg class="stat-card-icon" style="color:#00add8;"><use href="#i-globe"></use></svg>
            <svg class="stat-card-watermark" style="color:#00add8;"><use href="#i-globe"></use></svg>
            <div class="stat-label">设备总数</div>
            <div class="stat-value">{{.TotalNodes}}</div>
        </div>
        <div class="stat-card">
            <svg class="stat-card-icon" style="color:#4caf50;"><use href="#i-online"></use></svg>
            <svg class="stat-card-watermark" style="color:#4caf50;"><use href="#i-online"></use></svg>
            <div class="stat-label">在线设备</div>
            <div class="stat-value">{{.OnlineNodes}}</div>
        </div>
        <div class="stat-card">
            <svg class="stat-card-icon" style="color:#8a94a6;"><use href="#i-offline"></use></svg>
            <svg class="stat-card-watermark" style="color:#8a94a6;"><use href="#i-offline"></use></svg>
            <div class="stat-label">离线设备</div>
            <div class="stat-value {{if gt .OfflineNodes 0}}stat-value-warn{{end}}">{{.OfflineNodes}}</div>
        </div>
        <div class="stat-card">
            <svg class="stat-card-icon" style="color:#00add8;"><use href="#i-network"></use></svg>
            <svg class="stat-card-watermark" style="color:#00add8;"><use href="#i-network"></use></svg>
            <div class="stat-label">网络统计</div>
            <div class="net-rows">
                <div class="net-row">
                    <span class="net-rate"><svg class="net-arrow" style="color:#00add8;"><use href="#i-arrow-up"></use></svg><span class="tz-rate-text">{{.NetOutRateStr}}</span></span>
                    <span class="net-total">{{.NetOutTotalStr}}</span>
                </div>
                <div class="net-row">
                    <span class="net-rate"><svg class="net-arrow" style="color:#4caf50;"><use href="#i-arrow-down"></use></svg><span class="tz-rate-text">{{.NetInRateStr}}</span></span>
                    <span class="net-total">{{.NetInTotalStr}}</span>
                </div>
            </div>
        </div>
    </div>

    <div class="tz-filter">
        <span class="f-label">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 5h18l-7 8v5l-4 2v-7L3 5z"></path></svg>
            筛选
        </span>
        <button type="button" class="tz-tab active" data-key="all">全部<span class="n">{{len .Nodes}}</span></button>
        <button type="button" class="tz-tab" data-key="online">在线<span class="n">{{.OnlineNodes}}</span></button>
        <button type="button" class="tz-tab" data-key="offline">离线<span class="n">{{.OfflineNodes}}</span></button>
        {{range .Tags}}<button type="button" class="tz-tab" data-key="tag-{{.Name}}">{{.Name}}<span class="n">{{.Count}}</span></button>{{end}}
    </div>

    <table>
        <thead>
            <tr>
                {{if .IsAdmin}}<th style="width: 30px; text-align: center;"><input type="checkbox" id="selectAll" onclick="toggleSelectAll(this)" title="全选/取消全选"></th>{{end}}
                <th>排序</th>
                <th>节点名称</th>
                <th>IP 地址</th>
                <th>状态</th>
                <th>运行时间</th>
                <th>CPU 使用率</th>
                <th>内存 使用率</th>
                <th>磁盘 使用率</th>
                <th>实时速率 (↓入/↑出)</th>
                <th>最后更新</th>
                {{if .IsAdmin}}<th>操作</th>{{end}}
            </tr>
        </thead>
        <tbody id="table-body">
        {{range $index, $info := .Nodes}}
        <tr class="draggable-row" {{if $.IsAdmin}}draggable="true"{{else}}draggable="false"{{end}} data-id="{{.NodeID}}" data-ip="{{if .IPv4}}{{.IPv4}}{{else}}{{.IP}}{{end}}" data-tag="{{.Tag}}">
            
            {{if $.IsAdmin}}<td style="text-align: center;"><input type="checkbox" class="node-cb" value="{{.NodeID}}" onclick="onCheckboxClick()"></td>{{end}}
            
            <td>
                <span class="seq-num">{{inc $index}}</span>
                {{if $.IsAdmin}}<span class="drag-handle" title="按住拖拽排序">☰</span>{{end}}
            </td>
            {{if $.IsAdmin}}<td class="editable tz-name" onclick="renameNode('{{.NodeID}}', '{{.DisplayName}}')" title="点击修改备注名">{{.DisplayName}}{{if .Tag}} <span class="tz-node-tag">{{.Tag}}</span>{{end}}</td>{{else}}<td class="tz-name">{{.DisplayName}}{{if .Tag}} <span class="tz-node-tag">{{.Tag}}</span>{{end}}</td>{{end}}
            
            <td class="tz-ip" style="font-size: 0.95em; color: #444;">
                {{if $.IsAdmin}}
                    <div style="display: flex; align-items: center;">
                        <span>{{if .IPv4}}{{.IPv4}}{{else}}{{.IP}}{{end}}</span>
                        <button class="copy-btn" onclick="copyIP('{{if .IPv4}}{{.IPv4}}{{else}}{{.IP}}{{end}}', this)">复制</button>
                    </div>
                    {{if .IPv6}}
                        <div style="font-size: 12px; color: #888; margin-top: 4px; word-break: break-all;">{{.IPv6}}</div>
                    {{end}}
                {{else}}
                    <span style="color:#aaa; font-style: italic;">*.*.*.* (登录可见)</span>
                {{end}}
            </td>

            <td>{{if .IsOnline}}<span class="online">在线</span>{{else}}<span class="offline">离线</span>{{end}}</td>
            <td class="tz-uptime" style="font-size: 0.9em; color: #666;">{{formatUptime .Uptime}}</td>
            <td><div class="val-text">{{printf "%.1f" .CPUUsage}}%</div><div class="progress-bg"><div class="progress-bar" style="width: {{.CPUUsage}}%; background-color: {{if gt .CPUUsage 90.0}}#f44336{{else if gt .CPUUsage 70.0}}#ff9800{{else}}#4caf50{{end}};"></div></div></td>
            <td><div class="val-text">{{printf "%.1f" .MemUsage}}%</div><div class="progress-bg"><div class="progress-bar" style="width: {{.MemUsage}}%; background-color: {{if gt .MemUsage 90.0}}#f44336{{else if gt .MemUsage 70.0}}#ff9800{{else}}#4caf50{{end}};"></div></div></td>
            <td><div class="val-text">{{printf "%.1f" .DiskUsage}}%</div><div class="progress-bg"><div class="progress-bar" style="width: {{.DiskUsage}}%; background-color: {{if gt .DiskUsage 90.0}}#f44336{{else if gt .DiskUsage 80.0}}#ff9800{{else}}#4caf50{{end}};"></div></div></td>
            <td class="tz-rate">↓ {{formatRate .NetIn}} / ↑ {{formatRate .NetOut}}</td>
            <td class="tz-seen">{{.LastSeen}}</td>
            {{if $.IsAdmin}}
            <td class="tz-ops">
                <button class="action-btn" onclick="tagNode('{{.NodeID}}', '{{.Tag}}')" title="设置分组标签">标签</button>
                <button class="btn-delete" onclick="deleteNode('{{.NodeID}}', '{{.DisplayName}}')">删除</button>
            </td>
            {{end}}
        </tr>
        {{end}}
        <tr class="tz-empty" id="tz-empty-row" style="display:none;"><td>该分组暂无设备</td></tr>
        </tbody>
    </table>

    {{if .IsAdmin}}
    <div id="settingsModal" class="modal">
        <div class="modal-content">
            <span class="close-btn" onclick="closeSettings()">&times;</span>
            <h3>管理后台设置</h3>
            <label>探针名称 (自定义站点标题)</label>
            <input type="text" id="cfgSiteName" value="{{.SiteName}}">
            <label>后台用户名</label>
            <input type="text" id="cfgUser" value="{{.AdminUser}}">
            <label>后台新密码 (不修改请留空)</label>
            <input type="password" id="cfgPass" placeholder="留空则保持不变">
            <label>2FA 密钥 (Base32格式)</label>
            <input type="text" id="cfgTOTP" value="{{.TOTPSecret}}" placeholder="留空则禁用 2FA">
            
            <hr style="border: 0; border-top: 1px solid #ddd; margin: 20px 0;">
            <label style="color: #00add8;">🤖 Telegram 提醒 (掉线/恢复通知)</label>
            <label>Bot Token</label>
            <input type="text" id="cfgTGToken" value="{{.TGToken}}" placeholder="123456789:ABC-def1234...">
            <label>Chat ID</label>
            <input type="text" id="cfgTGChatID" value="{{.TGChatID}}" placeholder="例如: 123456789">
            
            <button type="button" onclick="testTGNotify(event)" style="background: #ff9800; margin-bottom: 15px;">🔔 测试 TG 通知</button>

            <hr style="border: 0; border-top: 1px solid #ddd; margin: 20px 0;">
            <label>站点图标 (Favicon)</label>
            <input type="file" id="cfgFavicon" accept="image/png, image/jpeg, image/ico, image/svg+xml, image/gif">
            <div class="file-hint">支持 jpg/png/ico。不选则保持原样，建议尺寸 64x64。</div>

            <label>自定义代码 (美化CSS / 统计JS)</label>
            <input type="hidden" id="cfgCustomCode" value="{{.CustomCode}}">
            <textarea id="cfgCustomCodeArea" rows="3" placeholder="例如: <style> body { background: #000; } </style>"></textarea>
            
            <button onclick="submitSettingsAsync()">保存所有设置</button>
        </div>
    </div>
    {{end}}

    <script>
        {{if .IsAdmin}}
        document.addEventListener('DOMContentLoaded', () => {
            const area = document.getElementById('cfgCustomCodeArea');
            if(area) area.value = ` + "`{{.CustomCode}}`" + `;
        });
        {{end}}

        let refreshTimer = setInterval(fetchData, 5000);
        
        function killRefresh() {
            if(refreshTimer) {
                clearInterval(refreshTimer);
                refreshTimer = null; 
            }
        }

        function resumeRefresh() {
            killRefresh();
            refreshTimer = setInterval(fetchData, 5000);
        }

        // ===== 局部数据刷新: 每 5 秒拉取 /api 原地更新, 不再整页刷新 =====
        function esc(s) {
            return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
                return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
            });
        }
        function jsStr(s) { return String(s == null ? '' : s).replace(/['"]/g, ''); }
        function pctColor(v, warn1, warn2) { return v > warn1 ? '#f44336' : v > warn2 ? '#ff9800' : '#4caf50'; }

        function buildRowHtml(n, admin) {
            var ipMain = admin ? (n.ipv4 || n.ip || '') : '****';
            var ipv6 = (admin && n.ipv6) ? '<div style="font-size:12px;color:#888;margin-top:4px;word-break:break-all;">' + esc(n.ipv6) + '</div>' : '';
            var tagHtml = n.tag ? ' <span class="tz-node-tag">' + esc(n.tag) + '</span>' : '';
            var cpu = (n.cpu || 0).toFixed(1), mem = (n.mem || 0).toFixed(1), disk = (n.disk || 0).toFixed(1);
            var cells = '';
            if (admin) {
                cells += '<td style="text-align:center;"><input type="checkbox" class="node-cb" value="' + esc(n.id) + '" onclick="onCheckboxClick()"></td>';
                cells += '<td><span class="seq-num"></span><span class="drag-handle" title="按住拖拽排序">☰</span></td>';
                cells += '<td class="editable tz-name" onclick="renameNode(\'' + jsStr(n.id) + '\', \'' + jsStr(n.name) + '\')" title="点击修改备注名">' + esc(n.name) + tagHtml + '</td>';
                cells += '<td class="tz-ip" style="font-size:0.95em;color:#444;"><div style="display:flex;align-items:center;"><span>' + esc(ipMain) + '</span><button class="copy-btn" onclick="copyIP(\'' + jsStr(ipMain) + '\', this)">复制</button></div>' + ipv6 + '</td>';
            } else {
                cells += '<td><span class="seq-num"></span></td>';
                cells += '<td class="tz-name">' + esc(n.name) + tagHtml + '</td>';
                cells += '<td class="tz-ip" style="font-size:0.95em;color:#444;"><span style="color:#aaa;font-style:italic;">*.*.*.* (登录可见)</span></td>';
            }
            cells += '<td>' + (n.online ? '<span class="online">在线</span>' : '<span class="offline">离线</span>') + '</td>';
            cells += '<td class="tz-uptime" style="font-size:0.9em;color:#666;">' + esc(n.uptime) + '</td>';
            cells += '<td><div class="val-text">' + cpu + '%</div><div class="progress-bg"><div class="progress-bar" style="width:' + cpu + '%;background-color:' + pctColor(n.cpu, 90, 70) + ';"></div></div></td>';
            cells += '<td><div class="val-text">' + mem + '%</div><div class="progress-bg"><div class="progress-bar" style="width:' + mem + '%;background-color:' + pctColor(n.mem, 90, 70) + ';"></div></div></td>';
            cells += '<td><div class="val-text">' + disk + '%</div><div class="progress-bg"><div class="progress-bar" style="width:' + disk + '%;background-color:' + pctColor(n.disk, 90, 80) + ';"></div></div></td>';
            cells += '<td class="tz-rate">↓ ' + esc(n.net_in_rate) + ' / ↑ ' + esc(n.net_out_rate) + '</td>';
            cells += '<td class="tz-seen">' + esc(n.last_seen) + '</td>';
            if (admin) {
                cells += '<td class="tz-ops"><button class="action-btn" onclick="tagNode(\'' + jsStr(n.id) + '\', \'' + jsStr(n.tag) + '\')" title="设置分组标签">标签</button> <button class="btn-delete" onclick="deleteNode(\'' + jsStr(n.id) + '\', \'' + jsStr(n.name) + '\')">删除</button></td>';
            }
            return '<tr class="draggable-row" draggable="' + (admin ? 'true' : 'false') + '" data-id="' + esc(n.id) + '" data-ip="' + esc(ipMain) + '" data-tag="' + esc(n.tag) + '">' + cells + '</tr>';
        }

        function updateRow(tr, n, admin) {
            var nameEl = tr.querySelector('.tz-name');
            if (nameEl) nameEl.innerHTML = esc(n.name) + (n.tag ? ' <span class="tz-node-tag">' + esc(n.tag) + '</span>' : '');
            if (admin) {
                var ipEl = tr.querySelector('.tz-ip');
                if (ipEl) {
                    var ipMain = n.ipv4 || n.ip || '';
                    var h = '<div style="display:flex;align-items:center;"><span>' + esc(ipMain) + '</span><button class="copy-btn" onclick="copyIP(\'' + jsStr(ipMain) + '\', this)">复制</button></div>';
                    if (n.ipv6) h += '<div style="font-size:12px;color:#888;margin-top:4px;word-break:break-all;">' + esc(n.ipv6) + '</div>';
                    ipEl.innerHTML = h;
                }
                var ops = tr.querySelector('.tz-ops');
                if (ops) ops.innerHTML = '<button class="action-btn" onclick="tagNode(\'' + jsStr(n.id) + '\', \'' + jsStr(n.tag) + '\')" title="设置分组标签">标签</button> <button class="btn-delete" onclick="deleteNode(\'' + jsStr(n.id) + '\', \'' + jsStr(n.name) + '\')">删除</button>';
            }
            var st = tr.querySelector('.online, .offline');
            if (st) { st.className = n.online ? 'online' : 'offline'; st.textContent = n.online ? '在线' : '离线'; }
            var up = tr.querySelector('.tz-uptime'); if (up) up.textContent = n.uptime;
            var vals = tr.querySelectorAll('.val-text');
            var bars = tr.querySelectorAll('.progress-bar');
            if (vals[0]) vals[0].textContent = (n.cpu || 0).toFixed(1) + '%';
            if (vals[1]) vals[1].textContent = (n.mem || 0).toFixed(1) + '%';
            if (vals[2]) vals[2].textContent = (n.disk || 0).toFixed(1) + '%';
            if (bars[0]) { bars[0].style.width = (n.cpu || 0).toFixed(1) + '%'; bars[0].style.backgroundColor = pctColor(n.cpu, 90, 70); }
            if (bars[1]) { bars[1].style.width = (n.mem || 0).toFixed(1) + '%'; bars[1].style.backgroundColor = pctColor(n.mem, 90, 70); }
            if (bars[2]) { bars[2].style.width = (n.disk || 0).toFixed(1) + '%'; bars[2].style.backgroundColor = pctColor(n.disk, 90, 80); }
            var rt = tr.querySelector('.tz-rate'); if (rt) rt.textContent = '↓ ' + n.net_in_rate + ' / ↑ ' + n.net_out_rate;
            var sn = tr.querySelector('.tz-seen'); if (sn) sn.textContent = n.last_seen;
            tr.setAttribute('data-tag', n.tag || '');
        }

        function applyData(d) {
            var sv = document.querySelectorAll('.stat-value');
            if (sv[0]) sv[0].textContent = d.total;
            if (sv[1]) sv[1].textContent = d.online;
            if (sv[2]) { sv[2].textContent = d.offline; sv[2].classList.toggle('stat-value-warn', d.offline > 0); }
            var rates = document.querySelectorAll('.tz-rate-text');
            if (rates[0]) rates[0].textContent = d.net_out_rate;
            if (rates[1]) rates[1].textContent = d.net_in_rate;
            var totals = document.querySelectorAll('.net-total');
            if (totals[0]) totals[0].textContent = d.net_out_total;
            if (totals[1]) totals[1].textContent = d.net_in_total;

            var banner = document.querySelector('.tz-banner');
            if (banner) {
                var dot = d.offline === 0 ? 'tz-dot' : 'tz-dot warn';
                var right = d.offline === 0 ? '所有设备可达' : d.offline + ' 台设备离线';
                banner.innerHTML = '<div class="l"><span class="' + dot + '"></span><b>公开运行状态</b><span>' + d.online + '/' + d.total + ' 台设备当前在线</span></div><div class="r">' + right + '<span>数据每 5 秒刷新</span></div>';
            }

            syncFilterTabs(d);

            var tbody = document.getElementById('table-body');
            if (!tbody) return;
            var rows = {};
            tbody.querySelectorAll('tr.draggable-row').forEach(function (tr) { rows[tr.getAttribute('data-id')] = tr; });
            var seen = {};
            d.nodes.forEach(function (n) {
                seen[n.id] = true;
                var tr = rows[n.id];
                if (tr) {
                    updateRow(tr, n, d.admin);
                } else {
                    var tmp = document.createElement('tbody');
                    tmp.innerHTML = buildRowHtml(n, d.admin);
                    var ntr = tmp.firstElementChild;
                    tbody.insertBefore(ntr, document.getElementById('tz-empty-row'));
                    rows[n.id] = ntr;
                }
            });
            Object.keys(rows).forEach(function (id) {
                if (!seen[id] && rows[id].parentNode) rows[id].parentNode.removeChild(rows[id]);
            });
            var seq = 1;
            tbody.querySelectorAll('tr.draggable-row .seq-num').forEach(function (el) { el.textContent = seq++; });
            reapplyFilter();
        }

        function syncFilterTabs(d) {
            var bar = document.querySelector('.tz-filter');
            if (!bar) return;
            var want = ['all', 'online', 'offline'];
            d.tags.forEach(function (t) { want.push('tag-' + t.name); });
            var cur = [];
            bar.querySelectorAll('.tz-tab').forEach(function (b) { cur.push(b.getAttribute('data-key')); });
            if (cur.length !== want.length || cur.some(function (k, i) { return k !== want[i]; })) {
                var active = null;
                bar.querySelectorAll('.tz-tab.active').forEach(function (b) { active = b.getAttribute('data-key'); });
                function tab(key, label, n) {
                    return '<button type="button" class="tz-tab' + (key === active ? ' active' : '') + '" data-key="' + esc(key) + '">' + esc(label) + '<span class="n">' + n + '</span></button>';
                }
                var html = '<span class="f-label">' + bar.querySelector('.f-label').innerHTML + '</span>';
                html += tab('all', '全部', d.total) + tab('online', '在线', d.online) + tab('offline', '离线', d.offline);
                d.tags.forEach(function (t) { html += tab('tag-' + t.name, t.name, t.count); });
                bar.innerHTML = html;
            } else {
                var map = { 'all': d.total, 'online': d.online, 'offline': d.offline };
                d.tags.forEach(function (t) { map['tag-' + t.name] = t.count; });
                bar.querySelectorAll('.tz-tab').forEach(function (b) {
                    var n = map[b.getAttribute('data-key')];
                    if (n !== undefined) b.querySelector('.n').textContent = n;
                });
            }
        }

        function fetchData() {
            fetch('/api')
                .then(function (r) { return r.json(); })
                .then(function (d) { applyData(d); })
                .catch(function () {});
        }

        // ===== 分组筛选 (计数由服务端统计, 前端负责过滤) =====
        function applyFilter(key) {
            var rows = document.querySelectorAll('#table-body tr.draggable-row');
            var visible = 0;
            rows.forEach(function (tr) {
                var show = true;
                if (key === 'online') show = !!(tr.querySelector('.online'));
                else if (key === 'offline') show = !!(tr.querySelector('.offline'));
                else if (key.indexOf('tag-') === 0) show = (tr.getAttribute('data-tag') || '') === key.slice(4);
                tr.style.display = show ? '' : 'none';
                if (show) visible++;
            });
            var empty = document.getElementById('tz-empty-row');
            if (empty) {
                var firstRow = document.querySelector('#table-body tr.draggable-row');
                if (firstRow) empty.querySelector('td').colSpan = firstRow.querySelectorAll('td').length;
                empty.style.display = visible === 0 ? '' : 'none';
            }
            document.querySelectorAll('.tz-filter .tz-tab').forEach(function (b) {
                b.classList.toggle('active', b.getAttribute('data-key') === key);
            });
            try { localStorage.setItem('tz-filter', key); } catch (e) {}
        }
        function reapplyFilter() {
            var saved = null;
            try { saved = localStorage.getItem('tz-filter'); } catch (e) {}
            var bar = document.querySelector('.tz-filter');
            if (saved && bar && bar.querySelector('[data-key="' + saved + '"]')) applyFilter(saved);
        }
        function initFilter() {
            var bar = document.querySelector('.tz-filter');
            if (!bar) return;
            bar.addEventListener('click', function (e) {
                var btn = e.target.closest('.tz-tab');
                if (btn) applyFilter(btn.getAttribute('data-key'));
            });
            reapplyFilter();
        }
        if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', initFilter);
        else initFilter();

        function tagNode(id, oldTag) {
            killRefresh();
            var newTag = prompt("请输入分组标签 (如 云服务器 / 香港 / PVE，留空清除):", oldTag);
            if (newTag !== null) {
                fetch('/set_tag', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                    body: 'id=' + encodeURIComponent(id) + '&tag=' + encodeURIComponent(newTag.trim())
                }).then(function (res) {
                    if (res.status === 401) { alert("未登录或登录已失效！"); }
                    window.location.reload();
                });
            } else { resumeRefresh(); }
        }

        {{if .IsAdmin}}
        function toggleSelectAll(source) {
            killRefresh(); 
            let checkboxes = document.querySelectorAll('.node-cb');
            checkboxes.forEach(cb => { cb.checked = source.checked; });
        }

        function onCheckboxClick() {
            killRefresh(); 
            let allChecked = true;
            document.querySelectorAll('.node-cb').forEach(cb => {
                if (!cb.checked) allChecked = false;
            });
            document.getElementById('selectAll').checked = allChecked;
        }

        function batchDelete() {
            killRefresh();
            let selected = [];
            document.querySelectorAll('.node-cb:checked').forEach(cb => {
                selected.push(cb.value);
            });

            if (selected.length === 0) {
                alert("请先勾选要删除的节点！");
                resumeRefresh(); 
                return;
            }

            if (confirm("确定要批量删除选中的 " + selected.length + " 个节点吗？\n(若客户端仍在运行，下次上报时会自动重新添加)")) {
                fetch('/batch_delete', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(selected)
                }).then(res => {
                    if(res.status === 401) { alert("操作失败：未登录或登录已失效！"); }
                    window.location.reload();
                });
            } else {
                resumeRefresh(); 
            }
        }
        
        function renameNode(id, oldName) {
            killRefresh();
            let newName = prompt("请输入新的节点名称 (留空则恢复默认标识):", oldName);
            if (newName !== null) {
                fetch('/rename', { method: 'POST', headers: {'Content-Type': 'application/x-www-form-urlencoded'}, body: 'id=' + encodeURIComponent(id) + '&name=' + encodeURIComponent(newName) })
                .then(res => { if(res.status === 401) { alert("未登录或登录已失效！"); } window.location.reload(); });
            } else { resumeRefresh(); }
        }

        function deleteNode(id, name) {
            killRefresh();
            if(confirm("确定要删除节点 [" + name + "] 吗？\n(若客户端仍在运行，下次上报时会自动重新添加)")) {
                fetch('/delete', { method: 'POST', headers: {'Content-Type': 'application/x-www-form-urlencoded'}, body: 'id=' + encodeURIComponent(id) })
                .then(res => { if(res.status === 401) { alert("操作失败：未登录或登录已失效！"); } window.location.reload(); });
            } else { resumeRefresh(); }
        }

        function copyIP(ip, btn) {
            killRefresh();
            let textArea = document.createElement("textarea"); textArea.value = ip; textArea.style.position = "fixed"; textArea.style.opacity = "0"; document.body.appendChild(textArea); textArea.focus(); textArea.select();
            try { document.execCommand('copy'); let oldText = btn.innerText; btn.innerText = "已复制!"; btn.style.backgroundColor = "#4caf50"; btn.style.color = "white"; btn.style.borderColor = "#4caf50";
                setTimeout(() => { btn.innerText = oldText; btn.style.backgroundColor = "#fff"; btn.style.color = "#555"; btn.style.borderColor = "#ccc"; resumeRefresh(); }, 1500);
            } catch (err) { alert("复制失败"); resumeRefresh(); }
            document.body.removeChild(textArea);
        }

        function openSettings() { killRefresh(); document.getElementById('settingsModal').style.display = 'flex'; }
        function closeSettings() { document.getElementById('settingsModal').style.display = 'none'; resumeRefresh(); }

        // 新增：测试TG通知逻辑
        function testTGNotify(event) {
            let tgToken = document.getElementById('cfgTGToken').value.trim();
            let tgChatID = document.getElementById('cfgTGChatID').value.trim();
            
            if (!tgToken || !tgChatID) {
                alert("请先填写完整的 Bot Token 和 Chat ID。");
                return;
            }

            let btn = event.target;
            let oldText = btn.innerText;
            btn.innerText = "正在发送...";
            btn.disabled = true;

            let params = new URLSearchParams();
            params.append('tg_token', tgToken);
            params.append('tg_chat_id', tgChatID);

            fetch('/test_tg', {
                method: 'POST',
                headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                body: params.toString()
            }).then(async res => {
                if (res.ok) {
                    alert("✅ 测试通知发送成功！请检查你的 Telegram 客户端。");
                } else {
                    let msg = await res.text();
                    alert("❌ 发送失败：\n" + msg);
                }
            }).catch(err => {
                alert("❌ 请求出现错误：" + err);
            }).finally(() => {
                btn.innerText = oldText;
                btn.disabled = false;
            });
        }

        async function submitSettingsAsync() {
            let s = document.getElementById('cfgSiteName').value;
            let u = document.getElementById('cfgUser').value;
            let p = document.getElementById('cfgPass').value;
            let t = document.getElementById('cfgTOTP').value;
            
            let tgToken = document.getElementById('cfgTGToken').value;
            let tgChatID = document.getElementById('cfgTGChatID').value;
            
            let c = document.getElementById('cfgCustomCodeArea').value;

            let fileInput = document.getElementById('cfgFavicon');
            let favBase64 = "";
            if (fileInput.files.length > 0) {
                let file = fileInput.files[0];
                if (file.size > 500 * 1024) { 
                    alert("图标文件过大！请选择 500KB 以下的图片文件。");
                    return;
                }
                favBase64 = await new Promise((resolve) => {
                    let reader = new FileReader();
                    reader.onload = (e) => resolve(e.target.result);
                    reader.readAsDataURL(file);
                });
            }

            let params = new URLSearchParams();
            params.append('site_name', s);
            params.append('username', u);
            params.append('password', p);
            params.append('totp', t);
            params.append('tg_token', tgToken);
            params.append('tg_chat_id', tgChatID);
            params.append('custom_code', c);
            if (favBase64 !== "") {
                params.append('favicon', favBase64);
            }

            fetch('/update_config', {
                method: 'POST',
                headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                body: params.toString()
            }).then(res => {
                if(res.ok) {
                    alert("设置保存成功！");
                    window.location.reload();
                } else {
                    alert("保存失败，请检查登录状态");
                }
            });
        }

        function copyAllIPs() {
            killRefresh();
            let ips = [];
            document.querySelectorAll('.draggable-row').forEach(row => {
                let ip = row.getAttribute('data-ip');
                if(ip && ip !== "") { ips.push(ip); }
            });
            if(ips.length === 0) { alert("没有找到可复制的 IP"); resumeRefresh(); return; }
            let text = ips.join("\n");
            let textArea = document.createElement("textarea"); textArea.value = text; textArea.style.position = "fixed"; textArea.style.opacity = "0"; document.body.appendChild(textArea); textArea.focus(); textArea.select();
            try { document.execCommand('copy'); alert("成功复制 " + ips.length + " 个 IP 地址！"); } catch (err) { alert("复制失败"); }
            document.body.removeChild(textArea);
            resumeRefresh();
        }

        let draggedRow = null;
        document.querySelectorAll('.draggable-row').forEach(row => {
            row.addEventListener('dragstart', function(e) { draggedRow = this; e.dataTransfer.effectAllowed = 'move'; killRefresh(); setTimeout(() => this.classList.add('dragging'), 0); });
            row.addEventListener('dragend', function() { this.classList.remove('dragging'); let newOrder = Array.from(document.querySelectorAll('.draggable-row')).map(r => r.getAttribute('data-id'));
                fetch('/update_order', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(newOrder) }).then(res => { if(res.status === 401) alert("操作失败：未登录！"); resumeRefresh(); });
            });
            row.addEventListener('dragover', function(e) { e.preventDefault(); if (draggedRow === this) return; let bounding = this.getBoundingClientRect(); let offset = e.clientY - bounding.top;
                if (offset > bounding.height / 2) { this.parentNode.insertBefore(draggedRow, this.nextSibling); } else { this.parentNode.insertBefore(draggedRow, this); }
                updateSeqNums();
            });
        });
        function updateSeqNums() { document.querySelectorAll('.seq-num').forEach((el, index) => { el.innerText = index + 1; }); }
        {{end}}
    </script>
</body>
</html>
`

const loginTemplate = `
<!DOCTYPE html>
<html>
<head>
    <title>管理登录 - {{.SiteName}}</title>
    <link rel="icon" href="{{if .Favicon}}{{.Favicon}}{{else}}data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>🌍</text></svg>{{end}}">
    <style>
        body { font-family: Arial, sans-serif; background: #f4f6f9; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .login-card { background: #fff; padding: 35px 30px; border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); width: 320px; }
        h3 { margin-top: 0; color: #333; text-align: center; margin-bottom: 25px; font-size: 22px; }
        .input-group { margin-bottom: 15px; }
        .input-group label { display: block; margin-bottom: 5px; color: #666; font-size: 0.9em; }
        input[type="text"], input[type="password"] { width: 100%; padding: 12px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; font-size: 1em; transition: border 0.3s; }
        input[type="text"]:focus, input[type="password"]:focus { border-color: #00add8; outline: none; }
        .totp-input { text-align: center; font-size: 1.2em; letter-spacing: 4px; font-family: monospace; }
        button { width: 100%; padding: 12px; background-color: #00add8; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 1.1em; margin-top: 10px; font-weight: bold; transition: background 0.3s; }
        button:hover { background-color: #008cae; }
        .err-msg { color: #f44336; font-size: 0.9em; text-align: center; margin-top: 15px; background: #ffebee; padding: 10px; border-radius: 4px; }
    </style>
</head>
<body>
    <div class="login-card">
        <h3>
            {{if .Favicon}}<img src="{{.Favicon}}" style="height: 28px; vertical-align: middle; margin-right: 8px; border-radius: 4px;">{{end}}
            管理登录
        </h3>
        <form method="POST" action="/login">
            <div class="input-group">
                <label>用户名</label>
                <input type="text" name="username" placeholder="请输入用户名" required autofocus>
            </div>
            <div class="input-group">
                <label>密码</label>
                <input type="password" name="password" placeholder="请输入密码" required>
            </div>
            {{if .Has2FA}}
            <div class="input-group">
                <label>动态验证码 (2FA)</label>
                <input type="text" name="totp" class="totp-input" placeholder="000000" maxlength="8" required autocomplete="off" oninput="this.value=this.value.replace(/\s+/g,'')">
            </div>
            {{end}}
            <button type="submit">登 录</button>
        </form>
        {{if .Error}} <div class="err-msg">{{.Error}}</div> {{end}}
    </div>
</body>
</html>
`

// ==========================================
// 🚀 核心路由与请求处理
// ==========================================

func main() {
	loadSecrets()
	loadConfig()
	loadNames()
	loadOrder()
	loadStats()
	loadTags()
	loadIPGeo()

	// 启动后台掉线监测守护协程 (15秒)
	go startOfflineChecker()

	// 每 60 秒持久化一次累计流量 (stats.json)
	go func() {
		for {
			time.Sleep(60 * time.Second)
			mu.Lock()
			saveStats()
			mu.Unlock()
		}
	}()

	// IP 归属地自动识别 (后台批量查询 + 本地缓存, 手动规则与缓存兜底)
	go func() {
		time.Sleep(10 * time.Second)
		for {
			resolveGeo()
			time.Sleep(30 * time.Second)
		}
	}()

	http.HandleFunc("/report", handleReport)
	http.HandleFunc("/rename", handleRename)
	http.HandleFunc("/delete", handleDelete)
	http.HandleFunc("/batch_delete", handleBatchDelete)
	http.HandleFunc("/api", handleAPI)
	http.HandleFunc("/set_tag", handleSetTag)
	http.HandleFunc("/update_order", handleUpdateOrder)
	http.HandleFunc("/update_config", handleUpdateConfig)
	http.HandleFunc("/test_tg", handleTestTG) // 测试TG通知的路由
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/logout", handleLogout)
	http.HandleFunc("/", handleIndex)

	fs := http.FileServer(http.Dir("./static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	fmt.Println("探针主控端已启动，监听端口 :5001 (支持 IP 归属地自动分组)")
	if err := http.ListenAndServe(":5001", nil); err != nil {
		fmt.Printf("启动失败: %v\n", err)
	}
}

// 专门处理前端发起的测试 TG 请求
func handleTestTG(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		return
	}
	if !checkAdminAuth(r) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	tgToken := strings.TrimSpace(r.FormValue("tg_token"))
	tgChatID := strings.TrimSpace(r.FormValue("tg_chat_id"))

	// [新增] 从当前测试请求中提取域名
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if host == "" {
		host = "Server"
	}

	testMsg := fmt.Sprintf("🔔 [%s] 这是一条来自服务器监控面板的 Telegram 测试通知！如果您看到了这条消息，说明自动探测域名功能正常。", host)

	err := sendNotify(tgToken, tgChatID, testMsg)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("发送成功"))
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	sysUser := config.Username
	sysPassHash := config.PasswordHash
	sysTOTPDecrypted := decryptAES(config.TOTPEncrypted)
	sysName := config.SiteName
	sysFavicon := config.Favicon
	mu.Unlock()

	has2FA := sysTOTPDecrypted != ""

	if r.Method == http.MethodGet {
		tmpl, _ := template.New("login").Parse(loginTemplate)
		tmpl.Execute(w, LoginData{Has2FA: has2FA, SiteName: sysName, Favicon: sysFavicon})
		return
	}

	if r.Method == http.MethodPost {
		user := r.FormValue("username")
		pass := r.FormValue("password")
		code := r.FormValue("totp")

		code = strings.ReplaceAll(code, " ", "")

		if user == sysUser && hashPassword(pass) == sysPassHash {
			if has2FA {
				if !verifyTOTP(sysTOTPDecrypted, code) {
					tmpl, _ := template.New("login").Parse(loginTemplate)
					tmpl.Execute(w, LoginData{Error: "2FA动态验证码错误！", Has2FA: has2FA, SiteName: sysName, Favicon: sysFavicon})
					return
				}
			}
			http.SetCookie(w, &http.Cookie{Name: "admin_session", Value: sessionAuthToken, Path: "/", HttpOnly: true, MaxAge: 86400})
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		tmpl, _ := template.New("login").Parse(loginTemplate)
		tmpl.Execute(w, LoginData{Error: "用户名或密码错误！", Has2FA: has2FA, SiteName: sysName, Favicon: sysFavicon})
	}
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: "admin_session", Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		return
	}

	// [新增] 自动探测并保存服务端域名 (如果是 "v.666200.xyz:5001" 会自动去掉端口号)
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	mu.Lock()
	if host != "" {
		autoDetectedHost = host
	}
	mu.Unlock()

	var data NodeInfo
	json.NewDecoder(r.Body).Decode(&data)
	data.Timestamp = time.Now().Unix()
	data.LastSeen = time.Now().Format("15:04:05")

	clientIP := r.Header.Get("X-Real-IP")
	if clientIP == "" {
		clientIP = r.Header.Get("X-Forwarded-For")
		if clientIP != "" {
			clientIP = strings.Split(clientIP, ",")[0]
			clientIP = strings.TrimSpace(clientIP)
		}
	}
	if clientIP == "" {
		clientIP, _, _ = net.SplitHostPort(r.RemoteAddr)
	}
	data.IP = clientIP

	if data.IPv4 == "" && data.IPv6 == "" {
		if strings.Contains(clientIP, ":") {
			data.IPv6 = clientIP
		} else {
			data.IPv4 = clientIP
		}
	}

	mu.Lock()
	if existData, exists := nodesStatus[data.NodeID]; exists {
		data.NotifiedOffline = existData.NotifiedOffline
		data.NetInTotal = existData.NetInTotal
		data.NetOutTotal = existData.NetOutTotal
		// 按两次上报的时间间隔对速率积分，得到累计流量 (间隔超过 60s 视为断线重连，不累计)
		dt := data.Timestamp - existData.Timestamp
		if dt > 0 && dt <= 60 {
			data.NetInTotal += uint64(float64(data.NetIn) * float64(dt))
			data.NetOutTotal += uint64(float64(data.NetOut) * float64(dt))
		}
	} else {
		if st, ok := nodeStats[data.NodeID]; ok {
			data.NetInTotal = st.NetInTotal
			data.NetOutTotal = st.NetOutTotal
		}
		found := false
		for _, id := range nodeOrder {
			if id == data.NodeID {
				found = true
				break
			}
		}
		if !found {
			nodeOrder = append(nodeOrder, data.NodeID)
			saveOrder()
		}
	}
	nodesStatus[data.NodeID] = &data
	nodeStats[data.NodeID] = &NodeTraffic{NetInTotal: data.NetInTotal, NetOutTotal: data.NetOutTotal}
	mu.Unlock()

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"success"}`))
}

func handleRename(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		return
	}
	if !checkAdminAuth(r) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	id := r.FormValue("id")
	newName := r.FormValue("name")
	if id != "" {
		mu.Lock()
		if newName == "" {
			delete(customNames, id)
		} else {
			customNames[id] = newName
		}
		saveNames()
		mu.Unlock()
	}
	w.WriteHeader(http.StatusOK)
}

func handleSetTag(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		return
	}
	if !checkAdminAuth(r) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	id := r.FormValue("id")
	tag := strings.TrimSpace(r.FormValue("tag"))
	if id != "" {
		mu.Lock()
		if tag == "" {
			delete(nodeTags, id)
		} else {
			nodeTags[id] = tag
		}
		saveTags()
		mu.Unlock()
	}
	w.WriteHeader(http.StatusOK)
}

func handleDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		return
	}
	if !checkAdminAuth(r) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	id := r.FormValue("id")
	if id != "" {
		mu.Lock()
		delete(nodesStatus, id)
		delete(nodeStats, id)
		delete(nodeTags, id)
		if _, ok := customNames[id]; ok {
			delete(customNames, id)
			saveNames()
		}
		newOrder := make([]string, 0)
		for _, v := range nodeOrder {
			if v != id {
				newOrder = append(newOrder, v)
			}
		}
		nodeOrder = newOrder
		saveOrder()
		saveStats()
		saveTags()
		mu.Unlock()
	}
	w.WriteHeader(http.StatusOK)
}

func handleBatchDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		return
	}
	if !checkAdminAuth(r) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	var ids []string
	if err := json.NewDecoder(r.Body).Decode(&ids); err == nil {
		mu.Lock()
		for _, id := range ids {
			delete(nodesStatus, id)
			delete(nodeStats, id)
			delete(nodeTags, id)
			if _, ok := customNames[id]; ok {
				delete(customNames, id)
			}
		}
		saveNames()

		newOrder := make([]string, 0)
		for _, v := range nodeOrder {
			keep := true
			for _, id := range ids {
				if v == id {
					keep = false
					break
				}
			}
			if keep {
				newOrder = append(newOrder, v)
			}
		}
		nodeOrder = newOrder
		saveOrder()
		saveStats()
		saveTags()
		mu.Unlock()
	}
	w.WriteHeader(http.StatusOK)
}

func handleUpdateOrder(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		return
	}
	if !checkAdminAuth(r) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	var newOrder []string
	if err := json.NewDecoder(r.Body).Decode(&newOrder); err == nil {
		mu.Lock()
		if len(newOrder) > 0 {
			nodeOrder = newOrder
			saveOrder()
		}
		mu.Unlock()
	}
	w.WriteHeader(http.StatusOK)
}

func handleUpdateConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		return
	}
	if !checkAdminAuth(r) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	newSite := r.FormValue("site_name")
	newUser := r.FormValue("username")
	newPass := r.FormValue("password")
	newTOTP := strings.TrimSpace(r.FormValue("totp"))

	newTGToken := strings.TrimSpace(r.FormValue("tg_token"))
	newTGChatID := strings.TrimSpace(r.FormValue("tg_chat_id"))

	newCustomCode := r.FormValue("custom_code")
	newFavicon := r.FormValue("favicon")

	mu.Lock()
	if newSite != "" {
		config.SiteName = newSite
	}
	if newUser != "" {
		config.Username = newUser
	}
	if newPass != "" {
		config.PasswordHash = hashPassword(newPass)
	}

	if newTOTP != "" {
		config.TOTPEncrypted = encryptAES(newTOTP)
	} else {
		config.TOTPEncrypted = ""
	}

	config.TGToken = newTGToken
	config.TGChatID = newTGChatID
	config.CustomCode = newCustomCode

	if newFavicon != "" {
		config.Favicon = newFavicon
	}

	saveConfig()
	mu.Unlock()

	w.WriteHeader(http.StatusOK)
}

// formatRate 把字节/秒格式化为可读速率 (B/s / K/s / M/s)
func formatRate(b uint64) string {
	switch {
	case b >= 1<<20:
		return fmt.Sprintf("%.1f M/s", float64(b)/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1f K/s", float64(b)/(1<<10))
	default:
		return fmt.Sprintf("%.0f B/s", float64(b))
	}
}

// formatBytes 把累计字节数格式化为可读容量 (B / KB / MB / GB)
func formatBytes(b uint64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.2f GB", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.2f MB", float64(b)/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.2f KB", float64(b)/(1<<10))
	default:
		return fmt.Sprintf("%.0f B", float64(b))
	}
}

// buildSnapshot 汇总当前仪表盘数据, 必须在持有 mu 锁时调用
func buildSnapshot(now int64) *dashSnapshot {
	loadIPGroupsLocked()
	var list []*NodeInfo
	processed := make(map[string]bool)

	for _, id := range nodeOrder {
		if info, exists := nodesStatus[id]; exists {
			if now-info.Timestamp > 15 {
				info.IsOnline = false
			} else {
				info.IsOnline = true
			}
			if name, ok := customNames[id]; ok {
				info.DisplayName = name
			} else {
				info.DisplayName = id
			}
			info.Tag = effectiveTag(id, info)
			list = append(list, info)
			processed[id] = true
		}
	}
	for id, info := range nodesStatus {
		if !processed[id] {
			if now-info.Timestamp > 15 {
				info.IsOnline = false
			} else {
				info.IsOnline = true
			}
			if name, ok := customNames[id]; ok {
				info.DisplayName = name
			} else {
				info.DisplayName = id
			}
			info.Tag = effectiveTag(id, info)
			list = append(list, info)
			nodeOrder = append(nodeOrder, id)
			saveOrder()
		}
	}

	snap := &dashSnapshot{list: list, total: len(list)}
	for _, info := range list {
		if info.IsOnline {
			snap.online++
		}
		snap.netInRate += info.NetIn
		snap.netOutRate += info.NetOut
		snap.netInTotal += info.NetInTotal
		snap.netOutTotal += info.NetOutTotal
	}

	// 按标签分组统计 (保持首次出现顺序)
	tagOrder := make([]string, 0)
	tagSeen := make(map[string]bool)
	tagCounts := make(map[string]int)
	for _, info := range list {
		if info.Tag == "" {
			continue
		}
		if !tagSeen[info.Tag] {
			tagSeen[info.Tag] = true
			tagOrder = append(tagOrder, info.Tag)
		}
		tagCounts[info.Tag]++
	}
	for _, t := range tagOrder {
		snap.tags = append(snap.tags, TagCount{Name: t, Count: tagCounts[t]})
	}
	return snap
}

// handleAPI 返回仪表盘 JSON 数据, 供前端局部刷新
func handleAPI(w http.ResponseWriter, r *http.Request) {
	admin := checkAdminAuth(r)
	mu.Lock()
	snap := buildSnapshot(time.Now().Unix())
	gTotal, gResolved, gErr, gMiss := geoTotal, geoResolved, geoLastError, geoMiss
	mu.Unlock()

	d := DashData{
		Admin:       admin,
		Total:       snap.total,
		Online:      snap.online,
		Offline:     snap.total - snap.online,
		NetInRate:   formatRate(snap.netInRate),
		NetOutRate:  formatRate(snap.netOutRate),
		NetInTotal:  formatBytes(snap.netInTotal),
		NetOutTotal: formatBytes(snap.netOutTotal),
		Tags:        snap.tags,
		GeoTotal:    gTotal,
		GeoResolved: gResolved,
		GeoError:    gErr,
		GeoMiss:     gMiss,
	}
	for _, info := range snap.list {
		d.Nodes = append(d.Nodes, NodeView{
			ID:         info.NodeID,
			Name:       info.DisplayName,
			IP:         info.IP,
			IPv4:       info.IPv4,
			IPv6:       info.IPv6,
			Online:     info.IsOnline,
			Uptime:     formatUptime(info.Uptime),
			CPU:        info.CPUUsage,
			Mem:        info.MemUsage,
			Disk:       info.DiskUsage,
			NetInRate:  formatRate(info.NetIn),
			NetOutRate: formatRate(info.NetOut),
			LastSeen:   info.LastSeen,
			Tag:        info.Tag,
		})
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(d)
}

// formatUptime 把秒数格式化为可读运行时长
func formatUptime(u uint64) string {
	if u == 0 {
		return "-"
	}
	days := u / 86400
	hours := (u % 86400) / 3600
	mins := (u % 3600) / 60
	if days > 0 {
		return fmt.Sprintf("%d天 %d时 %d分", days, hours, mins)
	}
	if hours > 0 {
		return fmt.Sprintf("%d时 %d分", hours, mins)
	}
	return fmt.Sprintf("%d分", mins)
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	mu.Lock()
	snap := buildSnapshot(time.Now().Unix())
	adminUser := config.Username
	siteName := config.SiteName
	totpSecretDecrypted := decryptAES(config.TOTPEncrypted)
	customCode := config.CustomCode
	sysFavicon := config.Favicon
	sysTGToken := config.TGToken
	sysTGChatID := config.TGChatID
	mu.Unlock()

	pageData := PageData{
		Nodes:          snap.list,
		TotalNodes:     snap.total,
		OnlineNodes:    snap.online,
		OfflineNodes:   snap.total - snap.online,
		NetInRateStr:   formatRate(snap.netInRate),
		NetOutRateStr:  formatRate(snap.netOutRate),
		NetInTotalStr:  formatBytes(snap.netInTotal),
		NetOutTotalStr: formatBytes(snap.netOutTotal),
		Tags:           snap.tags,
		IsAdmin:        checkAdminAuth(r),
		AdminUser:  adminUser,
		TOTPSecret: totpSecretDecrypted,
		SiteName:   siteName,
		CustomCode: customCode,
		Favicon:    sysFavicon,
		TGToken:    sysTGToken,
		TGChatID:   sysTGChatID,
	}

	tmpl := template.New("index").Funcs(template.FuncMap{
		"inc":          func(i int) int { return i + 1 },
		"formatRate":   formatRate,
		"formatBytes":  formatBytes,
		"formatUptime": formatUptime,
		"safeHTML": func(s string) template.HTML { return template.HTML(s) },
	})

	if _, err := os.Stat("theme.html"); err == nil {
		tmpl, _ = tmpl.ParseFiles("theme.html")
	} else {
		tmpl, _ = tmpl.Parse(htmlTemplate)
	}

	tmpl.Execute(w, pageData)
}
