package main

import (
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
	"strings"
	"sync"
	"time"
)

type NodeInfo struct {
	NodeID      string  `json:"node_id"`
	DisplayName string  `json:"-"`
	IP          string  `json:"-"`
	CPUUsage    float64 `json:"cpu_usage"`
	MemUsage    float64 `json:"mem_usage"`
	DiskUsage   float64 `json:"disk_usage"`
	NetIn       uint64  `json:"net_in"`
	NetOut      uint64  `json:"net_out"`
	Uptime      uint64  `json:"uptime"`
	Timestamp   int64   `json:"-"`
	LastSeen    string  `json:"-"`
	IsOnline    bool    `json:"-"`
}

type PageData struct {
	Nodes      []*NodeInfo
	IsAdmin    bool
	AdminUser  string
	TOTPSecret string
	SiteName   string
}

type AdminConfig struct {
	Username      string `json:"username"`
	PasswordHash  string `json:"password_hash"`  // 存储 Hash 后的密码
	TOTPEncrypted string `json:"totp_encrypted"` // 存储 AES 加密后的 2FA
	SiteName      string `json:"site_name"`
}

type LoginData struct {
	Error    string
	Has2FA   bool
	SiteName string
}

var (
	nodesStatus = make(map[string]*NodeInfo)
	customNames = make(map[string]string)
	nodeOrder   = make([]string, 0)
	mu          sync.Mutex
	namesFile   = "names.json"
	orderFile   = "order.json"
	configFile  = "config.json"
	config      AdminConfig

	sessionAuthToken = "TzAdminAuthenticatedTokenSecret_v3"
	
	// 系统级 AES 加密密钥 (必须是 32 字节，用于加密 2FA 密钥)
	aesSecretKey = []byte("TanzhengSafeKey12345678901234567")
)

// ==========================================
// 🔒 加密与哈希算法区
// ==========================================

// 将明文密码进行 SHA-256 哈希 (加盐防彩虹表)
func hashPassword(plain string) string {
	h := sha256.New()
	h.Write([]byte(plain + "tz_salt_9982")) 
	return hex.EncodeToString(h.Sum(nil))
}

// 使用 AES-256-GCM 加密 2FA 密钥
func encryptAES(text string) string {
	if text == "" { return "" }
	c, _ := aes.NewCipher(aesSecretKey)
	gcm, _ := cipher.NewGCM(c)
	nonce := make([]byte, gcm.NonceSize())
	io.ReadFull(rand.Reader, nonce)
	sealed := gcm.Seal(nonce, nonce, []byte(text), nil)
	return base64.StdEncoding.EncodeToString(sealed)
}

// 解密 2FA 密钥
func decryptAES(cryptoText string) string {
	if cryptoText == "" { return "" }
	data, err := base64.StdEncoding.DecodeString(cryptoText)
	if err != nil { return "" }
	c, _ := aes.NewCipher(aesSecretKey)
	gcm, _ := cipher.NewGCM(c)
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize { return "" }
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil { return "" }
	return string(plain)
}

// 持久化存储函数
func loadConfig() {
	b, err := os.ReadFile(configFile)
	if err == nil {
		json.Unmarshal(b, &config)
	} else {
		// 默认初始配置：密码 admin 会被转化为一串 Hash
		config = AdminConfig{
			Username:      "admin", 
			PasswordHash:  hashPassword("admin"), 
			TOTPEncrypted: "", 
			SiteName:      "服务器状态监控",
		}
		saveConfig()
	}
	if config.SiteName == "" { config.SiteName = "服务器状态监控" }
}
func saveConfig() { b, _ := json.MarshalIndent(config, "", "  "); os.WriteFile(configFile, b, 0644) }
func loadNames() { b, err := os.ReadFile(namesFile); if err == nil { json.Unmarshal(b, &customNames) } }
func saveNames() { b, _ := json.Marshal(customNames); os.WriteFile(namesFile, b, 0644) }
func loadOrder() { b, err := os.ReadFile(orderFile); if err == nil { json.Unmarshal(b, &nodeOrder) } }
func saveOrder() { b, _ := json.Marshal(nodeOrder); os.WriteFile(orderFile, b, 0644) }

// 验证登录状态
func checkAdminAuth(r *http.Request) bool {
	cookie, err := r.Cookie("admin_session")
	if err != nil { return false }
	return cookie.Value == sessionAuthToken
}

// 🛡️ 纯原生 TOTP (2FA) 验证算法
func verifyTOTP(secret string, userCode string) bool {
	if secret == "" { return true }
	secret = strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(secret, " ", ""), "=", ""))
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		key, err = base32.StdEncoding.DecodeString(secret)
		if err != nil { return false }
	}
	t := time.Now().Unix() / 30
	for i := int64(-1); i <= 1; i++ {
		if generateTOTP(key, t+i) == userCode { return true }
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
// 📄 HTML 模板定义
// ==========================================

// 1. 主监控面板模板
const htmlTemplate = `
<!DOCTYPE html>
<html>
<head>
    <title>{{.SiteName}}</title>
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
        
        .modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); z-index: 1000; justify-content: center; align-items: center; }
        .modal-content { background: white; padding: 25px; border-radius: 8px; width: 320px; box-shadow: 0 4px 15px rgba(0,0,0,0.2); }
        .modal-content h3 { margin-top: 0; margin-bottom: 20px; text-align: center; }
        .modal-content label { display: block; margin-bottom: 5px; font-size: 0.9em; color: #555; }
        .modal-content input { width: 100%; padding: 10px; margin-bottom: 15px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }
        .modal-content button { width: 100%; padding: 10px; background: #00add8; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 1em; }
        .modal-content button:hover { background: #008cae; }
        .close-btn { float: right; cursor: pointer; font-size: 1.5em; color: #888; line-height: 0.5; }
    </style>
</head>
<body>
    <div class="header-box">
        <h2>{{.SiteName}}</h2>
        <div class="header-actions">
            {{if .IsAdmin}} 
                <button class="action-btn" onclick="copyAllIPs()">📄 复制全部IP</button>
                <button class="login-btn settings" onclick="openSettings()">⚙️ 系统设置</button>
                <a href="/logout" class="login-btn logout">退出管理</a> 
            {{else}} 
                <a href="/login" class="login-btn">管理登录</a> 
            {{end}}
        </div>
    </div>
    <table>
        <thead>
            <tr>
                <th>排序</th>
                <th>节点名称</th>
                <th>IP 地址</th>
                <th>状态</th>
                <th>运行时间</th>
                <th>CPU 使用率</th>
                <th>内存 使用率</th>
                <th>磁盘 使用率</th>
                <th>网络入/出 (MB/s)</th>
                <th>最后更新</th>
                {{if .IsAdmin}}<th>操作</th>{{end}}
            </tr>
        </thead>
        <tbody id="table-body">
        {{range $index, $info := .Nodes}}
        <tr class="draggable-row" {{if $.IsAdmin}}draggable="true"{{else}}draggable="false"{{end}} data-id="{{.NodeID}}" data-ip="{{.IP}}">
            <td>
                <span class="seq-num">{{inc $index}}</span>
                {{if $.IsAdmin}}<span class="drag-handle" title="按住拖拽排序">☰</span>{{end}}
            </td>
            {{if $.IsAdmin}}<td class="editable" onclick="renameNode('{{.NodeID}}', '{{.DisplayName}}')" title="点击修改备注名">{{.DisplayName}}</td>{{else}}<td>{{.DisplayName}}</td>{{end}}
            <td style="font-size: 0.95em; color: #444;">{{if $.IsAdmin}}{{.IP}} <button class="copy-btn" onclick="copyIP('{{.IP}}', this)">复制</button>{{else}}<span style="color:#aaa; font-style: italic;">*.*.*.* (登录可见)</span>{{end}}</td>
            <td>{{if .IsOnline}}<span class="online">在线</span>{{else}}<span class="offline">离线</span>{{end}}</td>
            <td style="font-size: 0.9em; color: #666;">{{formatUptime .Uptime}}</td>
            <td><div class="val-text">{{printf "%.1f" .CPUUsage}}%</div><div class="progress-bg"><div class="progress-bar" style="width: {{.CPUUsage}}%; background-color: {{if gt .CPUUsage 90.0}}#f44336{{else if gt .CPUUsage 70.0}}#ff9800{{else}}#4caf50{{end}};"></div></div></td>
            <td><div class="val-text">{{printf "%.1f" .MemUsage}}%</div><div class="progress-bg"><div class="progress-bar" style="width: {{.MemUsage}}%; background-color: {{if gt .MemUsage 90.0}}#f44336{{else if gt .MemUsage 70.0}}#ff9800{{else}}#4caf50{{end}};"></div></div></td>
            <td><div class="val-text">{{printf "%.1f" .DiskUsage}}%</div><div class="progress-bg"><div class="progress-bar" style="width: {{.DiskUsage}}%; background-color: {{if gt .DiskUsage 90.0}}#f44336{{else if gt .DiskUsage 80.0}}#ff9800{{else}}#4caf50{{end}};"></div></div></td>
            <td>{{printf "%.2f" (div .NetIn)}} | {{printf "%.2f" (div .NetOut)}}</td>
            <td>{{.LastSeen}}</td>
            {{if $.IsAdmin}}
            <td>
                <button class="btn-delete" onclick="deleteNode('{{.NodeID}}', '{{.DisplayName}}')">删除</button>
            </td>
            {{end}}
        </tr>
        {{end}}
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
            <button onclick="submitSettings()">保存设置</button>
        </div>
    </div>
    {{end}}

    <script>
        let refreshTimer = setTimeout(() => window.location.reload(), 5000);
        
        function renameNode(id, oldName) {
            clearTimeout(refreshTimer);
            let newName = prompt("请输入新的节点名称 (留空则恢复默认标识):", oldName);
            if (newName !== null) {
                fetch('/rename', { method: 'POST', headers: {'Content-Type': 'application/x-www-form-urlencoded'}, body: 'id=' + encodeURIComponent(id) + '&name=' + encodeURIComponent(newName) })
                .then(res => { if(res.status === 401) { alert("未登录或登录已失效！"); } window.location.reload(); });
            } else { refreshTimer = setTimeout(() => window.location.reload(), 5000); }
        }

        function deleteNode(id, name) {
            clearTimeout(refreshTimer);
            if(confirm("确定要删除节点 [" + name + "] 吗？\n(若客户端仍在运行，下次上报时会自动重新添加)")) {
                fetch('/delete', { 
                    method: 'POST', 
                    headers: {'Content-Type': 'application/x-www-form-urlencoded'}, 
                    body: 'id=' + encodeURIComponent(id) 
                })
                .then(res => {
                    if(res.status === 401) { alert("操作失败：未登录或登录已失效！"); }
                    window.location.reload();
                });
            } else { refreshTimer = setTimeout(() => window.location.reload(), 5000); }
        }

        function copyIP(ip, btn) {
            clearTimeout(refreshTimer);
            let textArea = document.createElement("textarea"); textArea.value = ip; textArea.style.position = "fixed"; textArea.style.opacity = "0"; document.body.appendChild(textArea); textArea.focus(); textArea.select();
            try { document.execCommand('copy'); let oldText = btn.innerText; btn.innerText = "已复制!"; btn.style.backgroundColor = "#4caf50"; btn.style.color = "white"; btn.style.borderColor = "#4caf50";
                setTimeout(() => { btn.innerText = oldText; btn.style.backgroundColor = "#fff"; btn.style.color = "#555"; btn.style.borderColor = "#ccc"; refreshTimer = setTimeout(() => window.location.reload(), 5000); }, 1500);
            } catch (err) { alert("复制失败"); refreshTimer = setTimeout(() => window.location.reload(), 5000); }
            document.body.removeChild(textArea);
        }

        {{if .IsAdmin}}
        function openSettings() {
            clearTimeout(refreshTimer);
            document.getElementById('settingsModal').style.display = 'flex';
        }

        function closeSettings() {
            document.getElementById('settingsModal').style.display = 'none';
            refreshTimer = setTimeout(() => window.location.reload(), 5000);
        }

        function submitSettings() {
            let s = document.getElementById('cfgSiteName').value;
            let u = document.getElementById('cfgUser').value;
            let p = document.getElementById('cfgPass').value;
            let t = document.getElementById('cfgTOTP').value;
            fetch('/update_config', {
                method: 'POST',
                headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                body: 'site_name=' + encodeURIComponent(s) + '&username=' + encodeURIComponent(u) + '&password=' + encodeURIComponent(p) + '&totp=' + encodeURIComponent(t)
            }).then(res => {
                if(res.ok) {
                    alert("设置保存成功！配置已安全加密写入文件。");
                    window.location.reload();
                } else {
                    alert("保存失败，请检查登录状态");
                }
            });
        }

        function copyAllIPs() {
            clearTimeout(refreshTimer);
            let ips = [];
            document.querySelectorAll('.draggable-row').forEach(row => {
                let ip = row.getAttribute('data-ip');
                if(ip && ip !== "") { ips.push(ip); }
            });
            if(ips.length === 0) {
                alert("没有找到可复制的 IP");
                refreshTimer = setTimeout(() => window.location.reload(), 5000);
                return;
            }
            let text = ips.join("\n");
            let textArea = document.createElement("textarea"); textArea.value = text; 
            textArea.style.position = "fixed"; textArea.style.opacity = "0"; 
            document.body.appendChild(textArea); textArea.focus(); textArea.select();
            try { 
                document.execCommand('copy'); 
                alert("成功复制 " + ips.length + " 个 IP 地址到剪贴板！\n\n" + text); 
            } catch (err) { 
                alert("复制失败"); 
            }
            document.body.removeChild(textArea);
            refreshTimer = setTimeout(() => window.location.reload(), 5000);
        }

        let draggedRow = null;
        document.querySelectorAll('.draggable-row').forEach(row => {
            row.addEventListener('dragstart', function(e) { draggedRow = this; e.dataTransfer.effectAllowed = 'move'; clearTimeout(refreshTimer); setTimeout(() => this.classList.add('dragging'), 0); });
            row.addEventListener('dragend', function() { this.classList.remove('dragging'); let newOrder = Array.from(document.querySelectorAll('.draggable-row')).map(r => r.getAttribute('data-id'));
                fetch('/update_order', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(newOrder) }).then(res => { if(res.status === 401) { alert("操作失败：未登录！"); } refreshTimer = setTimeout(() => window.location.reload(), 5000); });
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

// 2. 登录页面模板
const loginTemplate = `
<!DOCTYPE html>
<html>
<head>
    <title>管理登录 - {{.SiteName}}</title>
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
        <h3>管理登录</h3>
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
	loadConfig() 
	loadNames()
	loadOrder()

	http.HandleFunc("/report", handleReport)
	http.HandleFunc("/rename", handleRename)
	http.HandleFunc("/delete", handleDelete)
	http.HandleFunc("/update_order", handleUpdateOrder)
	http.HandleFunc("/update_config", handleUpdateConfig)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/logout", handleLogout)
	http.HandleFunc("/", handleIndex)

	fs := http.FileServer(http.Dir("./static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	fmt.Println("探针主控端已启动，监听端口 :5001 ...")
	if err := http.ListenAndServe(":5001", nil); err != nil { fmt.Printf("启动失败: %v\n", err) }
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	sysUser := config.Username
	sysPassHash := config.PasswordHash
	sysTOTPDecrypted := decryptAES(config.TOTPEncrypted) // 登录时动态解密 2FA
	sysName := config.SiteName
	mu.Unlock()

	has2FA := sysTOTPDecrypted != ""

	if r.Method == http.MethodGet {
		tmpl, _ := template.New("login").Parse(loginTemplate)
		tmpl.Execute(w, LoginData{Has2FA: has2FA, SiteName: sysName})
		return
	}

	if r.Method == http.MethodPost {
		user := r.FormValue("username")
		pass := r.FormValue("password")
		code := r.FormValue("totp")
		
		code = strings.ReplaceAll(code, " ", "")

		// 将用户输入的密码也进行 Hash，与配置中的 Hash 值进行对比
		if user == sysUser && hashPassword(pass) == sysPassHash {
			if has2FA {
				if !verifyTOTP(sysTOTPDecrypted, code) {
					tmpl, _ := template.New("login").Parse(loginTemplate)
					tmpl.Execute(w, LoginData{Error: "2FA动态验证码错误！", Has2FA: has2FA, SiteName: sysName})
					return
				}
			}
			http.SetCookie(w, &http.Cookie{ Name: "admin_session", Value: sessionAuthToken, Path: "/", HttpOnly: true, MaxAge: 86400 })
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		tmpl, _ := template.New("login").Parse(loginTemplate)
		tmpl.Execute(w, LoginData{Error: "用户名或密码错误！", Has2FA: has2FA, SiteName: sysName})
	}
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{ Name: "admin_session", Value: "", Path: "/", MaxAge: -1 })
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { return }
	var data NodeInfo; json.NewDecoder(r.Body).Decode(&data)
	data.Timestamp = time.Now().Unix(); data.LastSeen = time.Now().Format("15:04:05")
	
	clientIP := r.Header.Get("X-Real-IP")
	if clientIP == "" { clientIP = r.Header.Get("X-Forwarded-For"); if clientIP != "" { clientIP = strings.Split(clientIP, ",")[0] ; clientIP = strings.TrimSpace(clientIP) } }
	if clientIP == "" { clientIP, _, _ = net.SplitHostPort(r.RemoteAddr) }
	data.IP = clientIP

	mu.Lock()
	if _, exists := nodesStatus[data.NodeID]; !exists {
		found := false; for _, id := range nodeOrder { if id == data.NodeID { found = true; break } }
		if !found { nodeOrder = append(nodeOrder, data.NodeID); saveOrder() }
	}
	nodesStatus[data.NodeID] = &data
	mu.Unlock()
	
	w.WriteHeader(http.StatusOK); w.Write([]byte(`{"status":"success"}`))
}

func handleRename(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { return }
	if !checkAdminAuth(r) { w.WriteHeader(http.StatusUnauthorized); return }
	
	id := r.FormValue("id"); newName := r.FormValue("name")
	if id != "" { 
		mu.Lock()
		if newName == "" { delete(customNames, id) } else { customNames[id] = newName }
		saveNames()
		mu.Unlock() 
	}
	w.WriteHeader(http.StatusOK)
}

func handleDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { return }
	if !checkAdminAuth(r) { w.WriteHeader(http.StatusUnauthorized); return }

	id := r.FormValue("id")
	if id != "" {
		mu.Lock()
		delete(nodesStatus, id)
		if _, ok := customNames[id]; ok { delete(customNames, id); saveNames() }
		newOrder := make([]string, 0)
		for _, v := range nodeOrder { if v != id { newOrder = append(newOrder, v) } }
		nodeOrder = newOrder
		saveOrder()
		mu.Unlock()
	}
	w.WriteHeader(http.StatusOK)
}

func handleUpdateOrder(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { return }
	if !checkAdminAuth(r) { w.WriteHeader(http.StatusUnauthorized); return }
	
	var newOrder []string
	if err := json.NewDecoder(r.Body).Decode(&newOrder); err == nil { 
		mu.Lock()
		if len(newOrder) > 0 { nodeOrder = newOrder; saveOrder() }
		mu.Unlock() 
	}
	w.WriteHeader(http.StatusOK)
}

// 保存设置时，触发加密
func handleUpdateConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { return }
	if !checkAdminAuth(r) { w.WriteHeader(http.StatusUnauthorized); return }

	newSite := r.FormValue("site_name")
	newUser := r.FormValue("username")
	newPass := r.FormValue("password")
	newTOTP := strings.TrimSpace(r.FormValue("totp"))

	mu.Lock()
	if newSite != "" { config.SiteName = newSite }
	if newUser != "" { config.Username = newUser }
	// 如果用户输入了新密码，将其哈希后再存储
	if newPass != "" { config.PasswordHash = hashPassword(newPass) }
	
	// 更新 2FA 密钥，存入前进行 AES 加密
	if newTOTP != "" { 
		config.TOTPEncrypted = encryptAES(newTOTP) 
	} else {
		config.TOTPEncrypted = ""
	}
	
	saveConfig()
	mu.Unlock()

	w.WriteHeader(http.StatusOK)
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" { http.NotFound(w, r); return }
	
	mu.Lock()
	now := time.Now().Unix()
	var list []*NodeInfo
	processed := make(map[string]bool)
	
	for _, id := range nodeOrder {
		if info, exists := nodesStatus[id]; exists {
			if now-info.Timestamp > 15 { info.IsOnline = false } else { info.IsOnline = true }
			if name, ok := customNames[id]; ok { info.DisplayName = name } else { info.DisplayName = id }
			list = append(list, info); processed[id] = true
		}
	}
	for id, info := range nodesStatus {
		if !processed[id] {
			if now-info.Timestamp > 15 { info.IsOnline = false } else { info.IsOnline = true }
			if name, ok := customNames[id]; ok { info.DisplayName = name } else { info.DisplayName = id }
			list = append(list, info); nodeOrder = append(nodeOrder, id); saveOrder()
		}
	}
	
	adminUser := config.Username
	siteName := config.SiteName
	// 传给前端用于显示的 2FA 密钥必须先解密，这样后台设置里才能看到之前配的字符串
	totpSecretDecrypted := decryptAES(config.TOTPEncrypted)
	mu.Unlock()
	
	pageData := PageData{ 
		Nodes: list, 
		IsAdmin: checkAdminAuth(r),
		AdminUser: adminUser,
		TOTPSecret: totpSecretDecrypted,
		SiteName: siteName,
	}
	tmpl, _ := template.New("index").Funcs(template.FuncMap{ 
		"div": func(b uint64) float64 { return float64(b) / 1024 / 1024 }, 
		"inc": func(i int) int { return i + 1 },
		"formatUptime": func(u uint64) string {
			if u == 0 { return "-" }
			days := u / 86400
			hours := (u % 86400) / 3600
			mins := (u % 3600) / 60
			if days > 0 { return fmt.Sprintf("%d天 %d时 %d分", days, hours, mins) }
			if hours > 0 { return fmt.Sprintf("%d时 %d分", hours, mins) }
			return fmt.Sprintf("%d分", mins)
		},
	}).Parse(htmlTemplate)
	
	tmpl.Execute(w, pageData)
}