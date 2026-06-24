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
	IPv4        string  `json:"ipv4"`
	IPv6        string  `json:"ipv6"`
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
	CustomCode string
	Favicon    string
}

type AdminConfig struct {
	Username      string `json:"username"`
	PasswordHash  string `json:"password_hash"`
	TOTPEncrypted string `json:"totp_encrypted"`
	SiteName      string `json:"site_name"`
	CustomCode    string `json:"custom_code"`
	Favicon       string `json:"favicon"`
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

var (
	nodesStatus = make(map[string]*NodeInfo)
	customNames = make(map[string]string)
	nodeOrder   = make([]string, 0)
	mu          sync.Mutex
	namesFile   = "names.json"
	orderFile   = "order.json"
	configFile  = "config.json"
	config      AdminConfig

	sessionAuthToken string
	aesSecretKey     []byte
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
		}
		saveConfig()
	}
	if config.SiteName == "" {
		config.SiteName = "服务器状态监控"
	}
}

func saveConfig() { b, _ := json.MarshalIndent(config, "", "  "); os.WriteFile(configFile, b, 0644) }
func loadNames() { b, err := os.ReadFile(namesFile); if err == nil { json.Unmarshal(b, &customNames) } }
func saveNames() { b, _ := json.Marshal(customNames); os.WriteFile(namesFile, b, 0644) }
func loadOrder() { b, err := os.ReadFile(orderFile); if err == nil { json.Unmarshal(b, &nodeOrder) } }
func saveOrder() { b, _ := json.Marshal(nodeOrder); os.WriteFile(orderFile, b, 0644) }

func checkAdminAuth(r *http.Request) bool {
	cookie, err := r.Cookie("admin_session")
	if err != nil { return false }
	return cookie.Value == sessionAuthToken
}

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
        
        .modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); z-index: 1000; justify-content: center; align-items: center; }
        .modal-content { background: white; padding: 25px; border-radius: 8px; width: 360px; box-shadow: 0 4px 15px rgba(0,0,0,0.2); max-height: 90vh; overflow-y: auto; }
        .modal-content h3 { margin-top: 0; margin-bottom: 20px; text-align: center; }
        .modal-content label { display: block; margin-bottom: 5px; font-size: 0.9em; color: #555; font-weight: bold; }
        .modal-content input, .modal-content textarea { width: 100%; padding: 10px; margin-bottom: 15px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }
        .modal-content input[type="file"] { padding: 6px; margin-bottom: 5px; }
        .file-hint { font-size: 0.8em; color: #888; margin-bottom: 15px; }
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
                <th>网络入/出 (MB/s)</th>
                <th>最后更新</th>
                {{if .IsAdmin}}<th>操作</th>{{end}}
            </tr>
        </thead>
        <tbody id="table-body">
        {{range $index, $info := .Nodes}}
        <tr class="draggable-row" {{if $.IsAdmin}}draggable="true"{{else}}draggable="false"{{end}} data-id="{{.NodeID}}" data-ip="{{if .IPv4}}{{.IPv4}}{{else}}{{.IP}}{{end}}">
            
            {{if $.IsAdmin}}<td style="text-align: center;"><input type="checkbox" class="node-cb" value="{{.NodeID}}" onclick="onCheckboxClick()"></td>{{end}}
            
            <td>
                <span class="seq-num">{{inc $index}}</span>
                {{if $.IsAdmin}}<span class="drag-handle" title="按住拖拽排序">☰</span>{{end}}
            </td>
            {{if $.IsAdmin}}<td class="editable" onclick="renameNode('{{.NodeID}}', '{{.DisplayName}}')" title="点击修改备注名">{{.DisplayName}}</td>{{else}}<td>{{.DisplayName}}</td>{{end}}
            
            <td style="font-size: 0.95em; color: #444;">
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
            
            <label>站点图标 (Favicon)</label>
            <input type="file" id="cfgFavicon" accept="image/png, image/jpeg, image/ico, image/svg+xml, image/gif">
            <div class="file-hint">支持 jpg/png/ico。不选则保持原样，建议尺寸 64x64。</div>

            <label>自定义代码 (美化CSS / 统计JS)</label>
            <textarea id="cfgCustomCode" rows="4" placeholder="例如: <style> body { background: #000; } </style>">{{.CustomCode}}</textarea>
            
            <button onclick="submitSettingsAsync()">保存设置</button>
        </div>
    </div>
    {{end}}

    <script>
        let refreshTimer = setTimeout(() => window.location.reload(), 5000);
        
        // [新增] 专门用于彻底暂停刷新的函数
        function killRefresh() {
            if(refreshTimer) {
                clearTimeout(refreshTimer);
                refreshTimer = null; // 确保彻底清空
            }
        }

        // [新增] 恢复定时刷新
        function resumeRefresh() {
            killRefresh();
            refreshTimer = setTimeout(() => window.location.reload(), 5000);
        }

        {{if .IsAdmin}}
        // [新增] 全选/取消全选 逻辑
        function toggleSelectAll(source) {
            killRefresh(); // 一旦操作选择框，立刻停止页面刷新！
            let checkboxes = document.querySelectorAll('.node-cb');
            checkboxes.forEach(cb => { cb.checked = source.checked; });
        }

        // [新增] 单个复选框点击 逻辑
        function onCheckboxClick() {
            killRefresh(); // 一旦操作选择框，立刻停止页面刷新！
            let allChecked = true;
            document.querySelectorAll('.node-cb').forEach(cb => {
                if (!cb.checked) allChecked = false;
            });
            document.getElementById('selectAll').checked = allChecked;
        }

        // [新增] 批量删除提交 逻辑
        function batchDelete() {
            killRefresh();
            let selected = [];
            document.querySelectorAll('.node-cb:checked').forEach(cb => {
                selected.push(cb.value);
            });

            if (selected.length === 0) {
                alert("请先勾选要删除的节点！");
                resumeRefresh(); // 没选东西的话，提示完恢复自动刷新
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
                resumeRefresh(); // 用户点了取消，恢复自动刷新
            }
        }
        {{end}}
        
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

        {{if .IsAdmin}}
        function openSettings() { killRefresh(); document.getElementById('settingsModal').style.display = 'flex'; }
        function closeSettings() { document.getElementById('settingsModal').style.display = 'none'; resumeRefresh(); }

        async function submitSettingsAsync() {
            let s = document.getElementById('cfgSiteName').value;
            let u = document.getElementById('cfgUser').value;
            let p = document.getElementById('cfgPass').value;
            let t = document.getElementById('cfgTOTP').value;
            let c = document.getElementById('cfgCustomCode').value;

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

	http.HandleFunc("/report", handleReport)
	http.HandleFunc("/rename", handleRename)
	http.HandleFunc("/delete", handleDelete)
	http.HandleFunc("/batch_delete", handleBatchDelete) // [新增] 批量删除接口
	http.HandleFunc("/update_order", handleUpdateOrder)
	http.HandleFunc("/update_config", handleUpdateConfig)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/logout", handleLogout)
	http.HandleFunc("/", handleIndex)

	fs := http.FileServer(http.Dir("./static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	fmt.Println("探针主控端已启动，监听端口 :5001 ...")
	if err := http.ListenAndServe(":5001", nil); err != nil {
		fmt.Printf("启动失败: %v\n", err)
	}
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
	if _, exists := nodesStatus[data.NodeID]; !exists {
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
		mu.Unlock()
	}
	w.WriteHeader(http.StatusOK)
}

// [新增] 专门处理批量删除的后端接口
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
			delete(nodesStatus, id) // 从内存状态中移除
			if _, ok := customNames[id]; ok {
				delete(customNames, id) // 从自定义名称表中移除
			}
		}
		saveNames()

		// 重建排序列表，剔除被删掉的节点
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

	config.CustomCode = newCustomCode

	if newFavicon != "" {
		config.Favicon = newFavicon
	}

	saveConfig()
	mu.Unlock()

	w.WriteHeader(http.StatusOK)
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	mu.Lock()
	now := time.Now().Unix()
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
			list = append(list, info)
			nodeOrder = append(nodeOrder, id)
			saveOrder()
		}
	}

	adminUser := config.Username
	siteName := config.SiteName
	totpSecretDecrypted := decryptAES(config.TOTPEncrypted)
	customCode := config.CustomCode
	sysFavicon := config.Favicon
	mu.Unlock()

	pageData := PageData{
		Nodes:      list,
		IsAdmin:    checkAdminAuth(r),
		AdminUser:  adminUser,
		TOTPSecret: totpSecretDecrypted,
		SiteName:   siteName,
		CustomCode: customCode,
		Favicon:    sysFavicon,
	}

	tmpl := template.New("index").Funcs(template.FuncMap{
		"div": func(b uint64) float64 { return float64(b) / 1024 / 1024 },
		"inc": func(i int) int { return i + 1 },
		"formatUptime": func(u uint64) string {
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
		},
		"safeHTML": func(s string) template.HTML { return template.HTML(s) },
	})

	if _, err := os.Stat("theme.html"); err == nil {
		tmpl, _ = tmpl.ParseFiles("theme.html")
	} else {
		tmpl, _ = tmpl.Parse(htmlTemplate)
	}

	tmpl.Execute(w, pageData)
}
