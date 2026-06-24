package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
	psnet "github.com/shirou/gopsutil/v3/net"
)

type ReportData struct {
	NodeID    string  `json:"node_id"`
	IPv4      string  `json:"ipv4"`
	IPv6      string  `json:"ipv6"`
	CPUUsage  float64 `json:"cpu_usage"`
	MemUsage  float64 `json:"mem_usage"`
	DiskUsage float64 `json:"disk_usage"`
	NetIn     uint64  `json:"net_in"`
	NetOut    uint64  `json:"net_out"`
	Uptime    uint64  `json:"uptime"`
}

var (
	// 全局缓存 IP，避免每 5 秒高频请求外网接口
	cachedIPv4 string
	cachedIPv6 string
)

func getOrGenerateNodeID(providedID string) string {
	if providedID != "" {
		return providedID
	}
	idFile := "/home/agent/tz-agent.id"
	b, err := os.ReadFile(idFile)
	if err == nil && len(b) > 0 {
		return strings.TrimSpace(string(b))
	}
	randBytes := make([]byte, 4)
	rand.Read(randBytes)
	newID := "Node-" + hex.EncodeToString(randBytes)
	os.WriteFile(idFile, []byte(newID), 0644)
	return newID
}

// 1. 本地网卡兜底读取逻辑 (当外部 API 失败时作为备用)
func getSystemIPsFallback() (string, string) {
	var ipv4, ipv6 string
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", ""
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			ipStr := ipnet.IP.String()
			if strings.Contains(ipStr, "/") {
				ipStr = strings.Split(ipStr, "/")[0]
			}
			if ipnet.IP.To4() != nil {
				if ipv4 == "" {
					ipv4 = ipStr
				}
			} else if ipnet.IP.To16() != nil {
				if ipv6 == "" && !strings.HasPrefix(ipStr, "fe80") {
					ipv6 = ipStr
				}
			}
		}
	}
	return ipv4, ipv6
}

// 2. 通用外部公网 IP 探测 (传入支持 v4 或 v6 专属的接口 URL)
func fetchExternalIP(apiURL string) string {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(apiURL)
	if err == nil {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		ip := strings.TrimSpace(string(body))
		// 校验拿到的结果是不是一个合法的 IP
		if net.ParseIP(ip) != nil {
			return ip
		}
	}
	return ""
}

// 3. 终极双栈探测逻辑
func updateIPs() {
	// 主力方案：无论 VPS 提供商是谁，直接通过外部接口拉取真实的双栈出口 IP
	pubV4 := fetchExternalIP("https://api4.ipify.org") // 纯 v4 接口
	pubV6 := fetchExternalIP("https://api6.ipify.org") // 纯 v6 接口

	// 兜底方案：读取本地网卡信息
	locV4, locV6 := getSystemIPsFallback()

	// 智能判定：优先使用外部 API 拿到的真实公网 IP，拿不到再用本地网卡 IP
	if pubV4 != "" {
		cachedIPv4 = pubV4
	} else {
		cachedIPv4 = locV4
	}

	if pubV6 != "" {
		cachedIPv6 = pubV6
	} else {
		cachedIPv6 = locV6
	}
}

func main() {
	nodeIDPtr := flag.String("id", "", "Node ID (留空则自动生成)")
	serverURLPtr := flag.String("server", "", "Server Report URL")
	flag.Parse()

	nodeID := getOrGenerateNodeID(*nodeIDPtr)
	serverURL := *serverURLPtr

	if serverURL == "" {
		serverURL = os.Getenv("TZ_SERVER_URL")
	}
	if serverURL == "" {
		fmt.Println("错误: 必须指定 -server 参数")
		os.Exit(1)
	}

	fmt.Printf("探针启动 | 机器标识: %s | 上报至: %s\n", nodeID, serverURL)

	// 启动时强制执行一次 IP 探测
	updateIPs()
	
	// 启动后台定时任务：每 1 小时重新校准一次公网 IP (适配动态 IP 机器)
	go func() {
		for {
			time.Sleep(1 * time.Hour)
			updateIPs()
		}
	}()

	var lastNetIn, lastNetOut uint64
	for {
		// 1. CPU
		cpuPercent, _ := cpu.Percent(time.Second, false)
		var cpuVal float64
		if len(cpuPercent) > 0 {
			cpuVal = cpuPercent[0]
		}

		// 2. Mem
		m, _ := mem.VirtualMemory()
		memVal := m.UsedPercent

		// 3. Disk
		d, _ := disk.Usage("/")
		diskVal := d.UsedPercent

		// 4. Network
		netIO, _ := psnet.IOCounters(false)
		var currentNetIn, currentNetOut uint64
		if len(netIO) > 0 {
			currentNetIn = netIO[0].BytesRecv
			currentNetOut = netIO[0].BytesSent
		}

		var speedIn, speedOut uint64
		if lastNetIn > 0 {
			speedIn = (currentNetIn - lastNetIn) / 5
			speedOut = (currentNetOut - lastNetOut) / 5
		}
		lastNetIn = currentNetIn
		lastNetOut = currentNetOut

		// 5. Uptime
		sysUptime, _ := host.Uptime()

		// 组装数据并发送 (使用已缓存的最精准 IP)
		data := ReportData{
			NodeID:    nodeID,
			IPv4:      cachedIPv4,
			IPv6:      cachedIPv6,
			CPUUsage:  cpuVal,
			MemUsage:  memVal,
			DiskUsage: diskVal,
			NetIn:     speedIn,
			NetOut:    speedOut,
			Uptime:    sysUptime,
		}

		jsonData, _ := json.Marshal(data)
		resp, err := http.Post(serverURL, "application/json", bytes.NewBuffer(jsonData))
		if err == nil {
			resp.Body.Close()
		}

		time.Sleep(4 * time.Second)
	}
}
