package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host" // [新增] 引入 host 包获取运行时间
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
)

type ReportData struct {
	NodeID    string  `json:"node_id"`
	CPUUsage  float64 `json:"cpu_usage"`
	MemUsage  float64 `json:"mem_usage"`
	DiskUsage float64 `json:"disk_usage"`
	NetIn     uint64  `json:"net_in"`
	NetOut    uint64  `json:"net_out"`
	Uptime    uint64  `json:"uptime"` // [新增] 添加运行时间字段 (秒)
}

// 获取或生成唯一的节点 ID
func getOrGenerateNodeID(providedID string) string {
	if providedID != "" {
		return providedID
	}
	
	// 修改后的路径：统一存放在 /home/agent 目录下
	idFile := "/home/agent/tz-agent.id"
	
	b, err := os.ReadFile(idFile)
	if err == nil && len(b) > 0 {
		return strings.TrimSpace(string(b))
	}
	
	// 生成随机 ID (如 Node-a1b2c3d4)
	randBytes := make([]byte, 4)
	rand.Read(randBytes)
	newID := "Node-" + hex.EncodeToString(randBytes)
	
	// 固化到本地，防止重启变化
	os.WriteFile(idFile, []byte(newID), 0644)
	return newID
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

	var lastNetIn, lastNetOut uint64
	for {
		// 1. 获取 CPU 使用率
		cpuPercent, _ := cpu.Percent(time.Second, false)
		var cpuVal float64
		if len(cpuPercent) > 0 {
			cpuVal = cpuPercent[0]
		}

		// 2. 获取内存使用率
		m, _ := mem.VirtualMemory()
		memVal := m.UsedPercent

		// 3. 获取磁盘使用率
		d, _ := disk.Usage("/")
		diskVal := d.UsedPercent

		// 4. 获取网络流量
		netIO, _ := net.IOCounters(false)
		var currentNetIn, currentNetOut uint64
		if len(netIO) > 0 {
			currentNetIn = netIO[0].BytesRecv
			currentNetOut = netIO[0].BytesSent
		}

		// 计算网速 (字节/秒)
		var speedIn, speedOut uint64
		if lastNetIn > 0 {
			speedIn = (currentNetIn - lastNetIn) / 5
			speedOut = (currentNetOut - lastNetOut) / 5
		}
		lastNetIn = currentNetIn
		lastNetOut = currentNetOut

		// [新增] 获取系统运行时间 (秒)
		sysUptime, _ := host.Uptime()

		// 5. 组装数据
		data := ReportData{
			NodeID:    nodeID,
			CPUUsage:  cpuVal,
			MemUsage:  memVal,
			DiskUsage: diskVal,
			NetIn:     speedIn,
			NetOut:    speedOut,
			Uptime:    sysUptime, // [新增] 将获取到的时间打包
		}

		// 6. 发送数据到主控端
		jsonData, _ := json.Marshal(data)
		resp, err := http.Post(serverURL, "application/json", bytes.NewBuffer(jsonData))
		if err == nil {
			resp.Body.Close()
		}

		// 每 5 秒上报一次
		time.Sleep(4 * time.Second)
	}
}