<img width="1530" height="638" alt="image" src="https://github.com/user-attachments/assets/98738f30-50c1-4818-90fc-52cc53f90517" />


轻量化服务器探针
是一个极其轻量、安全且专注于服务器状态监控的开源探针。我们追求“极简”，只保留最核心的性能指标，让运维回归本质。

核心特性
无需 Root 运行：客户端默认以低权限 monitor 用户身份运行，即便进程被攻破也无法威胁系统安全。

极致轻量：极低的内存占用和 CPU 开销，几乎不干扰业务运行。

自动自愈：基于 Systemd 守护，进程崩溃后会在 5 秒内自动重启。

隐私保护：探针只上报基础性能数据，不采集任何敏感文件或用户信息。

一键式部署：支持 Linux (x86_64/ARM64) 及 Windows 平台，安装全程无需手动配置。

监控指标
CPU 使用率

内存使用率

磁盘剩余空间

实时网络带宽 (进/出)

系统运行时间 (Uptime)

ipv4/ipv6显示

批量删除vps

简单自定义美化

运行:ip:5001

可以自己做个 ip:5001  的反代

Linux 部署 (推荐)
```
curl -o install.sh https://raw.githubusercontent.com/yzhpxd/tanZ/main/static/install.sh && bash install.sh
```
windowns 部署 
在 PowerShell (管理员模式) 中执行：
```
Set-ExecutionPolicy Bypass -Scope Process -Force; irm https://raw.githubusercontent.com/yzhpxd/tanz/main/static/install.ps1 | iex
```
