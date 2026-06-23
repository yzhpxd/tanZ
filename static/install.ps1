# 强制使用 TLS 1.2（兼容老版本 Windows 网络请求）
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$ServerUrl = "https://vps.666200.xyz/report"
$BaseUrl = "https://vps.666200.xyz/static"

# 【核心防冲突逻辑】在计算机名后附加 4 位随机数，解决克隆机重名覆盖问题
$RandomSuffix = Get-Random -Minimum 1000 -Maximum 9999
$NodeId = "$env:COMPUTERNAME-$RandomSuffix"

$InstallDir = "C:\tz-agent"
$ExePath = "$InstallDir\tz-agent-win64.exe"
$DownloadUrl = "$BaseUrl/tz-agent-win64.exe"

Write-Host "[-] 正在创建目录 $InstallDir ..." -ForegroundColor Cyan
if (!(Test-Path $InstallDir)) { New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null }

Write-Host "[-] 开始从服务端下载 Windows 客户端..." -ForegroundColor Cyan
Invoke-WebRequest -Uri $DownloadUrl -OutFile $ExePath

Write-Host "[-] 配置开机自启 (VBS后台隐藏运行)..." -ForegroundColor Cyan
# 获取当前用户的 Windows 启动文件夹
$StartupFolder = [Environment]::GetFolderPath('Startup')
$VbsPath = "$StartupFolder\tz-agent.vbs"

# 生成 VBS 隐藏运行脚本内容
$VbsContent = @"
Set ws = CreateObject("Wscript.Shell")
ws.Run """$ExePath"" -id ""$NodeId"" -server ""$ServerUrl""", 0, False
"@

# 写入启动文件夹 (每次开机会自动隐身运行这个 VBS)
Set-Content -Path $VbsPath -Value $VbsContent -Encoding Default

Write-Host "[-] 正在启动探针..." -ForegroundColor Cyan
# 杀掉可能正在运行的老进程，防止冲突
Stop-Process -Name "tz-agent-win64" -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

# 隐蔽执行 VBS 启动探针
Start-Process "wscript.exe" -ArgumentList "`"$VbsPath`"" -WindowStyle Hidden

Write-Host "[+] ==========================================" -ForegroundColor Green
Write-Host "[+] Windows 探针安装成功！已在后台静默运行。" -ForegroundColor Green
Write-Host "[+] 开机自启已就绪，节点名自动设为: $NodeId (防冲突模式)" -ForegroundColor Green
Write-Host "[+] （提示：可前往网页端点击名称重新备注）" -ForegroundColor Green
Write-Host "[+] ==========================================" -ForegroundColor Green
