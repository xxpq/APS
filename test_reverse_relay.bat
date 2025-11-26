@echo off
echo === 反向中继模式测试 ===
echo.

echo 1. 启动APS服务器 (主服务器)
start cmd /k "aps.exe -config test_reverse_relay.json -mode server"
timeout /t 3 /nobreak > nul

echo 2. 启动E2端点 (反向等待模式 - 监听端口)
start cmd /k "aps.exe -config test_reverse_relay.json -mode endpoint -name E2 -relay-mode reverse-wait"
timeout /t 3 /nobreak > nul

echo 3. 启动E1端点 (反向连接模式 - 主动连接E2)
start cmd /k "aps.exe -config test_reverse_relay.json -mode endpoint -name E1 -relay-mode reverse"
timeout /t 5 /nobreak > nul

echo.
echo === 测试场景说明 ===
echo E1 (受限端点，无法监听端口) 主动连接 E2 (可监听端口)
echo 连接建立后，E2可以通过E1访问APS服务器
echo 路径: S <-> E2 <-> E1 (反向连接)
echo.

echo 按任意键停止所有服务...
pause > nul

echo 停止所有服务...
taskkill /F /IM aps.exe > nul 2>&1
echo 测试完成