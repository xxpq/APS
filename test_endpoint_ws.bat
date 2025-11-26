@echo off
echo Testing endpoint with WebSocket transport...
echo.

echo Starting server with WebSocket support...
start cmd /k "go run . -config config.websocket.example.json"

timeout /t 3 /nobreak > nul

echo.
echo Starting endpoint with WebSocket mode...
start cmd /k "cd endpoint && go run . -server localhost:8081 -tunnel test-tunnel -name ws-endpoint -transport ws -debug"

timeout /t 2 /nobreak > nul

echo.
echo Starting endpoint with mix mode (gRPC fallback to WebSocket)...
start cmd /k "cd endpoint && go run . -server localhost:8081 -tunnel test-tunnel -name mix-endpoint -transport mix -debug"

echo.
echo All services started. Check the console windows for activity.
echo Press any key to stop all services...
pause

echo Stopping services...
taskkill /F /IM go.exe 2>nul
taskkill /F /IM aps.exe 2>nul

echo Test completed.
pause