@echo off
echo Testing relay mode functionality...
echo.

echo Starting main server with relay support...
start cmd /k "go run . -config config.websocket.example.json"

timeout /t 3 /nobreak > nul

echo.
echo Starting E1 (relay server)...
start cmd /k "cd endpoint && go run . -server localhost:8081 -tunnel test-tunnel -name E1 -relay-mode relay -debug"

timeout /t 2 /nobreak > nul

echo.
echo Starting E2 (client via E1 relay)...
start cmd /k "cd endpoint && go run . -server localhost:8081 -tunnel test-tunnel -name E2 -relay-mode hybrid -relays localhost:18081 -debug"

timeout /t 2 /nobreak > nul

echo.
echo Starting E3 (client via E2 relay)...
start cmd /k "cd endpoint && go run . -server localhost:8081 -tunnel test-tunnel -name E3 -relay-mode hybrid -relays localhost:18082 -debug"

echo.
echo All services started. Check the console windows for activity.
echo Press any key to stop all services...
pause

echo Stopping services...
taskkill /F /IM go.exe 2>nul
taskkill /F /IM aps.exe 2>nul

echo Test completed.
pause