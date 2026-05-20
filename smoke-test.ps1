$ErrorActionPreference = "Stop"

$API = "http://127.0.0.1:8080"
$USER = "admin"
$PASS = "netguard123"
$TEST_IP = "203.0.113.50"

Write-Host "`n[1] Health check"
Invoke-RestMethod "$API/health" | ConvertTo-Json -Depth 5

Write-Host "`n[2] Login"
$loginBody = @{ username = $USER; password = $PASS } | ConvertTo-Json
$login = Invoke-RestMethod -Method POST -Uri "$API/auth/login" -ContentType "application/json" -Body $loginBody
$token = $login.access_token
$H = @{ Authorization = "Bearer $token"; "Content-Type"="application/json" }

Write-Host "`n[3] Auth me"
Invoke-RestMethod -Uri "$API/auth/me" -Headers $H | ConvertTo-Json -Depth 5

Write-Host "`n[4] Stats + History"
Invoke-RestMethod -Uri "$API/stats" -Headers $H | ConvertTo-Json -Depth 5
(Invoke-RestMethod -Uri "$API/history?limit=5" -Headers $H) | ConvertTo-Json -Depth 5

Write-Host "`n[5] Interfaces + Capture status"
$ifaces = Invoke-RestMethod -Uri "$API/capture/interfaces" -Headers $H
"Interfaces count: " + $ifaces.interfaces.Count
Invoke-RestMethod -Uri "$API/capture/status" -Headers $H | ConvertTo-Json -Depth 5

Write-Host "`n[6] Predict test payload"
$testPayload = @{
  "Dst Port"=80; "Protocol"=6; "Flow Duration"=6010454; "Tot Fwd Pkts"=4; "Tot Bwd Pkts"=4;
  "TotLen Fwd Pkts"=285; "TotLen Bwd Pkts"=972; "test_mode"=$true
} | ConvertTo-Json
Invoke-RestMethod -Method POST -Uri "$API/predict" -ContentType "application/json" -Body $testPayload | ConvertTo-Json -Depth 5

Write-Host "`n[7] Network scan quick"
Invoke-RestMethod -Method POST -Uri "$API/network/scan/arp" -Headers $H | ConvertTo-Json -Depth 5

Write-Host "`n[8] Blocklist block/unblock smoke"
$blockBody = @{ ip=$TEST_IP; reason="Smoke test"; ttl_seconds=300; layer="firewall" } | ConvertTo-Json
Invoke-RestMethod -Method POST -Uri "$API/blocked-ips" -Headers $H -Body $blockBody | ConvertTo-Json -Depth 5
Invoke-RestMethod -Method DELETE -Uri "$API/blocked-ips/$TEST_IP" -Headers $H | ConvertTo-Json -Depth 5

Write-Host "`n[9] Alert settings read/write/read"
$cur = Invoke-RestMethod -Uri "$API/admin/alert-settings" -Headers $H
$cur | ConvertTo-Json -Depth 5
$patchBody = @{ alert_to_email = $cur.alert_to_email } | ConvertTo-Json
Invoke-RestMethod -Method PATCH -Uri "$API/admin/alert-settings" -Headers $H -Body $patchBody | ConvertTo-Json -Depth 5

Write-Host "`n[10] Recent detections from SQLite"
python -c "import sqlite3; c=sqlite3.connect(r'c:\iot-ids\logs\detections.db'); rows=c.execute('select timestamp,prediction,confidence,severity,source_ip,mode from detections order by id desc limit 10').fetchall(); [print(r) for r in rows]; c.close()"

Write-Host "`n✅ Smoke test complete"
