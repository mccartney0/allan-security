$ErrorActionPreference = 'Stop'
$root = Join-Path $env:TEMP 'allan-realtime-smoke'
Remove-Item -Recurse -Force $root -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $root | Out-Null
$watch = Join-Path $root 'watch'
$localAppData = Join-Path $root 'localappdata'
New-Item -ItemType Directory -Force -Path $watch, $localAppData | Out-Null
$env:LOCALAPPDATA = $localAppData
$stdout = Join-Path $root 'monitor.stdout.log'
$stderr = Join-Path $root 'monitor.stderr.log'
$binary = 'D:\Softwares\antivirus\target\debug\allan-security-cli.exe'
$process = Start-Process -FilePath $binary -ArgumentList @('realtime', $watch) -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru -WindowStyle Hidden
try {
    Start-Sleep -Seconds 2
    Set-Content -Path (Join-Path $watch 'safe.txt') -Value 'allan-security-realtime-smoke'
    Start-Sleep -Seconds 5
    $history = Join-Path $localAppData 'AllanSecurity\history.jsonl'
    if (-not (Test-Path $history)) {
        throw "histórico não foi criado pelo monitor"
    }
    $historyContent = Get-Content $history -Raw
    if ([string]::IsNullOrWhiteSpace($historyContent)) {
        throw "histórico foi criado, mas não recebeu resultado do scan"
    }
    Write-Output 'REALTIME_SMOKE_OK'
    Write-Output "History: $history"
    Write-Output "Monitor output: $stdout"
} finally {
    if (-not $process.HasExited) {
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
    }
}
