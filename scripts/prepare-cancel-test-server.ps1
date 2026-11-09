param(
    [string]$TestRunId = '',
    [string]$ServerIdentity = '',
    [switch]$IdentityFromEnvironment,
    [switch]$RuleEngineTestMode,
    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$serverScript = Join-Path $PSScriptRoot 'local-test-server.ps1'
$buildDirectory = Join-Path $repoRoot 'build'
$logPath = Join-Path $buildDirectory 'live-test-server-observations.jsonl'
$stdoutPath = Join-Path $buildDirectory 'phase4a-server.stdout.log'
$stderrPath = Join-Path $buildDirectory 'phase4a-server.stderr.log'
$maxRequests = 40
$maxBodyBytes = 1048576
$requestTimeoutSeconds = 10
$maxRunSeconds = 900
$healthUrl = 'http://127.0.0.1:8000/__phase4a-health'
$healthMarker = 'MCP_LOCAL_TEST_SERVER_READY'
$serverProcess = $null

if ($IdentityFromEnvironment) {
    $TestRunId = [Environment]::GetEnvironmentVariable('BURP_TEST_RUN_ID', 'Process')
    $ServerIdentity = [Environment]::GetEnvironmentVariable('BURP_TEST_SERVER_IDENTITY', 'Process')
}

if ([string]::IsNullOrWhiteSpace($TestRunId) -xor [string]::IsNullOrWhiteSpace($ServerIdentity)) {
    throw 'Supply both -TestRunId and -ServerIdentity for unattended local test mode, or supply neither.'
}
if ($TestRunId -and $TestRunId -notmatch '^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$') {
    throw 'TestRunId is malformed.'
}
if ($ServerIdentity -and $ServerIdentity -notmatch '^[A-Za-z0-9_-]{43}$') {
    throw 'ServerIdentity is malformed.'
}

if (-not (Test-Path -LiteralPath $serverScript -PathType Leaf)) {
    throw "Local test-server script is missing: $serverScript"
}

$existingListeners = @(Get-NetTCPConnection -State Listen -LocalPort 8000 -ErrorAction SilentlyContinue)
if ($existingListeners.Count -gt 0) {
    $owners = @($existingListeners | ForEach-Object {
        $owner = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        if ($owner) { "$($owner.ProcessName) PID $($owner.Id)" } else { "PID $($_.OwningProcess)" }
    } | Select-Object -Unique)
    throw "Port 8000 is already occupied ($($owners -join ', ')); the script will not stop or replace that process."
}

New-Item -ItemType Directory -Force -Path $buildDirectory | Out-Null
$serverArguments = @(
    '-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $serverScript,
    '-LogPath', $logPath,
    '-MaxRequests', "$maxRequests",
    '-MaxBodyBytes', "$maxBodyBytes",
    '-RequestTimeoutSeconds', "$requestTimeoutSeconds",
    '-MaxRunSeconds', "$maxRunSeconds"
)
$serverArguments += '-IdentityFromEnvironment'
if ($RuleEngineTestMode) { $serverArguments += '-RuleEngineTestMode' }
$environmentNames = @('BURP_MCP_TOKEN', 'BURP_TEST_RUN_ID', 'BURP_TEST_SERVER_IDENTITY')
$previousEnvironment = @{}
foreach ($name in $environmentNames) {
    $previousEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}
try {
    [Environment]::SetEnvironmentVariable('BURP_MCP_TOKEN', $null, 'Process')
    [Environment]::SetEnvironmentVariable('BURP_TEST_RUN_ID', $TestRunId, 'Process')
    [Environment]::SetEnvironmentVariable('BURP_TEST_SERVER_IDENTITY', $ServerIdentity, 'Process')
    $serverProcess = Start-Process -FilePath 'powershell.exe' -ArgumentList $serverArguments -WorkingDirectory $repoRoot -WindowStyle Hidden -PassThru -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath
} finally {
    foreach ($name in $previousEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($name, $previousEnvironment[$name], 'Process')
    }
    $previousEnvironment.Clear()
}

try {
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    $listeners = @()
    while ([DateTime]::UtcNow -lt $deadline) {
        $serverProcess.Refresh()
        if ($serverProcess.HasExited) {
            throw "Local test server exited during startup (PID $($serverProcess.Id))."
        }
        $listeners = @(Get-NetTCPConnection -State Listen -LocalPort 8000 -ErrorAction SilentlyContinue)
        if ($listeners.Count -gt 0) { break }
        Start-Sleep -Milliseconds 100
    }
    if ($listeners.Count -eq 0) {
        throw 'Local test server did not open port 8000 within 10 seconds.'
    }

    $request = [System.Net.HttpWebRequest]::Create($healthUrl)
    $request.Method = 'GET'
    $request.Proxy = $null
    $request.Timeout = 3000
    $request.ReadWriteTimeout = 3000
    $request.KeepAlive = $false
    if ($TestRunId) {
        $request.Headers['X-MCP-Test-Run'] = $TestRunId
        $request.Headers['X-MCP-Server-Identity'] = $ServerIdentity
    }
    $response = $null
    $reader = $null
    try {
        $response = $request.GetResponse()
        $reader = [System.IO.StreamReader]::new($response.GetResponseStream(), [System.Text.Encoding]::ASCII)
        $body = $reader.ReadToEnd()
        if ([int]$response.StatusCode -ne 200 -or $body -cne $healthMarker) {
            throw 'Local test server health check did not match the expected response.'
        }
        if ($TestRunId -and (
            $response.Headers['X-MCP-Test-Run'] -cne $TestRunId -or
            $response.Headers['X-MCP-Server-Identity'] -cne $ServerIdentity
        )) {
            throw 'Local test server identity did not match the active Burp-local authorization.'
        }
    } finally {
        if ($null -ne $reader) { $reader.Dispose() }
        if ($null -ne $response) { $response.Dispose() }
    }

    $serverProcess.Refresh()
    $listeners = @(Get-NetTCPConnection -State Listen -LocalPort 8000 -ErrorAction SilentlyContinue)
    if ($serverProcess.HasExited -or $listeners.Count -eq 0) {
        throw 'Local test server stopped during its health check.'
    }

    $readyResult = [pscustomobject]@{
        State = 'READY'
        ProcessId = $serverProcess.Id
        LoopbackEndpoint = '127.0.0.1:8000'
        MaxRequests = $maxRequests
        MaxBodyBytes = $maxBodyBytes
        RequestTimeoutSeconds = $requestTimeoutSeconds
        MaxRunSeconds = $maxRunSeconds
        RuleEngineTestMode = [bool]$RuleEngineTestMode
        HealthCheck = 'PASS; excluded from the origin observation log'
        ObservationLog = $logPath
    }
    if ($PassThru) { $readyResult } else { $readyResult | Format-List }
} catch {
    if ($null -ne $serverProcess) {
        $serverProcess.Refresh()
        if (-not $serverProcess.HasExited) {
            Stop-Process -Id $serverProcess.Id -Force -ErrorAction SilentlyContinue
        }
    }
    throw
}
