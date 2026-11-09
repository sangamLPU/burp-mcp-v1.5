$ErrorActionPreference = 'Stop'

$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$serverScript = Join-Path $PSScriptRoot 'local-test-server.ps1'
$validationDir = Join-Path $repoRoot 'build\validation'
$null = New-Item -ItemType Directory -Force -Path $validationDir
$runId = [Guid]::NewGuid().ToString().ToLowerInvariant()
$serverIdentityBytes = New-Object byte[] 32
$random = [System.Security.Cryptography.RandomNumberGenerator]::Create()
try { $random.GetBytes($serverIdentityBytes) } finally { $random.Dispose() }
$serverIdentity = [Convert]::ToBase64String($serverIdentityBytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
$wrongServerIdentity = if ($serverIdentity[0] -eq 'A') { 'B' + $serverIdentity.Substring(1) } else { 'A' + $serverIdentity.Substring(1) }
$logPath = Join-Path $validationDir ("local-identity-{0}.jsonl" -f [Guid]::NewGuid().ToString('N'))
$stdoutPath = Join-Path $validationDir ("local-identity-{0}.out.log" -f [Guid]::NewGuid().ToString('N'))
$stderrPath = Join-Path $validationDir ("local-identity-{0}.err.log" -f [Guid]::NewGuid().ToString('N'))
$serverProcess = $null
$previousEnvironment = @{}

function Invoke-IdentityProbe {
    param([string]$Path, [string]$RunHeader = '', [string]$IdentityHeader = '')

    $request = [System.Net.HttpWebRequest]::Create("http://127.0.0.1:8000$Path")
    $request.Method = 'GET'
    $request.Proxy = $null
    $request.Timeout = 3000
    $request.ReadWriteTimeout = 3000
    $request.KeepAlive = $false
    if ($RunHeader) { $request.Headers['X-MCP-Test-Run'] = $RunHeader }
    if ($IdentityHeader) { $request.Headers['X-MCP-Server-Identity'] = $IdentityHeader }
    $response = $null
    try {
        try { $response = $request.GetResponse() }
        catch [System.Net.WebException] {
            if ($null -eq $_.Exception.Response) { throw }
            $response = [System.Net.HttpWebResponse]$_.Exception.Response
        }
        $body = ''
        $reader = [System.IO.StreamReader]::new($response.GetResponseStream())
        try { $body = $reader.ReadToEnd() } finally { $reader.Dispose() }
        [pscustomobject]@{
            StatusCode = [int]$response.StatusCode
            Body = $body
            TestRun = $response.Headers['X-MCP-Test-Run']
            ServerIdentity = $response.Headers['X-MCP-Server-Identity']
        }
    } finally {
        if ($null -ne $response) { $response.Dispose() }
    }
}

try {
    $listeners = @(Get-NetTCPConnection -State Listen -LocalAddress '127.0.0.1' -LocalPort 8000 -ErrorAction SilentlyContinue)
    if ($listeners.Count -gt 0) { throw '127.0.0.1:8000 is already in use; no existing process was changed.' }

    foreach ($name in @('BURP_MCP_TOKEN', 'BURP_TEST_RUN_ID', 'BURP_TEST_SERVER_IDENTITY')) {
        $previousEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
    }
    [Environment]::SetEnvironmentVariable('BURP_MCP_TOKEN', $null, 'Process')
    [Environment]::SetEnvironmentVariable('BURP_TEST_RUN_ID', $runId, 'Process')
    [Environment]::SetEnvironmentVariable('BURP_TEST_SERVER_IDENTITY', $serverIdentity, 'Process')
    try {
        $shellPath = (Get-Process -Id $PID).Path
        $arguments = @(
            '-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $serverScript,
            '-IdentityFromEnvironment', '-LogPath', $logPath, '-MaxRequests', '12',
            '-MaxBodyBytes', '1048576', '-RequestTimeoutSeconds', '5',
            '-MaxRunSeconds', '60', '-TimeoutDelayMilliseconds', '0'
        )
        $serverProcess = Start-Process -FilePath $shellPath -ArgumentList $arguments -WorkingDirectory $repoRoot -WindowStyle Hidden -PassThru `
            -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath
    } finally {
        foreach ($name in $previousEnvironment.Keys) {
            [Environment]::SetEnvironmentVariable($name, $previousEnvironment[$name], 'Process')
        }
        $previousEnvironment.Clear()
    }

    $listenDeadline = [DateTime]::UtcNow.AddSeconds(10)
    do {
        $serverProcess.Refresh()
        if ($serverProcess.HasExited) { throw 'Identity test server exited before binding.' }
        $listeners = @(Get-NetTCPConnection -State Listen -LocalAddress '127.0.0.1' -LocalPort 8000 -ErrorAction SilentlyContinue)
        if ($listeners.Count -gt 0) { break }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $listenDeadline)
    if ($listeners.Count -eq 0 -or @($listeners | Where-Object OwningProcess -eq $serverProcess.Id).Count -ne 1) {
        throw 'The identity test server did not bind 127.0.0.1:8000 under its own process ID.'
    }

    $publicHealth = Invoke-IdentityProbe -Path '/__phase4a-health'
    $health = Invoke-IdentityProbe -Path '/__phase4a-health' -RunHeader $runId -IdentityHeader $serverIdentity
    if ($publicHealth.StatusCode -ne 403 -or $health.StatusCode -ne 200 -or
        $health.Body -cne 'MCP_LOCAL_TEST_SERVER_READY' -or
        $health.TestRun -cne $runId -or $health.ServerIdentity -cne $serverIdentity) {
        throw 'Health route did not require and return only the matching active synthetic identity.'
    }

    $probes = @(
        (Invoke-IdentityProbe -Path '/live-check' -RunHeader $runId -IdentityHeader $serverIdentity),
        (Invoke-IdentityProbe -Path '/test-html'),
        (Invoke-IdentityProbe -Path '/test-html' -RunHeader '11111111-2222-3333-4444-555555555555' -IdentityHeader $serverIdentity),
        (Invoke-IdentityProbe -Path '/test-html' -RunHeader $runId -IdentityHeader $wrongServerIdentity),
        (Invoke-IdentityProbe -Path '/test-html' -RunHeader $runId -IdentityHeader $serverIdentity)
    )
    if ($probes[0].StatusCode -ne 403 -or $probes[1].StatusCode -ne 403 -or
        $probes[2].StatusCode -ne 403 -or $probes[3].StatusCode -ne 403 -or
        $probes[4].StatusCode -ne 200) {
        throw 'Synthetic identity enforcement did not reject every invalid probe and accept the exact local identity.'
    }

    $records = @(Get-Content -LiteralPath $logPath | ForEach-Object { $_ | ConvertFrom-Json -ErrorAction Stop })
    $identityFieldsPersisted = $false
    if ($records.Count -eq 1) {
        $identityFieldsPersisted = @($records[0].PSObject.Properties.Name | Where-Object { $_ -in @('testRunId', 'serverIdentity') }).Count -gt 0
    }
    if ($records.Count -ne 1 -or $records[0].path -ne '/test-html' -or $identityFieldsPersisted) {
        throw 'Health or rejected identity probes contaminated origin delivery evidence.'
    }

    [pscustomobject]@{
        Status = 'PASS'
        UnauthenticatedHealthRejected = ($publicHealth.StatusCode -eq 403)
        HealthIdentity = 'PASS'
        InvalidPathRejected = ($probes[0].StatusCode -eq 403)
        MissingIdentityRejected = ($probes[1].StatusCode -eq 403)
        WrongRunRejected = ($probes[2].StatusCode -eq 403)
        WrongServerIdentityRejected = ($probes[3].StatusCode -eq 403)
        ExactIdentityAccepted = ($probes[4].StatusCode -eq 200)
        OriginRecords = $records.Count
        RunAndServerIdentitiesPersisted = $identityFieldsPersisted
        RejectedAndHealthRequestsLogged = $false
    } | Format-List
} finally {
    if ($null -ne $serverProcess) {
        $serverProcess.Refresh()
        if (-not $serverProcess.HasExited) {
            $ownedListener = @(Get-NetTCPConnection -State Listen -LocalAddress '127.0.0.1' -LocalPort 8000 -ErrorAction SilentlyContinue |
                Where-Object OwningProcess -eq $serverProcess.Id)
            if ($ownedListener.Count -gt 0) { $serverProcess.Kill() }
            $serverProcess.WaitForExit(5000) | Out-Null
        }
        $serverProcess.Dispose()
    }
    foreach ($name in $previousEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($name, $previousEnvironment[$name], 'Process')
    }
    $previousEnvironment.Clear()
}
