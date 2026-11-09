$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'cancel-test-auth.ps1')

$assertions = 0
function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw "ASSERTION FAILED: $Message" }
    $script:assertions++
}
function Assert-Equal {
    param([object]$Expected, [object]$Actual, [string]$Message)
    if ($Expected -cne $Actual) { throw "ASSERTION FAILED: $Message (expected '$Expected', got '$Actual')" }
    $script:assertions++
}
function Read-Events {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return @() }
    return @(Get-Content -LiteralPath $Path | Where-Object { $_ } | ForEach-Object { $_ | ConvertFrom-Json })
}
function Add-Event {
    param([string]$Path, [string]$Name, [int]$ProcessId = 0)
    $event = [pscustomobject]@{ name = $Name; processId = $ProcessId } | ConvertTo-Json -Compress
    [System.IO.File]::AppendAllText($Path, $event + [Environment]::NewLine)
}
function New-Harness {
    param(
        [string]$Scenario,
        [string]$FailurePhase = '',
        [string]$Mode = 'SUPERVISED',
        [string]$ResultCounts = '{"PASS":3,"FAIL":0,"BLOCKED":0,"INCONCLUSIVE":0,"UNVERIFIED":0,"UNSUPPORTED":0}'
    )
    $root = Join-Path $env:TEMP ("burp-coordinator-offline-{0}-{1}" -f $Scenario, [Guid]::NewGuid().ToString('N'))
    $repo = Join-Path $root 'repo'
    $scripts = Join-Path $repo 'scripts'
    $null = New-Item -ItemType Directory -Path $scripts -Force
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'run-supervised-reliability-suite.ps1') -Destination $scripts
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'cancel-test-auth.ps1') -Destination $scripts
    $eventLog = Join-Path $root 'events.jsonl'
    $fakeValidation = @'
param([ValidateSet('OFFLINE','LOCAL','SUPERVISED')][string]$Mode='OFFLINE',[int]$PerTestTimeoutSeconds=300)
$reportDirectory = Join-Path $PSScriptRoot '..\build\reports\full-validation'
$null = New-Item -ItemType Directory -Path $reportDirectory -Force
$counts = $env:COORDINATOR_RESULT_COUNTS | ConvertFrom-Json
$report = [ordered]@{runId='fake-validation';mode=$Mode;counts=$counts;results=@()}
$name = 'validation-' + [Guid]::NewGuid().ToString('N') + '.json'
$report | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $reportDirectory $name) -Encoding UTF8
Write-Output "FAKE VALIDATION REPORT: $Mode"
'@
    [System.IO.File]::WriteAllText((Join-Path $scripts 'run-full-validation.ps1'), $fakeValidation, [System.Text.UTF8Encoding]::new($false))

    $fakePython = @'
import json, os, sys
args = sys.argv[1:]
events = os.environ['COORDINATOR_EVENT_LOG']
fail_phase = os.environ.get('COORDINATOR_FAIL_PHASE', '')
phase = args[0] if args else 'unexpected'
with open(events, 'a', encoding='utf-8') as stream:
    stream.write(json.dumps({'name': phase}) + '\n')
if fail_phase == phase:
    sys.stderr.write('PREFLIGHT FAIL: controlled offline ' + phase + ' gate; request was not sent.\n')
    sys.exit(2)
if phase == '--coordinator-identities':
    print(json.dumps({'testRunId':'11111111-2222-3333-4444-555555555555','serverIdentity':'S'*43,'scopeEligibleCount':9,'authorizationRemainingMillis':290000}))
elif phase == '--setup-only':
    print('SETUP PREFLIGHT PASS: controlled offline fixture, auth, scope, and queues verified.')
elif phase == '--start-session':
    print(json.dumps({'enabled':True,'heartbeatHealth':'HEALTHY','sessionLifetimeSeconds':180,'sessionRemainingMillis':179000,'authorizationRemainingMillis':250000,'pendingRequests':0,'pendingResponses':0}))
elif phase == '--drop-matching-request':
    print(json.dumps({'dropState':'DROPPED','approvalMode':'AUTOMATIC','automaticApprovalEvidence':True,'staleGetRejected':True,'staleEditRejected':True,'staleForwardRejected':True,'pendingRequests':0,'pendingResponses':0}))
elif phase == '--stop-session-if-safe':
    print(json.dumps({'stopped':True,'alreadyInactive':False,'pendingRequests':0,'pendingResponses':0}))
else:
    sys.stderr.write('unexpected offline helper arguments\n')
    sys.exit(9)
'@
    [System.IO.File]::WriteAllText((Join-Path $scripts 'cancel_test_preflight.py'), $fakePython, [System.Text.UTF8Encoding]::new($false))

    $listenerScript = @'
$ErrorActionPreference = 'Stop'
$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 8000)
try {
    $listener.Start()
    while ($true) { Start-Sleep -Milliseconds 250 }
} finally { $listener.Stop() }
'@
    [System.IO.File]::WriteAllText((Join-Path $scripts 'fake-listener.ps1'), $listenerScript, [System.Text.UTF8Encoding]::new($false))
    $fixtureScript = @'
param([switch]$IdentityFromEnvironment, [switch]$PassThru)
if (-not $IdentityFromEnvironment -or -not $PassThru) { throw 'Coordinator did not use the in-memory fixture identity handoff.' }
if ($env:BURP_TEST_RUN_ID -notmatch '^[a-f0-9-]{36}$' -or $env:BURP_TEST_SERVER_IDENTITY -notmatch '^[A-Za-z0-9_-]{43}$') { throw 'Fixture identity environment is malformed.' }
$powershell = (Get-Process -Id $PID).Path
$listenerScript = Join-Path $PSScriptRoot 'fake-listener.ps1'
$arguments = @('-NoLogo','-NoProfile','-ExecutionPolicy','Bypass','-File',$listenerScript)
$quoted = @($arguments | ForEach-Object { ConvertTo-CancelTestProcessArgument -Value $_ }) -join ' '
$info = [System.Diagnostics.ProcessStartInfo]::new()
$info.FileName = $powershell
$info.Arguments = $quoted
$info.UseShellExecute = $false
$info.CreateNoWindow = $true
$process = [System.Diagnostics.Process]::new()
$process.StartInfo = $info
if (-not $process.Start()) { throw 'Offline listener child did not start.' }
$deadline = [DateTime]::UtcNow.AddSeconds(5)
do {
    $listener = @(Get-NetTCPConnection -State Listen -LocalPort 8000 -ErrorAction SilentlyContinue | Where-Object OwningProcess -eq $process.Id)
    if ($listener.Count -gt 0) { break }
    Start-Sleep -Milliseconds 50
} while ([DateTime]::UtcNow -lt $deadline)
if ($listener.Count -eq 0) { Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue; throw 'Offline controlled listener did not start.' }
$event = [pscustomobject]@{ name='fixture'; processId=$process.Id } | ConvertTo-Json -Compress
[System.IO.File]::AppendAllText($env:COORDINATOR_EVENT_LOG, $event + [Environment]::NewLine)
[pscustomobject]@{State='READY';ProcessId=$process.Id;LoopbackEndpoint='127.0.0.1:8000';HealthCheck='PASS; identity headers matched'}
'@
    [System.IO.File]::WriteAllText((Join-Path $scripts 'prepare-cancel-test-server.ps1'), $fixtureScript, [System.Text.UTF8Encoding]::new($false))

    $fakeRunner = @'
param([switch]$PromptForMcpToken,[ValidateRange(150,600)][int]$MinimumSessionSeconds=300,[string]$CoordinatorStatePath='')
if (-not $PromptForMcpToken -or $MinimumSessionSeconds -ne 180 -or -not $CoordinatorStatePath) { throw 'Runner arguments did not preserve the coordinator session budget.' }
if ($env:BURP_TEST_RUN_ID -notmatch '^[a-f0-9-]{36}$' -or $env:BURP_TEST_SERVER_IDENTITY -notmatch '^[A-Za-z0-9_-]{43}$') { throw 'Runner did not inherit the fixture identities securely.' }
$event = [pscustomobject]@{name='runner';processId=0} | ConvertTo-Json -Compress
[System.IO.File]::AppendAllText($env:COORDINATOR_EVENT_LOG, $event + [Environment]::NewLine)
$state = [ordered]@{phase='Complete';testId='phase4a-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';targetPath='/test-cancel';requestSent=$true;clientOutcome='ConnectionReset';clientHttpStatusCode=$null;serverRequestsToTestPath=0;matchingTestIdRecords=0;validationPassed=$true;failedConditions=@();timestampUtc=[DateTime]::UtcNow.ToString('o')}
[System.IO.File]::WriteAllText($CoordinatorStatePath, ($state | ConvertTo-Json -Compress), [System.Text.UTF8Encoding]::new($false))
'@
    [System.IO.File]::WriteAllText((Join-Path $scripts 'run-cancel-test.ps1'), $fakeRunner, [System.Text.UTF8Encoding]::new($false))
    return [pscustomobject]@{ Root=$root; Scripts=$scripts; EventLog=$eventLog; FailurePhase=$FailurePhase; Mode=$Mode; ResultCounts=$ResultCounts }
}
function Invoke-Harness {
    param($Harness)
    $powershell = (Get-Process -Id $PID).Path
    $scriptPath = Join-Path $Harness.Scripts 'run-supervised-reliability-suite.ps1'
    $args = @('-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',$scriptPath,'-Mode',$Harness.Mode)
    if ($Harness.Mode -eq 'SUPERVISED') { $args += @('-SessionLifetimeSeconds','180','-QueueWaitSeconds','5') }
    $quoted = @($args | ForEach-Object { ConvertTo-CancelTestProcessArgument -Value $_ }) -join ' '
    $info = [System.Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $powershell
    $info.Arguments = $quoted
    $info.WorkingDirectory = $Harness.Root
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.EnvironmentVariables['BURP_MCP_TOKEN'] = 'T' * 43
    $info.EnvironmentVariables['COORDINATOR_EVENT_LOG'] = $Harness.EventLog
    $info.EnvironmentVariables['COORDINATOR_FAIL_PHASE'] = $Harness.FailurePhase
    $info.EnvironmentVariables['COORDINATOR_RESULT_COUNTS'] = $Harness.ResultCounts
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $info
    if (-not $process.Start()) { throw 'Offline coordinator child did not start.' }
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit(90000)) {
        try { $process.Kill() } catch { }
        throw 'Offline coordinator simulation exceeded its 90-second bound.'
    }
    $result = [pscustomobject]@{
        ExitCode=$process.ExitCode
        StdOut=$stdoutTask.GetAwaiter().GetResult()
        StdErr=$stderrTask.GetAwaiter().GetResult()
        Events=@(Read-Events -Path $Harness.EventLog)
        Report=(Get-Content -LiteralPath (Get-ChildItem -LiteralPath (Join-Path $Harness.Root 'repo\build\reports') -Filter 'supervised-reliability-*.json' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName -Raw -ErrorAction SilentlyContinue)
    }
    $process.Dispose()
    return $result
}

$listenerAlreadyPresent = @(Get-NetTCPConnection -State Listen -LocalPort 8000 -ErrorAction SilentlyContinue)
if ($listenerAlreadyPresent.Count -gt 0) { throw 'Port 8000 is occupied; the offline coordinator harness will not touch an existing listener.' }
$harnesses = [System.Collections.Generic.List[object]]::new()
$syntheticIdentity = 'S' * 43
$syntheticToken = 'T' * 43
try {
    $success = New-Harness -Scenario 'success'
    $harnesses.Add($success)
    $successResult = Invoke-Harness -Harness $success
    if ($successResult.ExitCode -ne 0) { Write-Output ($successResult.StdOut + [Environment]::NewLine + $successResult.Report) }
    Assert-Equal 0 $successResult.ExitCode 'complete offline supervised orchestration should report PASS'
    Assert-True ($successResult.StdOut.Contains('Outcome=PASS')) 'offline coordinator should report its simulated completion'
    Assert-True (-not ($successResult.StdOut + $successResult.StdErr).Contains($syntheticToken)) 'the token must not appear in coordinator output'
    Assert-True (-not ($successResult.StdOut + $successResult.StdErr).Contains($syntheticIdentity)) 'server identity must not appear in coordinator output'
    $successPhases = @($successResult.Events | ForEach-Object name)
    Assert-Equal '--coordinator-identities|fixture|--setup-only|--start-session' (($successPhases | Select-Object -First 4) -join '|') 'identity, fixture, setup and session stages must be ordered'
    Assert-Equal '--drop-matching-request|runner' ((@($successPhases | Select-Object -Skip 4 -First 2) | Sort-Object) -join '|') 'one runner and one drop must start only after session activation'
    Assert-Equal '--stop-session-if-safe' $successPhases[-1] 'session cleanup must be the final orchestration operation'
    Assert-Equal 1 @($successPhases | Where-Object { $_ -eq '--start-session' }).Count 'the session should be requested exactly once'
    Assert-Equal 1 @($successPhases | Where-Object { $_ -eq '--drop-matching-request' }).Count 'the matching request should be dropped exactly once'
    $fixtureEvent = $successResult.Events | Where-Object name -eq 'fixture' | Select-Object -First 1
    Assert-True ($null -ne $fixtureEvent -and -not (Get-Process -Id $fixtureEvent.processId -ErrorAction SilentlyContinue)) 'coordinator should stop only the fixture process it started'

    $setupFailure = New-Harness -Scenario 'setup-failure' -FailurePhase '--setup-only'
    $harnesses.Add($setupFailure)
    $setupResult = Invoke-Harness -Harness $setupFailure
    Assert-Equal 1 $setupResult.ExitCode 'setup failure should be a hard failure before session creation'
    $setupPhases = @($setupResult.Events | ForEach-Object name)
    Assert-True ($setupPhases -notcontains '--start-session') 'setup failure must prevent session activation'
    Assert-True ($setupPhases -notcontains 'runner') 'setup failure must prevent test traffic'
    Assert-True ($setupPhases -notcontains '--drop-matching-request') 'setup failure must prevent drop orchestration'
    $setupFixture = $setupResult.Events | Where-Object name -eq 'fixture' | Select-Object -First 1
    Assert-True ($null -ne $setupFixture -and -not (Get-Process -Id $setupFixture.processId -ErrorAction SilentlyContinue)) 'setup failure should clean up its owned fixture'

    $inactive = New-Harness -Scenario 'inactive' -FailurePhase '--coordinator-identities'
    $harnesses.Add($inactive)
    $inactivePython = @'
import json, os, sys
with open(os.environ['COORDINATOR_EVENT_LOG'], 'a', encoding='utf-8') as stream: stream.write(json.dumps({'name':sys.argv[1]})+'\n')
sys.stderr.write('PREFLIGHT FAIL: Unattended local test mode is not active; no session was requested.\n')
sys.exit(2)
'@
    [System.IO.File]::WriteAllText((Join-Path $inactive.Scripts 'cancel_test_preflight.py'), $inactivePython, [System.Text.UTF8Encoding]::new($false))
    $inactiveResult = Invoke-Harness -Harness $inactive
    Assert-Equal 3 $inactiveResult.ExitCode 'missing human activation should be BLOCKED rather than bypassed'
    Assert-True ($inactiveResult.StdOut.Contains('Outcome=BLOCKED')) 'inactive authorization should be reported as BLOCKED'
    Assert-Equal 1 $inactiveResult.Events.Count 'inactive authorization must stop before fixture, session, or runner work'

    $unverified = New-Harness -Scenario 'offline-unverified' -Mode 'OFFLINE' `
        -ResultCounts '{"PASS":3,"FAIL":0,"BLOCKED":0,"INCONCLUSIVE":0,"UNVERIFIED":1,"UNSUPPORTED":0}'
    $harnesses.Add($unverified)
    $unverifiedResult = Invoke-Harness -Harness $unverified
    Assert-Equal 2 $unverifiedResult.ExitCode 'unverified checks must prevent an aggregate PASS'
    Assert-True ($unverifiedResult.StdOut.Contains('Outcome=INCONCLUSIVE')) 'unverified child results should stay INCONCLUSIVE'

    $blocked = New-Harness -Scenario 'offline-blocked' -Mode 'OFFLINE' `
        -ResultCounts '{"PASS":3,"FAIL":0,"BLOCKED":1,"INCONCLUSIVE":0,"UNVERIFIED":0,"UNSUPPORTED":0}'
    $harnesses.Add($blocked)
    $blockedResult = Invoke-Harness -Harness $blocked
    Assert-Equal 3 $blockedResult.ExitCode 'blocked checks must not become an aggregate PASS'
    Assert-True ($blockedResult.StdOut.Contains('Outcome=BLOCKED')) 'blocked child results should stay BLOCKED'

    Write-Output ("PASS: {0} offline coordinator assertions; actual PowerShell coordinator process, identity capture, fixture lifecycle, setup gate, session ordering, one-shot runner/drop, stale/queue result handling, blocked activation path, and aggregate status mapping were exercised with fake MCP tools; no Burp or HTTP test request was sent." -f $assertions)
} finally {
    foreach ($harness in $harnesses) {
        $events = @(Read-Events -Path $harness.EventLog)
        foreach ($event in $events | Where-Object { $_.name -eq 'fixture' -and $_.processId -gt 0 }) {
            $process = Get-Process -Id $event.processId -ErrorAction SilentlyContinue
            if ($null -ne $process) { Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue }
        }
        if (Test-Path -LiteralPath $harness.Root -PathType Container) {
            Remove-Item -LiteralPath $harness.Root -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
