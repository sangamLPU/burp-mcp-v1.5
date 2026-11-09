$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
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
function Read-WorkflowEvents {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return @() }
    return @(Get-Content -LiteralPath $Path | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_ | ConvertFrom-Json })
}
function Wait-ForWorkflowPhase {
    param($Context, [string]$Phase, [int]$TimeoutSeconds = 30)
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $events = @(Read-WorkflowEvents -Path $Context.EventLog)
        if (@($events | Where-Object phase -eq $Phase).Count -gt 0) { return }
        if ($Context.Process.HasExited) {
            throw "Runner exited before the '$Phase' preflight phase; exit code $($Context.Process.ExitCode)."
        }
        Start-Sleep -Milliseconds 50
    }
    throw "Timed out waiting for the '$Phase' preflight phase."
}
function Close-OfflineConnectionIfPresent {
    param($Context)
    if (-not $Context.NetworkObserved -and $Context.AcceptTask.IsCompleted) {
        $Context.NetworkObserved = $true
        try {
            $client = $Context.AcceptTask.GetAwaiter().GetResult()
            $client.Close()
        } catch { }
    }
}
function Wait-ForRunnerExit {
    param($Context, [int]$TimeoutSeconds = 30)
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while (-not $Context.Process.HasExited -and [DateTime]::UtcNow -lt $deadline) {
        Close-OfflineConnectionIfPresent -Context $Context
        Start-Sleep -Milliseconds 50
        $Context.Process.Refresh()
    }
    Close-OfflineConnectionIfPresent -Context $Context
    if (-not $Context.Process.HasExited) {
        try { $Context.Process.Kill() } catch { }
        throw 'Offline runner simulation timed out.'
    }
    [pscustomobject]@{
        ExitCode = $Context.Process.ExitCode
        StdOut = $Context.StdOutTask.GetAwaiter().GetResult()
        StdErr = $Context.StdErrTask.GetAwaiter().GetResult()
        NetworkObserved = $Context.NetworkObserved
    }
}

$tempRoot = Join-Path $env:TEMP ("phase4a-workflow-offline-{0}" -f [Guid]::NewGuid().ToString('N'))
$tempScripts = Join-Path $tempRoot 'scripts'
$null = New-Item -ItemType Directory -Path $tempScripts -Force
$processTokenBefore = [Environment]::GetEnvironmentVariable('BURP_MCP_TOKEN', 'Process')
$processWorkflowLogBefore = [Environment]::GetEnvironmentVariable('PHASE4A_WORKFLOW_LOG', 'Process')
$runId = [Guid]::NewGuid().ToString('D').ToLowerInvariant()
$serverIdentity = 'Q' * 43
$syntheticToken = 'R' * 43
$fixtureStub = Join-Path $tempScripts 'prepare-cancel-test-server.ps1'
$fakePreflight = Join-Path $tempScripts 'cancel_test_preflight.py'
$runnerCopy = Join-Path $tempScripts 'run-cancel-test.ps1'
$authCopy = Join-Path $tempScripts 'cancel-test-auth.ps1'
$validationCopy = Join-Path $tempScripts 'cancel-test-validation.ps1'
$sourceEncoding = [System.Text.UTF8Encoding]::new($false)
$originalRunner = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'run-cancel-test.ps1') -Raw
$copyWorkflowSource = Get-Content -LiteralPath (Join-Path $repoRoot 'src\main\kotlin\net\portswigger\mcp\intercept\LocalTestPowerShellCommands.kt') -Raw
$fixtureScriptSource = @'
param([string]$TestRunId, [string]$ServerIdentity)
if ($TestRunId -notmatch '^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$') { throw 'Synthetic fixture run identity is malformed.' }
if ($ServerIdentity -notmatch '^[A-Za-z0-9_-]{43}$') { throw 'Synthetic fixture server identity is malformed.' }
$event = [pscustomobject]@{ phase = 'fixture'; state = 'READY'; identityMatch = $true } | ConvertTo-Json -Compress
[System.IO.File]::AppendAllText($env:PHASE4A_WORKFLOW_LOG, $event + [Environment]::NewLine)
Write-Output 'FIXTURE READY: synthetic run and server identities match.'
'@
$fakePythonSource = @'
import json, os, sys
args = sys.argv[1:]
if args == ['--auth-only']:
    phase = 'auth'
elif args == ['--setup-only']:
    phase = 'setup'
elif args == []:
    phase = 'full'
else:
    phase = 'unexpected'
with open(os.environ['PHASE4A_WORKFLOW_LOG'], 'a', encoding='utf-8') as stream:
    stream.write(json.dumps({'phase': phase, 'args': args}) + '\n')
if os.environ.get('PHASE4A_FAIL_PHASE') == phase:
    sys.stderr.write('controlled ' + phase + ' preflight failure\n')
    sys.exit(23)
print(('SETUP PREFLIGHT PASS' if phase == 'setup' else 'PREFLIGHT PASS') + ': controlled preflight passed')
'@

function New-OfflineListener {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    [pscustomobject]@{
        Listener = $listener
        Port = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
        AcceptTask = $listener.AcceptTcpClientAsync()
    }
}

function Start-OfflineRunner {
    param([string]$EventLog, [string]$FailurePhase, [int]$ProxyPort, $AcceptTask)
    $runnerText = $originalRunner.Replace('$proxyPort = 8080', ('$proxyPort = {0}' -f $ProxyPort))
    if ($runnerText -eq $originalRunner) { throw 'Offline runner copy did not receive the controlled loopback port.' }
    [System.IO.File]::WriteAllText($runnerCopy, $runnerText, $sourceEncoding)

    $powershellPath = (Get-Process -Id $PID).Path
    $argumentList = @(
        '-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $runnerCopy,
        '-PromptForMcpToken', '-WaitForLiveSession', '-OfflineSimulationNoTraffic',
        '-TestRunId', $runId, '-ServerIdentity', $serverIdentity
    )
    $quotedArguments = @($argumentList | ForEach-Object { ConvertTo-CancelTestProcessArgument -Value $_ }) -join ' '
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $powershellPath
    $startInfo.Arguments = $quotedArguments
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.EnvironmentVariables['BURP_MCP_TOKEN'] = $syntheticToken
    $startInfo.EnvironmentVariables['PHASE4A_WORKFLOW_LOG'] = $EventLog
    $startInfo.EnvironmentVariables['PHASE4A_FAIL_PHASE'] = $FailurePhase

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    if (-not $process.Start()) { throw 'Offline PowerShell runner child did not start.' }
    [pscustomobject]@{
        Process = $process
        StdOutTask = $process.StandardOutput.ReadToEndAsync()
        StdErrTask = $process.StandardError.ReadToEndAsync()
        EventLog = $EventLog
        AcceptTask = $AcceptTask
        NetworkObserved = $false
    }
}

$eventLog = $null
$contexts = [System.Collections.Generic.List[object]]::new()
$listeners = [System.Collections.Generic.List[object]]::new()
try {
    $prepareIndex = $copyWorkflowSource.IndexOf('prepare-cancel-test-server.ps1', [StringComparison]::Ordinal)
    $runnerIndex = $copyWorkflowSource.IndexOf('run-cancel-test.ps1 -PromptForMcpToken -WaitForLiveSession', [StringComparison]::Ordinal)
    Assert-True ($prepareIndex -ge 0 -and $runnerIndex -gt $prepareIndex) 'Copy Test Commands must prepare the identity-bound fixture before invoking the runner'
    Assert-True ($copyWorkflowSource.Contains('Read-Host -Prompt ''Paste the active Burp Run ID (hidden)'' -AsSecureString')) 'copied workflow must collect the run ID through a secure prompt'
    Assert-True ($copyWorkflowSource.Contains('Read-Host -Prompt ''Paste the active Burp Server Identity (hidden)'' -AsSecureString')) 'copied workflow must collect the server identity through a secure prompt'
    Assert-True ($originalRunner -match "PreflightArguments @\('--setup-only'\)") 'copied workflow must run setup preflight before requesting a fresh live session'

    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'cancel-test-auth.ps1') -Destination $authCopy
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'cancel-test-validation.ps1') -Destination $validationCopy
    [System.IO.File]::WriteAllText($fixtureStub, $fixtureScriptSource, $sourceEncoding)
    [System.IO.File]::WriteAllText($fakePreflight, $fakePythonSource, $sourceEncoding)
    $null = Get-Command 'python.exe' -ErrorAction Stop

    $eventLog = Join-Path $tempRoot 'success-events.jsonl'
    [Environment]::SetEnvironmentVariable('PHASE4A_WORKFLOW_LOG', $eventLog, 'Process')
    & $fixtureStub -TestRunId $runId -ServerIdentity $serverIdentity | Out-Null
    $listener = New-OfflineListener
    $listeners.Add($listener)
    $successContext = Start-OfflineRunner -EventLog $eventLog -FailurePhase '' -ProxyPort $listener.Port -AcceptTask $listener.AcceptTask
    $contexts.Add($successContext)
    Wait-ForWorkflowPhase -Context $successContext -Phase 'setup'
    Start-Sleep -Milliseconds 400
    $phasesWhilePaused = @((Read-WorkflowEvents -Path $eventLog) | ForEach-Object { $_.phase })
    Assert-Equal 2 $phasesWhilePaused.Count 'setup preflight must finish before the runner waits for a fresh live session'
    Assert-Equal 'setup' $phasesWhilePaused[1] 'the second workflow event must be authenticated setup preflight'
    Assert-True (-not $successContext.Process.HasExited) 'runner must remain paused after setup readiness until resumed'
    $successContext.Process.StandardInput.WriteLine('')
    $successContext.Process.StandardInput.Flush()
    $successContext.Process.StandardInput.Close()
    $successResult = Wait-ForRunnerExit -Context $successContext
    Assert-Equal 0 $successResult.ExitCode 'successful copied-workflow simulation should complete'
    Assert-True ($successResult.StdOut.Contains('OFFLINE SIMULATION PASS')) 'runner should complete the single final preflight and stop before test traffic'
    $successEvents = @(Read-WorkflowEvents -Path $eventLog)
    Assert-Equal 'fixture' $successEvents[0].phase 'identity-bound fixture preparation should precede the runner'
    Assert-Equal 'READY' $successEvents[0].state 'offline fixture preparation should report READY'
    Assert-True ($successEvents[0].identityMatch -eq $true) 'offline fixture preparation should confirm matching identities'
    Assert-Equal 'setup' $successEvents[1].phase 'authenticated setup preflight should run before the session pause'
    Assert-Equal 'full' $successEvents[2].phase 'one full preflight should run after the user resumes'
    Assert-Equal 0 @($successEvents[2].args).Count 'the final preflight must pass no extra Python arguments'
    Assert-True (-not $successResult.NetworkObserved) 'successful offline simulation must not connect to even the controlled transport'
    $listener.Listener.Stop()

    $eventLog = Join-Path $tempRoot 'setup-failure-events.jsonl'
    [Environment]::SetEnvironmentVariable('PHASE4A_WORKFLOW_LOG', $eventLog, 'Process')
    & $fixtureStub -TestRunId $runId -ServerIdentity $serverIdentity | Out-Null
    $listener = New-OfflineListener
    $listeners.Add($listener)
    $setupFailureContext = Start-OfflineRunner -EventLog $eventLog -FailurePhase 'setup' -ProxyPort $listener.Port -AcceptTask $listener.AcceptTask
    $contexts.Add($setupFailureContext)
    $setupFailureResult = Wait-ForRunnerExit -Context $setupFailureContext
    Assert-True ($setupFailureResult.ExitCode -ne 0) 'setup preflight failure must stop before the live session pause'
    Assert-True (($setupFailureResult.StdOut + $setupFailureResult.StdErr).Contains('controlled setup preflight failure')) 'setup failure must remain clear and non-secret'
    Assert-True (-not $setupFailureResult.StdOut.Contains('After the approved 300-second session is active')) 'failed setup must not request a live session'
    Assert-True (-not $setupFailureResult.NetworkObserved) 'failed setup must not connect to the controlled proxy transport'
    $setupEvents = @(Read-WorkflowEvents -Path $eventLog)
    Assert-Equal 2 $setupEvents.Count 'setup failure simulation must contain only fixture and setup events'
    $listener.Listener.Stop()

    $eventLog = Join-Path $tempRoot 'full-failure-events.jsonl'
    [Environment]::SetEnvironmentVariable('PHASE4A_WORKFLOW_LOG', $eventLog, 'Process')
    & $fixtureStub -TestRunId $runId -ServerIdentity $serverIdentity | Out-Null
    $listener = New-OfflineListener
    $listeners.Add($listener)
    $fullFailureContext = Start-OfflineRunner -EventLog $eventLog -FailurePhase 'full' -ProxyPort $listener.Port -AcceptTask $listener.AcceptTask
    $contexts.Add($fullFailureContext)
    Start-Sleep -Milliseconds 400
    Assert-True (-not $fullFailureContext.Process.HasExited) 'runner should remain paused before the final preflight failure is triggered'
    $fullFailureContext.Process.StandardInput.WriteLine('')
    $fullFailureContext.Process.StandardInput.Flush()
    $fullFailureContext.Process.StandardInput.Close()
    $fullFailureResult = Wait-ForRunnerExit -Context $fullFailureContext
    Assert-True ($fullFailureResult.ExitCode -ne 0) 'final preflight failure should terminate the runner'
    Assert-True (($fullFailureResult.StdOut + $fullFailureResult.StdErr).Contains('controlled full preflight failure')) 'final preflight failure should surface the child stderr safely'
    Assert-True (-not $fullFailureResult.StdOut.Contains('OFFLINE SIMULATION PASS')) 'failed full preflight must not report the workflow ready'
    Assert-True (-not $fullFailureResult.NetworkObserved) 'final preflight failure must not connect to the controlled transport'
    $listener.Listener.Stop()

    Write-Output ("PASS: {0} offline copied-workflow assertions; fixture, pre-session auth/scope setup preflight, pause/resume, final preflight, failure gates, and one-request boundary verified with controlled child processes; no Burp or origin traffic." -f $assertions)
} finally {
    foreach ($context in $contexts) {
        if ($null -ne $context.Process) {
            if (-not $context.Process.HasExited) {
                try { $context.Process.Kill() } catch { }
            }
            $context.Process.Dispose()
        }
    }
    foreach ($item in $listeners) {
        if ($null -ne $item -and $null -ne $item.Listener) {
            try { $item.Listener.Stop() } catch { }
        }
    }
    if (Test-Path -LiteralPath $tempRoot -PathType Container) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force
    }
    [Environment]::SetEnvironmentVariable('BURP_MCP_TOKEN', $processTokenBefore, 'Process')
    [Environment]::SetEnvironmentVariable('PHASE4A_WORKFLOW_LOG', $processWorkflowLogBefore, 'Process')
}
