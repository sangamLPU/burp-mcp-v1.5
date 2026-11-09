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
    if ($Expected -cne $Actual) { throw "ASSERTION FAILED: $Message" }
    $script:assertions++
}
function Assert-NotContains {
    param([string]$Text, [string]$Value, [string]$Message)
    if ($Text.Contains($Value)) { throw "ASSERTION FAILED: $Message" }
    $script:assertions++
}
function New-FakeInvoker {
    param([object[]]$Responses)
    $queue = [System.Collections.Queue]::new()
    foreach ($response in $Responses) { $null = $queue.Enqueue($response) }
    $observedTokens = [System.Collections.Generic.List[string]]::new()
    $invoker = {
        param([string]$PythonPath, [string[]]$Arguments)
        $null = $observedTokens.Add([Environment]::GetEnvironmentVariable('BURP_MCP_TOKEN', 'Process'))
        if ($queue.Count -eq 0) { throw 'Fake preflight process was called more times than expected.' }
        return $queue.Dequeue()
    }.GetNewClosure()
    [pscustomobject]@{ Invoker = $invoker; ObservedTokens = $observedTokens; Remaining = $queue }
}
function New-FakeSecurePrompt {
    param([string]$Value)
    $messages = [System.Collections.Generic.List[string]]::new()
    $prompt = {
        param([string]$Message)
        $null = $messages.Add($Message)
        return ConvertTo-SecureString -String $Value -AsPlainText -Force
    }.GetNewClosure()
    [pscustomobject]@{ Prompt = $prompt; Messages = $messages }
}
function New-ProcessResult {
    param([int]$ExitCode, [string]$StdOut = '', [string]$StdErr = '')
    [pscustomobject]@{ ExitCode = $ExitCode; StdOut = $StdOut; StdErr = $StdErr }
}

$previousToken = [Environment]::GetEnvironmentVariable('BURP_MCP_TOKEN', 'Process')
$previousArgumentCapture = [Environment]::GetEnvironmentVariable('PHASE4A_ARGUMENT_CAPTURE', 'Process')
$originalErrorActionPreference = $ErrorActionPreference
$temporaryDirectory = Join-Path $env:TEMP ("phase4a-preflight-process-{0}" -f [Guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $temporaryDirectory -Force
$temporaryChildScript = Join-Path $env:TEMP ("phase4a-native-exit-{0}.ps1" -f [Guid]::NewGuid().ToString('N'))
$argumentCapturePath = Join-Path $temporaryDirectory 'arguments.json'
$argumentCaptureScript = Join-Path $temporaryDirectory 'capture_arguments.py'
$stderrChildScript = Join-Path $temporaryDirectory 'stderr_exit.py'
try {
    $freshToken = 'B' * 43
    [Environment]::SetEnvironmentVariable('BURP_MCP_TOKEN', $null, 'Process')
    $missingInvoker = New-FakeInvoker -Responses @((New-ProcessResult -ExitCode 0))
    $missingPrompt = New-FakeSecurePrompt -Value $freshToken
    Assert-True (Invoke-CancelTestAuthentication -PythonPath 'python.exe' -PreflightScript 'preflight.py' -PromptForMcpToken -ProcessInvoker $missingInvoker.Invoker -SecurePrompt $missingPrompt.Prompt) 'missing-token recovery should authenticate'
    Assert-Equal 1 $missingPrompt.Messages.Count 'missing token should request one secure input'
    Assert-Equal $freshToken $missingInvoker.ObservedTokens[0] 'fresh token should be process-local input to Python'
    Assert-NotContains ($missingPrompt.Messages -join '') $freshToken 'the secure prompt message must not include a token'

    $staleToken = 'A' * 43
    [Environment]::SetEnvironmentVariable('BURP_MCP_TOKEN', $staleToken, 'Process')
    $rejectedInvoker = New-FakeInvoker -Responses @(
        (New-ProcessResult -ExitCode 2 -StdErr 'PREFLIGHT FAIL: MCP authentication rejected BURP_MCP_TOKEN (HTTP 401)'),
        (New-ProcessResult -ExitCode 0)
    )
    $rejectedPrompt = New-FakeSecurePrompt -Value $freshToken
    Assert-True (Invoke-CancelTestAuthentication -PythonPath 'python.exe' -PreflightScript 'preflight.py' -PromptForMcpToken -ProcessInvoker $rejectedInvoker.Invoker -SecurePrompt $rejectedPrompt.Prompt) 'a rejected environment token should recover once'
    Assert-Equal 2 $rejectedInvoker.ObservedTokens.Count 'rejected token flow should call auth twice'
    Assert-Equal $staleToken $rejectedInvoker.ObservedTokens[0] 'first auth must test the existing token'
    Assert-Equal $freshToken $rejectedInvoker.ObservedTokens[1] 'second auth must use the secure fresh token'
    Assert-Equal 1 $rejectedPrompt.Messages.Count 'rejected token should cause one secure prompt'

    [Environment]::SetEnvironmentVariable('BURP_MCP_TOKEN', $staleToken, 'Process')
    $preflightRejectedInvoker = New-FakeInvoker -Responses @(
        (New-ProcessResult -ExitCode 2 -StdErr 'PREFLIGHT FAIL: MCP authentication rejected BURP_MCP_TOKEN (HTTP 401)'),
        (New-ProcessResult -ExitCode 0 -StdOut 'SETUP PREFLIGHT PASS')
    )
    $preflightRejectedPrompt = New-FakeSecurePrompt -Value $freshToken
    Invoke-CancelTestPreflightProcess -PythonPath 'python.exe' -PreflightScript 'preflight.py' -PreflightArguments @() -PromptForMcpToken -ProcessInvoker $preflightRejectedInvoker.Invoker -SecurePrompt $preflightRejectedPrompt.Prompt
    Assert-Equal 2 $preflightRejectedInvoker.ObservedTokens.Count 'a rejected token during setup preflight should retry exactly once'
    Assert-Equal $staleToken $preflightRejectedInvoker.ObservedTokens[0] 'setup preflight should first test the existing environment token'
    Assert-Equal $freshToken $preflightRejectedInvoker.ObservedTokens[1] 'setup preflight retry should use the secure replacement token'
    Assert-Equal 1 $preflightRejectedPrompt.Messages.Count 'setup preflight 401 recovery should prompt once'

    [Environment]::SetEnvironmentVariable('BURP_MCP_TOKEN', $null, 'Process')
    $invalidPrompt = New-FakeSecurePrompt -Value 'too-short'
    $invalidInvoker = New-FakeInvoker -Responses @()
    $invalidPromptError = $null
    try {
        $null = Invoke-CancelTestAuthentication -PythonPath 'python.exe' -PreflightScript 'preflight.py' -PromptForMcpToken -ProcessInvoker $invalidInvoker.Invoker -SecurePrompt $invalidPrompt.Prompt
    } catch { $invalidPromptError = $_.Exception.Message }
    Assert-True ($invalidPromptError -match 'expected bare 43-character') 'malformed fresh token should produce a clear format error'
    Assert-Equal 0 $invalidInvoker.ObservedTokens.Count 'malformed fresh token must be rejected before Python starts'

    [Environment]::SetEnvironmentVariable('BURP_MCP_TOKEN', $staleToken, 'Process')
    $failedRetryInvoker = New-FakeInvoker -Responses @(
        (New-ProcessResult -ExitCode 2 -StdErr 'PREFLIGHT FAIL: MCP authentication rejected BURP_MCP_TOKEN (HTTP 401)'),
        (New-ProcessResult -ExitCode 2 -StdErr 'PREFLIGHT FAIL: MCP authentication rejected BURP_MCP_TOKEN (HTTP 401)')
    )
    $failedRetryPrompt = New-FakeSecurePrompt -Value $freshToken
    $failedRetryError = $null
    try {
        $null = Invoke-CancelTestAuthentication -PythonPath 'python.exe' -PreflightScript 'preflight.py' -PromptForMcpToken -ProcessInvoker $failedRetryInvoker.Invoker -SecurePrompt $failedRetryPrompt.Prompt
    } catch { $failedRetryError = $_.Exception.Message }
    Assert-True ($failedRetryError -match 'HTTP 401') 'a rejected fresh token should produce a clear HTTP 401 error'
    Assert-NotContains $failedRetryError $staleToken 'stale token must not appear in error text'
    Assert-NotContains $failedRetryError $freshToken 'fresh token must not appear in error text'
    Assert-Equal 2 $failedRetryInvoker.ObservedTokens.Count 'authentication must not automatically retry a second time'
    Assert-Equal 1 $failedRetryPrompt.Messages.Count 'failed refresh must not prompt repeatedly'

    [Environment]::SetEnvironmentVariable('BURP_MCP_TOKEN', $staleToken, 'Process')
    $unrelatedInvoker = New-FakeInvoker -Responses @((New-ProcessResult -ExitCode 7 -StdErr 'MCP listener unavailable'))
    $unrelatedPrompt = New-FakeSecurePrompt -Value $freshToken
    $unrelatedError = $null
    try {
        $null = Invoke-CancelTestAuthentication -PythonPath 'python.exe' -PreflightScript 'preflight.py' -PromptForMcpToken -ProcessInvoker $unrelatedInvoker.Invoker -SecurePrompt $unrelatedPrompt.Prompt
    } catch { $unrelatedError = $_.Exception.Message }
    Assert-True ($unrelatedError -match 'Python exit code 7') 'non-authentication process failures should be reported clearly'
    Assert-Equal 0 $unrelatedPrompt.Messages.Count 'listener failures must not prompt for a different token'

    [System.IO.File]::WriteAllText($temporaryChildScript, "[Console]::Out.WriteLine('synthetic stdout')`r`n[Console]::Error.WriteLine('synthetic stderr')`r`nexit 7`r`n")
    $nativeResult = Invoke-CancelTestNativeProcess -ExecutablePath (Join-Path $PSHOME 'powershell.exe') -Arguments @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $temporaryChildScript)
    Assert-Equal 7 $nativeResult.ExitCode 'nonzero child exit code should be captured'
    Assert-True ($nativeResult.StdOut.Contains('synthetic stdout')) 'child stdout should be captured'
    Assert-True ($nativeResult.StdErr.Contains('synthetic stderr')) 'child stderr should be captured without NativeCommandError'
    Assert-Equal 'Stop' $ErrorActionPreference 'native process handling must preserve ErrorActionPreference'
    Assert-Equal $originalErrorActionPreference $ErrorActionPreference 'test should not change PowerShell error policy'

    $pythonPath = (Get-Command 'python.exe' -ErrorAction Stop).Source
    $pythonEncoding = [System.Text.UTF8Encoding]::new($false)
    $argumentCaptureSource = @'
import json, os, sys
with open(os.environ['PHASE4A_ARGUMENT_CAPTURE'], 'w', encoding='utf-8') as f:
    json.dump(sys.argv[1:], f)
'@
    [System.IO.File]::WriteAllText($argumentCaptureScript, $argumentCaptureSource, $pythonEncoding)
    [Environment]::SetEnvironmentVariable('PHASE4A_ARGUMENT_CAPTURE', $argumentCapturePath, 'Process')

    Invoke-CancelTestPreflightProcess -PythonPath $pythonPath -PreflightScript $argumentCaptureScript -PreflightArguments @()
    $emptyArgumentsJson = (Get-Content -LiteralPath $argumentCapturePath -Raw).Trim()
    Assert-Equal '[]' $emptyArgumentsJson 'empty PreflightArguments must pass only the script to Python'

    Invoke-CancelTestPreflightProcess -PythonPath $pythonPath -PreflightScript $argumentCaptureScript -PreflightArguments @('--setup-only')
    $oneArgument = [string[]](ConvertFrom-Json -InputObject (Get-Content -LiteralPath $argumentCapturePath -Raw))
    Assert-Equal 1 $oneArgument.Count 'one PreflightArgument should arrive as one Python argument'
    Assert-Equal '--setup-only' $oneArgument[0] 'the single preflight argument should be preserved'

    Invoke-CancelTestPreflightProcess -PythonPath $pythonPath -PreflightScript $argumentCaptureScript -PreflightArguments @('--name', 'phase 4a simulation', '--limit', '3')
    $multipleArguments = [string[]](ConvertFrom-Json -InputObject (Get-Content -LiteralPath $argumentCapturePath -Raw))
    Assert-Equal 4 $multipleArguments.Count ("multiple PreflightArguments should arrive without being merged; received {0}: [{1}]" -f $multipleArguments.Count, ($multipleArguments -join '|'))
    Assert-Equal 'phase 4a simulation' $multipleArguments[1] 'arguments containing spaces should preserve their value'
    Assert-Equal '3' $multipleArguments[3] 'the final preflight argument should be preserved'

    $identityJson = '{"testRunId":"11111111-2222-3333-4444-555555555555","serverIdentity":"' + ('S' * 43) + '"}'
    $captureResult = New-ProcessResult -ExitCode 0 -StdOut $identityJson
    $captureInvoker = New-FakeInvoker -Responses @($captureResult)
    $capturedIdentityResult = Invoke-CancelTestPreflightProcess -PythonPath 'python.exe' -PreflightScript 'preflight.py' `
        -PreflightArguments @('--coordinator-identities', '180') -ReturnResult -ProcessInvoker $captureInvoker.Invoker
    Assert-Equal $identityJson $capturedIdentityResult.StdOut 'coordinator identity output should be returned to the parent process for in-memory handling'
    Assert-Equal 0 $capturedIdentityResult.ExitCode 'coordinator capture should preserve the native child exit code'

    $stderrChildSource = @'
import sys
sys.stderr.write('synthetic python stderr\n')
sys.exit(7)
'@
    [System.IO.File]::WriteAllText($stderrChildScript, $stderrChildSource, $pythonEncoding)
    $pythonStderrError = $null
    try {
        Invoke-CancelTestPreflightProcess -PythonPath $pythonPath -PreflightScript $stderrChildScript -PreflightArguments @()
    } catch { $pythonStderrError = $_.Exception.Message }
    Assert-True ($pythonStderrError -match 'exit code 7') 'Python stderr with a nonzero exit should preserve the child exit code'
    Assert-True ($pythonStderrError.Contains('synthetic python stderr')) 'Python stderr should be included in the safe preflight error'
    Assert-NotContains $pythonStderrError $freshToken 'Python stderr errors must not reveal the fresh token'

    Write-Output ("PASS: {0} runner authentication/process assertions; child processes were offline and no test traffic was sent." -f $assertions)
} finally {
    [Environment]::SetEnvironmentVariable('BURP_MCP_TOKEN', $previousToken, 'Process')
    [Environment]::SetEnvironmentVariable('PHASE4A_ARGUMENT_CAPTURE', $previousArgumentCapture, 'Process')
    if (Test-Path -LiteralPath $temporaryChildScript -PathType Leaf) {
        Remove-Item -LiteralPath $temporaryChildScript -Force
    }
    if (Test-Path -LiteralPath $temporaryDirectory -PathType Container) {
        Remove-Item -LiteralPath $temporaryDirectory -Recurse -Force
    }
}
