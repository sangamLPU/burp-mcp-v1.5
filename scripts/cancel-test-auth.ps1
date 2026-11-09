function ConvertTo-CancelTestProcessArgument {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] [AllowEmptyString()] [string]$Value)

    if ($Value.Length -eq 0) { return '""' }
    if ($Value -notmatch '[\s"]') { return $Value }

    $builder = [System.Text.StringBuilder]::new()
    [void]$builder.Append([char]'"')
    $backslashCount = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq [char]'\') {
            $backslashCount++
            continue
        }
        if ($character -eq [char]'"') {
            if ($backslashCount -gt 0) { [void]$builder.Append([char]'\', $backslashCount * 2) }
            [void]$builder.Append([char]'\')
            [void]$builder.Append([char]'"')
            $backslashCount = 0
            continue
        }
        if ($backslashCount -gt 0) { [void]$builder.Append([char]'\', $backslashCount) }
        [void]$builder.Append($character)
        $backslashCount = 0
    }
    if ($backslashCount -gt 0) { [void]$builder.Append([char]'\', $backslashCount * 2) }
    [void]$builder.Append([char]'"')
    return $builder.ToString()
}

function Invoke-CancelTestNativeProcess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string]$ExecutablePath,
        [Parameter(Mandatory = $true)] [AllowEmptyCollection()] [string[]]$Arguments
    )

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $ExecutablePath
    $startInfo.Arguments = (@($Arguments | ForEach-Object { ConvertTo-CancelTestProcessArgument -Value $_ }) -join ' ')
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true

    $process = [System.Diagnostics.Process]::new()
    try {
        $process.StartInfo = $startInfo
        if (-not $process.Start()) {
            return [pscustomobject]@{ ExitCode = 127; StdOut = ''; StdErr = 'Python preflight process did not start.' }
        }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        return [pscustomobject]@{
            ExitCode = $process.ExitCode
            StdOut = $stdoutTask.GetAwaiter().GetResult()
            StdErr = $stderrTask.GetAwaiter().GetResult()
        }
    } catch {
        return [pscustomobject]@{ ExitCode = 127; StdOut = ''; StdErr = 'Could not start or read the Python preflight process.' }
    } finally {
        $process.Dispose()
    }
}

function Get-CancelTestAuthFailureKind {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] [string]$Text)

    if ($Text -match '(?i)HTTP\s*401|authentication rejected|token was rejected') { return 'Rejected' }
    if ($Text -match '(?i)BURP_MCP_TOKEN is missing|BURP_MCP_TOKEN is empty|bare 43-character token|expected bare 43-character') { return 'Invalid' }
    return 'Other'
}

function Set-CancelTestTokenFromSecurePrompt {
    [CmdletBinding()]
    param(
        [scriptblock]$SecurePrompt,
        [Parameter(Mandatory = $true)] [string]$Prompt
    )

    $secureValue = $null
    $buffer = [IntPtr]::Zero
    $candidate = $null
    try {
        if ($null -ne $SecurePrompt) {
            $secureValue = & $SecurePrompt $Prompt
        } else {
            $secureValue = Read-Host -Prompt $Prompt -AsSecureString
        }
        if ($secureValue -isnot [System.Security.SecureString]) {
            throw 'The secure MCP token prompt did not return a secure value.'
        }
        $buffer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureValue)
        $candidate = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($buffer)
        if ($candidate -notmatch '^[A-Za-z0-9_-]{43}$') {
            throw 'The entered value is not the expected bare 43-character Burp MCP token. No test request was sent.'
        }
        [Environment]::SetEnvironmentVariable('BURP_MCP_TOKEN', $candidate, 'Process')
    } finally {
        $candidate = $null
        if ($buffer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($buffer) }
        if ($null -ne $secureValue) { $secureValue.Dispose() }
    }
}

function Invoke-CancelTestAuthentication {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string]$PythonPath,
        [Parameter(Mandatory = $true)] [string]$PreflightScript,
        [switch]$PromptForMcpToken,
        [scriptblock]$ProcessInvoker,
        [scriptblock]$SecurePrompt
    )

    $prompted = $false
    $token = [Environment]::GetEnvironmentVariable('BURP_MCP_TOKEN', 'Process')
    if ([string]::IsNullOrWhiteSpace($token) -or $token -notmatch '^[A-Za-z0-9_-]{43}$') {
        if (-not $PromptForMcpToken) {
            if ([string]::IsNullOrWhiteSpace($token)) {
                throw 'BURP_MCP_TOKEN is missing. Rerun with -PromptForMcpToken; no test request was sent.'
            }
            throw 'BURP_MCP_TOKEN is not a bare 43-character token. Rerun with -PromptForMcpToken; no test request was sent.'
        }
        Set-CancelTestTokenFromSecurePrompt -SecurePrompt $SecurePrompt -Prompt 'Enter the current bare Burp MCP token (input hidden)'
        $prompted = $true
    }

    $arguments = @($PreflightScript, '--auth-only')
    if ($null -ne $ProcessInvoker) {
        $result = & $ProcessInvoker $PythonPath $arguments
    } else {
        $result = Invoke-CancelTestNativeProcess -ExecutablePath $PythonPath -Arguments $arguments
    }
    if ($result.ExitCode -eq 0) {
        return $true
    }

    $failureText = [string]$result.StdOut + [Environment]::NewLine + [string]$result.StdErr
    $failureKind = Get-CancelTestAuthFailureKind -Text $failureText
    if ($PromptForMcpToken -and -not $prompted -and $failureKind -in @('Rejected', 'Invalid')) {
        Set-CancelTestTokenFromSecurePrompt -SecurePrompt $SecurePrompt -Prompt 'The existing token was rejected. Enter a fresh bare Burp MCP token (input hidden)'
        if ($null -ne $ProcessInvoker) {
            $result = & $ProcessInvoker $PythonPath $arguments
        } else {
            $result = Invoke-CancelTestNativeProcess -ExecutablePath $PythonPath -Arguments $arguments
        }
        if ($result.ExitCode -eq 0) { return $true }
        $failureText = [string]$result.StdOut + [Environment]::NewLine + [string]$result.StdErr
        $failureKind = Get-CancelTestAuthFailureKind -Text $failureText
    }

    if ($failureKind -eq 'Rejected') {
        throw 'Burp MCP rejected the supplied token (HTTP 401). Refresh the bare token in Burp Security and rerun; no test request was sent.'
    }
    if ($failureKind -eq 'Invalid') {
        throw 'The supplied Burp MCP token is missing or malformed. Refresh the bare token in Burp Security and rerun; no test request was sent.'
    }
    throw "Authenticated MCP preflight failed (Python exit code $($result.ExitCode)). No test request was sent. Check the local MCP listener and Python installation."
}

function Invoke-CancelTestPreflightProcess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string]$PythonPath,
        [Parameter(Mandatory = $true)] [string]$PreflightScript,
        [Parameter(Mandatory = $true)] [AllowEmptyCollection()] [string[]]$PreflightArguments,
        [switch]$PromptForMcpToken,
        [switch]$ReturnResult,
        [scriptblock]$ProcessInvoker,
        [scriptblock]$SecurePrompt
    )

    $prompted = $false
    $token = [Environment]::GetEnvironmentVariable('BURP_MCP_TOKEN', 'Process')
    if ([string]::IsNullOrWhiteSpace($token) -or $token -notmatch '^[A-Za-z0-9_-]{43}$') {
        if (-not $PromptForMcpToken) {
            if ([string]::IsNullOrWhiteSpace($token)) {
                throw 'BURP_MCP_TOKEN is missing; rerun with -PromptForMcpToken; no test request was sent.'
            }
            throw 'BURP_MCP_TOKEN is not a bare 43-character token; rerun with -PromptForMcpToken; no test request was sent.'
        }
        Set-CancelTestTokenFromSecurePrompt -SecurePrompt $SecurePrompt -Prompt 'Enter the current bare Burp MCP token (input hidden)'
        $prompted = $true
    }

    $arguments = @($PreflightScript) + @($PreflightArguments)
    if ($null -ne $ProcessInvoker) {
        $result = & $ProcessInvoker $PythonPath $arguments
    } else {
        $result = Invoke-CancelTestNativeProcess -ExecutablePath $PythonPath -Arguments $arguments
    }
    if ($result.ExitCode -eq 0) {
        if ($ReturnResult) { return $result }
        if (-not [string]::IsNullOrWhiteSpace($result.StdOut)) { Write-Host $result.StdOut.Trim() }
        return
    }

    $token = [Environment]::GetEnvironmentVariable('BURP_MCP_TOKEN', 'Process')
    $failureText = [string]$result.StdOut + [Environment]::NewLine + [string]$result.StdErr
    $failureKind = Get-CancelTestAuthFailureKind -Text $failureText
    if ($PromptForMcpToken -and -not $prompted -and $failureKind -in @('Rejected', 'Invalid')) {
        Set-CancelTestTokenFromSecurePrompt -SecurePrompt $SecurePrompt -Prompt 'The existing token was rejected. Enter a fresh bare Burp MCP token (input hidden)'
        $prompted = $true
        if ($null -ne $ProcessInvoker) {
            $result = & $ProcessInvoker $PythonPath $arguments
        } else {
            $result = Invoke-CancelTestNativeProcess -ExecutablePath $PythonPath -Arguments $arguments
        }
        if ($result.ExitCode -eq 0) {
            if ($ReturnResult) { return $result }
            if (-not [string]::IsNullOrWhiteSpace($result.StdOut)) { Write-Host $result.StdOut.Trim() }
            return
        }
        $token = [Environment]::GetEnvironmentVariable('BURP_MCP_TOKEN', 'Process')
        $failureText = [string]$result.StdOut + [Environment]::NewLine + [string]$result.StdErr
        $failureKind = Get-CancelTestAuthFailureKind -Text $failureText
    }

    if ($failureKind -eq 'Rejected') {
        throw 'Burp MCP rejected the supplied token (HTTP 401). Refresh the bare token in Burp Security and rerun; no test request was sent.'
    }
    if ($failureKind -eq 'Invalid') {
        throw 'The supplied Burp MCP token is missing or malformed. Refresh the bare token in Burp Security and rerun; no test request was sent.'
    }

    $details = $failureText.Trim()
    if (-not [string]::IsNullOrEmpty($token)) { $details = $details.Replace($token, '[redacted]') }
    if ([string]::IsNullOrWhiteSpace($details)) { $details = 'No safe preflight details were returned.' }
    throw "Cancellation readiness preflight failed (Python exit code $($result.ExitCode)); no test request was sent. $details"
}
