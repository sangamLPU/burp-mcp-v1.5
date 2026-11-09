$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'local-test-method-fixture.ps1')
$script:passed = 0
function Assert-Fixture([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
    $script:passed++
}
function Assert-FixtureRejects([hashtable]$Arguments) {
    $rejected = $false
    try { New-TestMethodFixtureResponse @Arguments | Out-Null } catch { $rejected = $true }
    Assert-Fixture $rejected 'Unsafe or malformed synthetic fixture input was accepted.'
}
$payload = '{"enabled":true,"name":"original","mcp_test":"after","marker":"preserve","case":"phase2-one","nested":{"keep":17}}'
$bytes = [Text.Encoding]::UTF8.GetBytes($payload)
$hash = [Security.Cryptography.SHA256]::Create()
try { $digest = ([BitConverter]::ToString($hash.ComputeHash($bytes))).Replace('-','').ToLowerInvariant() } finally { $hash.Dispose() }
$arguments = @{Path='/test-post-phase2';Method='POST';BodyBytes=$bytes;BodySha256=$digest;RuleEngineTestMode=$true;ContentType='application/json; charset=utf-8';TestId='phase2-one'}
$result = New-TestMethodFixtureResponse @arguments
Assert-Fixture ($result.enabled -eq $false -and $payload.Contains('"enabled":true')) 'Response must independently reset enabled=false.'
Assert-Fixture ($result.case -ceq 'phase2-one' -and $result.marker -ceq 'preserve' -and $result.nested.keep -eq 17) 'Synthetic fields were not preserved.'
Assert-Fixture ($result.bodySha256 -ceq $digest -and $result.bodyByteLength -eq $bytes.Length -and $result.method -ceq 'POST') 'Origin body evidence changed.'
$legacy = New-TestMethodFixtureResponse -Path '/test-method' -Method 'GET' -BodyBytes $bytes -BodySha256 $digest -RuleEngineTestMode $false
Assert-Fixture ($legacy.Count -eq 4 -and $legacy.path -ceq '/test-method' -and $legacy.method -ceq 'GET') 'Existing method fixture contract changed.'
$legacyCase = New-TestMethodFixtureResponse -Path '/TEST-METHOD' -Method 'GET' -BodyBytes $bytes -BodySha256 $digest -RuleEngineTestMode $false
Assert-Fixture ($legacyCase.path -ceq '/test-method') 'Existing case-insensitive method route changed.'
foreach ($override in @(
    @{RuleEngineTestMode=$false}, @{Path='/test-post-phase2-extra'}, @{Path='/TEST-POST-PHASE2'},
    @{Method='GET'}, @{ContentType='text/plain'}, @{TestId='wrong-case'},
    @{BodyBytes=[Text.Encoding]::UTF8.GetBytes('not-json')},
    @{BodyBytes=[Text.Encoding]::UTF8.GetBytes($payload.Replace('"enabled":true','"enabled":"true"'))},
    @{BodyBytes=[Text.Encoding]::UTF8.GetBytes($payload.Replace('"keep":17','"keep":17,"extra":1'))},
    @{BodyBytes=[Text.Encoding]::UTF8.GetBytes($payload.Replace('"marker":"preserve"','"marker":"preserve","password":"synthetic"'))}
)) {
    $negative = $arguments.Clone()
    foreach ($key in $override.Keys) { $negative[$key] = $override[$key] }
    Assert-FixtureRejects $negative
}
Write-Output "PASS: $script:passed pure fixture checks; no listener, HTTP request or Burp connection."
