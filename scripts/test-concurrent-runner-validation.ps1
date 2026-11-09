$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'concurrent-test-validation.ps1')

$idA = 'phase3-A-5464857c6f354b81b135962cbe72f3bc'
$idB = 'phase3-B-93ba1620067e43cea1a517dc2ec2de6b'
$originalBodyA = "test_id=$idA&mcp_test=alpha&name=case-A&marker=keep-A"
$originalBodyB = "test_id=$idB&mcp_test=beta&name=case-B&marker=keep-B"
$editedBodyA = "test_id=$idA&mcp_test=alpha-modified&name=case-A&marker=keep-A"
$editedBodyB = "test_id=$idB&mcp_test=beta-modified&name=case-B&marker=keep-B"
$ascii = [System.Text.Encoding]::ASCII
$originalLengthA = $ascii.GetByteCount($originalBodyA)
$originalLengthB = $ascii.GetByteCount($originalBodyB)

# These JSON fixtures match the local server response schema and the observed run.
$serverA = @{
    Path = '/test-concurrent-a'; TestId = $idA; TestIdVerified = $true
    McpTestModified = $true; NameFieldPreserved = $true; MarkerFieldPreserved = $true
    FieldCount = 4; ContentTypeVerified = $true; RequestContentLength = 99
    RequestBodyByteLength = 99; RequestContentLengthMatchesBody = $true; ServerVerified = $true
} | ConvertTo-Json -Compress | ConvertFrom-Json
$serverB = @{
    Path = '/test-concurrent-b'; TestId = $idB; TestIdVerified = $true
    McpTestModified = $true; NameFieldPreserved = $true; MarkerFieldPreserved = $true
    FieldCount = 4; ContentTypeVerified = $true; RequestContentLength = 98
    RequestBodyByteLength = 98; RequestContentLengthMatchesBody = $true; ServerVerified = $true
} | ConvertTo-Json -Compress | ConvertFrom-Json
$responseA = [pscustomobject]@{ StatusCode = 200; ContentLength = 337; BytesReceived = 337; Json = $serverA }
$responseB = [pscustomobject]@{ StatusCode = 200; ContentLength = 337; BytesReceived = 337; Json = $serverB }

if ($originalLengthA -ne 90 -or $originalLengthB -ne 89) {
    throw "Fixture setup drifted: original body lengths were $originalLengthA/$originalLengthB, expected 90/89."
}
if ($ascii.GetByteCount($editedBodyA) -ne 99 -or $ascii.GetByteCount($editedBodyB) -ne 98) {
    throw 'Fixture setup drifted: edited body lengths must be 99/98 bytes.'
}
if ($serverA.RequestBodyByteLength -eq $originalLengthA -or $serverB.RequestBodyByteLength -eq $originalLengthB) {
    throw 'Regression fixture must show that edited request lengths differ from the original request lengths.'
}
if ($serverA.ServerVerified -isnot [bool] -or $serverA.RequestContentLength -isnot [int] -or
    $serverA.RequestBodyByteLength -isnot [int] -or $serverA.McpTestModified -isnot [bool]) {
    throw 'ConvertFrom-Json did not produce the expected Boolean and integer property types.'
}

$positive = Test-ConcurrentRunnerResult -ResponseA $responseA -ResponseB $responseB -TestIdA $idA -TestIdB $idB
if (-not $positive.Passed) {
    throw "Edited-body framing fixture should pass; failed conditions: $($positive.FailedConditions -join ', ')"
}

$badFramingA = $serverA | Select-Object *
$badFramingA.RequestContentLength = 100
$badFramingA.RequestContentLengthMatchesBody = $false
$badFramingResponseA = [pscustomobject]@{ StatusCode = 200; ContentLength = 337; BytesReceived = 337; Json = $badFramingA }
$badFraming = Test-ConcurrentRunnerResult -ResponseA $badFramingResponseA -ResponseB $responseB -TestIdA $idA -TestIdB $idB
if ($badFraming.Passed -or $badFraming.FailedConditions -notcontains 'A_RequestFraming') {
    throw 'Negative request-framing fixture was not rejected by A_RequestFraming.'
}

$crossedServerB = $serverB | Select-Object *
$crossedServerB.TestId = $idA
$crossedResponseB = [pscustomobject]@{ StatusCode = 200; ContentLength = 337; BytesReceived = 337; Json = $crossedServerB }
$crossed = Test-ConcurrentRunnerResult -ResponseA $responseA -ResponseB $crossedResponseB -TestIdA $idA -TestIdB $idB
if ($crossed.Passed -or $crossed.FailedConditions -notcontains 'B_TestIdMatches') {
    throw 'Negative cross-association fixture was not rejected by B_TestIdMatches.'
}

[pscustomobject]@{
    PositiveEditedLengthFixture = 'PASS'
    OriginalRequestLengths = "$originalLengthA/$originalLengthB"
    EditedRequestLengths = "$($serverA.RequestBodyByteLength)/$($serverB.RequestBodyByteLength)"
    OldPredicateWouldRejectValidRun = 'True'
    BadFramingRejected = 'PASS'
    CrossAssociationRejected = 'PASS'
    NetworkRequestsSent = 0
} | Format-List
