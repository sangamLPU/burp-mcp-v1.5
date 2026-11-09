function Test-ConcurrentRunnerResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [psobject]$ResponseA,
        [Parameter(Mandatory = $true)] [psobject]$ResponseB,
        [Parameter(Mandatory = $true)] [string]$TestIdA,
        [Parameter(Mandatory = $true)] [string]$TestIdB
    )

    $serverA = $ResponseA.Json
    $serverB = $ResponseB.Json
    $checks = [ordered]@{
        UniqueTestIds = ($TestIdA -ne $TestIdB)
        A_Http200 = ($ResponseA.StatusCode -eq 200)
        A_ResponseFraming = ($ResponseA.ContentLength -eq $ResponseA.BytesReceived)
        A_PathMatches = ($serverA.Path -eq '/test-concurrent-a')
        A_TestIdMatches = ($serverA.TestId -eq $TestIdA)
        A_ServerVerified = ($serverA.ServerVerified -eq $true)
        A_McpTestModified = ($serverA.McpTestModified -eq $true)
        A_NameFieldPreserved = ($serverA.NameFieldPreserved -eq $true)
        A_MarkerFieldPreserved = ($serverA.MarkerFieldPreserved -eq $true)
        A_FieldCount = ($serverA.FieldCount -eq 4)
        A_ContentTypeVerified = ($serverA.ContentTypeVerified -eq $true)
        A_RequestFraming = (
            $serverA.RequestContentLengthMatchesBody -eq $true -and
            $serverA.RequestBodyByteLength -eq $serverA.RequestContentLength
        )
        B_Http200 = ($ResponseB.StatusCode -eq 200)
        B_ResponseFraming = ($ResponseB.ContentLength -eq $ResponseB.BytesReceived)
        B_PathMatches = ($serverB.Path -eq '/test-concurrent-b')
        B_TestIdMatches = ($serverB.TestId -eq $TestIdB)
        B_ServerVerified = ($serverB.ServerVerified -eq $true)
        B_McpTestModified = ($serverB.McpTestModified -eq $true)
        B_NameFieldPreserved = ($serverB.NameFieldPreserved -eq $true)
        B_MarkerFieldPreserved = ($serverB.MarkerFieldPreserved -eq $true)
        B_FieldCount = ($serverB.FieldCount -eq 4)
        B_ContentTypeVerified = ($serverB.ContentTypeVerified -eq $true)
        B_RequestFraming = (
            $serverB.RequestContentLengthMatchesBody -eq $true -and
            $serverB.RequestBodyByteLength -eq $serverB.RequestContentLength
        )
    }

    $failedConditions = @(
        foreach ($entry in $checks.GetEnumerator()) {
            if (-not [bool]$entry.Value) { $entry.Key }
        }
    )
    [pscustomobject]@{
        Passed = ($failedConditions.Count -eq 0)
        FailedConditions = $failedConditions
        Checks = [pscustomobject]$checks
    }
}
