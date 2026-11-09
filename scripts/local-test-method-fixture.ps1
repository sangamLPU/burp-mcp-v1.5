# Pure response builder shared by the existing method fixture and Phase 2 alias.
# Loading this file creates no listener and sends no traffic.
function New-TestMethodFixtureResponse {
    param(
        [string]$Path,
        [string]$Method,
        [byte[]]$BodyBytes,
        [string]$BodySha256,
        [bool]$RuleEngineTestMode,
        [string]$ContentType = '',
        [string]$TestId = ''
    )
    $result = [ordered]@{
        path = $Path
        method = $Method
        bodyByteLength = $BodyBytes.Length
        bodySha256 = $BodySha256
    }
    if ($Path -ieq '/test-method') {
        $result['path'] = '/test-method'
        return $result
    }
    if ($Path -cne '/test-post-phase2' -or -not $RuleEngineTestMode) {
        throw 'Phase 2 fixture is available only at its exact path in rule-test mode.'
    }
    if ($Method -cne 'POST' -or ($ContentType -split ';')[0].Trim() -cne 'application/json') {
        throw 'Phase 2 fixture requires POST application/json.'
    }
    $body = ConvertFrom-Json -InputObject ([Text.UTF8Encoding]::new($false,$true).GetString($BodyBytes)) -ErrorAction Stop
    if ($body -isnot [pscustomobject] -or $body.enabled -isnot [bool] -or
        $TestId -cnotmatch '^[A-Za-z0-9_-]{1,64}$' -or $body.case -cne $TestId -or
        $body.name -cne 'original' -or $body.mcp_test -cne 'after' -or
        $body.marker -cne 'preserve' -or $body.nested.keep -ne 17 -or
        (($body.PSObject.Properties.Name | Sort-Object) -join ',') -cne 'case,enabled,marker,mcp_test,name,nested' -or
        (($body.nested.PSObject.Properties.Name | Sort-Object) -join ',') -cne 'keep') {
        throw 'Phase 2 fixture requires the bounded synthetic payload and matching case ID.'
    }
    # Origin records separately retain the received request value. The deliberately
    # false origin response lets the client independently verify a response edit.
    foreach ($property in $body.PSObject.Properties) { $result[$property.Name] = $property.Value }
    $result['enabled'] = $false
    return $result
}
