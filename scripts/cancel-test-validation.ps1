function Get-CancelSocketTermination {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] [System.Exception]$Exception)

    $current = $Exception
    while ($null -ne $current) {
        if ($current -is [System.Net.Sockets.SocketException]) {
            switch ($current.SocketErrorCode) {
                ([System.Net.Sockets.SocketError]::TimedOut) { return 'ReadTimeout' }
                ([System.Net.Sockets.SocketError]::ConnectionReset) { return 'ConnectionReset' }
                ([System.Net.Sockets.SocketError]::ConnectionAborted) { return 'ConnectionAborted' }
                default { return 'SocketError' }
            }
        }
        $current = $current.InnerException
    }
    return 'ReadError'
}

function Get-CancelClientObservation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [AllowEmptyCollection()] [byte[]]$ResponseBytes,
        [Parameter(Mandatory = $true)]
        [ValidateSet('Open', 'EOF', 'ConnectionReset', 'ConnectionAborted', 'ReadTimeout', 'SocketError', 'ReadError', 'ResponseTooLarge')]
        [string]$Termination
    )

    $byteCount = $ResponseBytes.Length
    $emptyResult = switch ($Termination) {
        'Open' { 'NoDataYet' }
        'EOF' { 'EOFWithoutResponse' }
        'ConnectionReset' { 'ConnectionReset' }
        'ConnectionAborted' { 'ConnectionAborted' }
        'ReadTimeout' { 'ReadTimeout' }
        'ResponseTooLarge' { 'ResponseTooLarge' }
        default { $Termination }
    }
    if ($byteCount -eq 0) {
        return [pscustomobject]@{
            Outcome = $emptyResult; BytesObserved = 0; HttpStatusCode = $null
            ExpectedBodyBytes = $null; BodyBytesObserved = 0; Framing = 'None'
            ResponseComplete = $false
        }
    }
    if ($Termination -eq 'ResponseTooLarge') {
        return [pscustomobject]@{
            Outcome = 'ResponseTooLarge'; BytesObserved = $byteCount; HttpStatusCode = $null
            ExpectedBodyBytes = $null; BodyBytesObserved = $null; Framing = 'Unknown'
            ResponseComplete = $false
        }
    }

    # ASCII is used only to inspect HTTP framing. The original bytes remain in memory and
    # are never displayed or written to disk.
    $text = [System.Text.Encoding]::ASCII.GetString($ResponseBytes)
    $headerTerminator = "`r`n`r`n"
    $headerEnd = $text.IndexOf($headerTerminator, [System.StringComparison]::Ordinal)
    if ($headerEnd -lt 0) {
        $protocols = @('HTTP/1.0 ', 'HTTP/1.1 ')
        $possibleHttp = $false
        foreach ($protocol in $protocols) {
            if ($protocol.StartsWith($text, [System.StringComparison]::OrdinalIgnoreCase) -or
                $text.StartsWith($protocol, [System.StringComparison]::OrdinalIgnoreCase)) {
                $possibleHttp = $true
                break
            }
        }
        if (-not $possibleHttp) {
            return [pscustomobject]@{
                Outcome = 'NonHttpData'; BytesObserved = $byteCount; HttpStatusCode = $null
                ExpectedBodyBytes = $null; BodyBytesObserved = $null; Framing = 'Unknown'
                ResponseComplete = $false
            }
        }
        $partialOutcome = switch ($Termination) {
            'Open' { 'ResponseInProgress' }
            'EOF' { 'PartialHttpResponseEOF' }
            'ConnectionReset' { 'PartialHttpResponseConnectionReset' }
            'ConnectionAborted' { 'PartialHttpResponseConnectionAborted' }
            'ReadTimeout' { 'PartialHttpResponseTimeout' }
            default { 'PartialHttpResponse' }
        }
        return [pscustomobject]@{
            Outcome = $partialOutcome; BytesObserved = $byteCount; HttpStatusCode = $null
            ExpectedBodyBytes = $null; BodyBytesObserved = $null; Framing = 'HeadersIncomplete'
            ResponseComplete = $false
        }
    }

    $headerText = $text.Substring(0, $headerEnd)
    $lines = $headerText -split "`r`n"
    if ($lines.Count -lt 1 -or $lines[0] -notmatch '^HTTP/1\.[01] ([0-9]{3})(?:[ \t].*)?$') {
        return [pscustomobject]@{
            Outcome = 'InvalidHttpResponse'; BytesObserved = $byteCount; HttpStatusCode = $null
            ExpectedBodyBytes = $null; BodyBytesObserved = $null; Framing = 'Invalid'
            ResponseComplete = $false
        }
    }
    $statusCode = [int]$Matches[1]
    $headers = @{}
    $contentLengths = @()
    $transferEncoding = $null
    for ($index = 1; $index -lt $lines.Count; $index++) {
        $line = $lines[$index]
        if ($line -notmatch '^([^:]+):[ \t]*(.*)$') {
            return [pscustomobject]@{
                Outcome = 'InvalidHttpResponse'; BytesObserved = $byteCount; HttpStatusCode = $statusCode
                ExpectedBodyBytes = $null; BodyBytesObserved = $null; Framing = 'Invalid'
                ResponseComplete = $false
            }
        }
        $name = $Matches[1].Trim()
        $value = $Matches[2].Trim()
        if ($name -ieq 'Content-Length') { $contentLengths += $value }
        if ($name -ieq 'Transfer-Encoding') { $transferEncoding = $value }
        $headers[$name] = $value
    }
    $bodyStart = $headerEnd + $headerTerminator.Length
    $bodyBytes = $byteCount - $bodyStart
    $framing = 'CloseDelimited'
    $expectedBodyBytes = $null
    $framingComplete = $false
    $framingInvalid = $false

    if ($contentLengths.Count -gt 0) {
        $parsedLengths = @()
        foreach ($lengthText in $contentLengths) {
            $parsedLength = [long]0
            if (-not [long]::TryParse($lengthText, [ref]$parsedLength) -or $parsedLength -lt 0) {
                $framingInvalid = $true
                break
            }
            $parsedLengths += $parsedLength
        }
        if (-not $framingInvalid -and (@($parsedLengths | Select-Object -Unique).Count -ne 1)) {
            $framingInvalid = $true
        }
        if ($null -ne $transferEncoding) { $framingInvalid = $true }
        if (-not $framingInvalid) {
            $expectedBodyBytes = [long]$parsedLengths[0]
            $framing = 'Content-Length'
            if ($bodyBytes -eq $expectedBodyBytes) { $framingComplete = $true }
        }
    } elseif ($null -ne $transferEncoding) {
        if ($transferEncoding -notmatch '(?i)(?:^|,)\s*chunked\s*$') {
            $framingInvalid = $true
        } else {
            $framing = 'Chunked'
            $position = $bodyStart
            while (-not $framingInvalid -and -not $framingComplete) {
                $chunkLineEnd = $text.IndexOf("`r`n", $position, [System.StringComparison]::Ordinal)
                if ($chunkLineEnd -lt 0) { break }
                $chunkLine = $text.Substring($position, $chunkLineEnd - $position)
                $sizeText = ($chunkLine -split ';', 2)[0].Trim()
                $chunkSize = [long]0
                if (-not [long]::TryParse($sizeText, [System.Globalization.NumberStyles]::HexNumber, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$chunkSize) -or $chunkSize -lt 0) {
                    $framingInvalid = $true
                    break
                }
                $chunkDataStart = $chunkLineEnd + 2
                if ($chunkSize -eq 0) {
                    if ($text.Length -ge ($chunkDataStart + 2) -and $text.Substring($chunkDataStart, 2) -ceq "`r`n") {
                        $framingComplete = $true
                    } else {
                        $trailersEnd = $text.IndexOf($headerTerminator, $chunkDataStart, [System.StringComparison]::Ordinal)
                        if ($trailersEnd -ge 0) { $framingComplete = $true }
                    }
                    break
                }
                $nextChunk = $chunkDataStart + $chunkSize
                if ($nextChunk + 2 -gt $byteCount) { break }
                if ($text.Substring([int]$nextChunk, 2) -cne "`r`n") {
                    $framingInvalid = $true
                    break
                }
                $position = [int]$nextChunk + 2
            }
        }
    } elseif ($statusCode -lt 200 -or $statusCode -eq 204 -or $statusCode -eq 304) {
        $framing = 'NoBody'
        $expectedBodyBytes = [long]0
        $framingComplete = ($bodyBytes -eq 0)
        if ($bodyBytes -gt 0) { $framingInvalid = $true }
    }

    if ($framingInvalid) {
        return [pscustomobject]@{
            Outcome = 'InvalidHttpResponse'; BytesObserved = $byteCount; HttpStatusCode = $statusCode
            ExpectedBodyBytes = $expectedBodyBytes; BodyBytesObserved = $bodyBytes; Framing = 'Invalid'
            ResponseComplete = $false
        }
    }

    $extraBodyBytes = ($null -ne $expectedBodyBytes -and $bodyBytes -gt $expectedBodyBytes)
    if ($extraBodyBytes) {
        return [pscustomobject]@{
            Outcome = 'UnexpectedExtraResponseBytes'; BytesObserved = $byteCount; HttpStatusCode = $statusCode
            ExpectedBodyBytes = $expectedBodyBytes; BodyBytesObserved = $bodyBytes; Framing = $framing
            ResponseComplete = $false
        }
    }
    if ($framingComplete) {
        return [pscustomobject]@{
            Outcome = 'HttpResponseComplete'; BytesObserved = $byteCount; HttpStatusCode = $statusCode
            ExpectedBodyBytes = $expectedBodyBytes; BodyBytesObserved = $bodyBytes; Framing = $framing
            ResponseComplete = $true
        }
    }
    if ($framing -eq 'CloseDelimited' -and $Termination -eq 'EOF') {
        return [pscustomobject]@{
            Outcome = 'HttpResponseComplete'; BytesObserved = $byteCount; HttpStatusCode = $statusCode
            ExpectedBodyBytes = $null; BodyBytesObserved = $bodyBytes; Framing = $framing
            ResponseComplete = $true
        }
    }
    if ($Termination -eq 'Open') {
        $outcome = 'ResponseInProgress'
    } else {
        $outcome = switch ($Termination) {
            'EOF' { 'PartialHttpResponseEOF' }
            'ConnectionReset' { 'PartialHttpResponseConnectionReset' }
            'ConnectionAborted' { 'PartialHttpResponseConnectionAborted' }
            'ReadTimeout' { 'PartialHttpResponseTimeout' }
            default { 'PartialHttpResponse' }
        }
    }
    return [pscustomobject]@{
        Outcome = $outcome; BytesObserved = $byteCount; HttpStatusCode = $statusCode
        ExpectedBodyBytes = $expectedBodyBytes; BodyBytesObserved = $bodyBytes; Framing = $framing
        ResponseComplete = $false
    }
}

function Test-CancelInterceptionObservation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string]$ClientOutcome,
        [object]$ClientStatusCode = $null,
        [Parameter(Mandatory = $true)] [int]$ServerRequestCount
    )

    $clientFailureObserved = $ClientOutcome -in @('EOFWithoutResponse', 'ConnectionReset', 'ConnectionAborted')
    if ($ClientOutcome -eq 'HttpResponseComplete' -and $null -ne $ClientStatusCode) {
        $clientFailureObserved = ([int]$ClientStatusCode -ge 400 -and [int]$ClientStatusCode -le 599)
    }
    $checks = [ordered]@{
        ClientReleasedWithObservableFailure = [bool]$clientFailureObserved
        OriginDidNotReceiveRequest = ($ServerRequestCount -eq 0)
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

function Test-CancelServerDeliveryEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [AllowEmptyCollection()] [object[]]$Records,
        [Parameter(Mandatory = $true)] [ValidatePattern('^phase4a-[0-9a-f]{32}$')] [string]$TestId
    )

    $testPathRecords = @($Records | Where-Object { $_.path -eq '/test-cancel' })
    $matchingIdRecords = @($testPathRecords | Where-Object { $_.cancellationTestId -ceq $TestId })
    $verifiedSingleDelivery = (
        $matchingIdRecords.Count -eq 1 -and
        $matchingIdRecords[0].cancellationTestIdVerified -eq $true -and
        $matchingIdRecords[0].cancellationRequestVerified -eq $true
    )
    [pscustomobject]@{
        ServerRequestsToTestPath = $testPathRecords.Count
        MatchingTestIdRecords = $matchingIdRecords.Count
        VerifiedSingleDelivery = $verifiedSingleDelivery
        NoOriginDelivery = ($testPathRecords.Count -eq 0)
    }
}
