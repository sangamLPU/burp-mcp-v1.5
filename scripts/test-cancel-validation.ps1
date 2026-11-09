$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'cancel-test-validation.ps1')

function New-HttpTestBytes([string]$Text) {
    return ,([System.Text.Encoding]::ASCII.GetBytes($Text))
}

function Assert-Outcome {
    param(
        [string]$Name,
        [byte[]]$Bytes,
        [string]$Termination,
        [string]$ExpectedOutcome,
        [int]$ExpectedServerCount = 0,
        [object]$ExpectedStatusCode = $null,
        [bool]$ExpectedPass
    )
    $observation = Get-CancelClientObservation -ResponseBytes $Bytes -Termination $Termination
    if ($observation.Outcome -ne $ExpectedOutcome) {
        throw "${Name}: expected outcome $ExpectedOutcome, observed $($observation.Outcome)."
    }
    if ($null -ne $ExpectedStatusCode -and $observation.HttpStatusCode -ne [int]$ExpectedStatusCode) {
        throw "${Name}: expected status $ExpectedStatusCode, observed $($observation.HttpStatusCode)."
    }
    $validation = Test-CancelInterceptionObservation -ClientOutcome $observation.Outcome -ClientStatusCode $observation.HttpStatusCode -ServerRequestCount $ExpectedServerCount
    if ($validation.Passed -ne $ExpectedPass) {
        throw "${Name}: validation pass state mismatch; failed conditions: $($validation.FailedConditions -join ', ')."
    }
    return $observation
}

$empty = [byte[]]@()
$eof = Assert-Outcome -Name 'EmptyEof' -Bytes $empty -Termination EOF -ExpectedOutcome EOFWithoutResponse -ExpectedPass $true
$reset = Assert-Outcome -Name 'EmptyReset' -Bytes $empty -Termination ConnectionReset -ExpectedOutcome ConnectionReset -ExpectedPass $true
$aborted = Assert-Outcome -Name 'EmptyAbort' -Bytes $empty -Termination ConnectionAborted -ExpectedOutcome ConnectionAborted -ExpectedPass $true

$completeError = New-HttpTestBytes "HTTP/1.1 502 Bad Gateway`r`nContent-Length: 4`r`nConnection: close`r`n`r`nnope"
$httpError = Assert-Outcome -Name 'CompleteHttpError' -Bytes $completeError -Termination Open -ExpectedOutcome HttpResponseComplete -ExpectedStatusCode 502 -ExpectedPass $true
if ($httpError.ExpectedBodyBytes -ne 4 -or $httpError.BodyBytesObserved -ne 4 -or $httpError.Framing -ne 'Content-Length') {
    throw 'CompleteHttpError: content-length framing was not fully verified.'
}

$completeSuccess = New-HttpTestBytes "HTTP/1.1 200 OK`r`nContent-Length: 0`r`n`r`n"
$httpSuccess = Assert-Outcome -Name 'UnexpectedSuccessResponse' -Bytes $completeSuccess -Termination Open -ExpectedOutcome HttpResponseComplete -ExpectedStatusCode 200 -ExpectedPass $false

$oneByteHeader = New-HttpTestBytes 'H'
$partialTimeout = Assert-Outcome -Name 'OneByteThenTimeout' -Bytes $oneByteHeader -Termination ReadTimeout -ExpectedOutcome PartialHttpResponseTimeout -ExpectedPass $false
if ($partialTimeout.BytesObserved -ne 1) { throw 'OneByteThenTimeout: expected exactly one observed byte.' }
$partialEofHeader = Assert-Outcome -Name 'OneByteThenEof' -Bytes $oneByteHeader -Termination EOF -ExpectedOutcome PartialHttpResponseEOF -ExpectedPass $false
$partialReset = Assert-Outcome -Name 'OneByteThenReset' -Bytes $oneByteHeader -Termination ConnectionReset -ExpectedOutcome PartialHttpResponseConnectionReset -ExpectedPass $false
$partialAbort = Assert-Outcome -Name 'OneByteThenAbort' -Bytes $oneByteHeader -Termination ConnectionAborted -ExpectedOutcome PartialHttpResponseConnectionAborted -ExpectedPass $false
$partialHeadersBytes = New-HttpTestBytes "HTTP/1.1 502 Bad Gateway`r`nContent-Length: 4`r`n"
$partialHeaders = Assert-Outcome -Name 'PartialHeadersTimeout' -Bytes $partialHeadersBytes -Termination ReadTimeout -ExpectedOutcome PartialHttpResponseTimeout -ExpectedPass $false
if ($partialHeaders.Framing -ne 'HeadersIncomplete') { throw 'PartialHeadersTimeout: incomplete headers were not distinguished.' }
$malformedStatus = New-HttpTestBytes "HTTP/1.1 xyz`r`n`r`n"
$invalidStatus = Assert-Outcome -Name 'MalformedStatusLine' -Bytes $malformedStatus -Termination EOF -ExpectedOutcome InvalidHttpResponse -ExpectedPass $false
$malformedHeader = New-HttpTestBytes "HTTP/1.1 502 Bad Gateway`r`nMalformed-Header`r`n`r`nbody"
$invalidHeader = Assert-Outcome -Name 'MalformedHeaderLine' -Bytes $malformedHeader -Termination EOF -ExpectedOutcome InvalidHttpResponse -ExpectedStatusCode 502 -ExpectedPass $false

$partialBody = New-HttpTestBytes "HTTP/1.1 502 Bad Gateway`r`nContent-Length: 10`r`n`r`nbad"
$partialEof = Assert-Outcome -Name 'PartialBodyEof' -Bytes $partialBody -Termination EOF -ExpectedOutcome PartialHttpResponseEOF -ExpectedStatusCode 502 -ExpectedPass $false
if ($partialEof.ExpectedBodyBytes -ne 10 -or $partialEof.BodyBytesObserved -ne 3) {
    throw 'PartialBodyEof: partial Content-Length framing was not reported accurately.'
}
$extraBody = New-HttpTestBytes "HTTP/1.1 502 Bad Gateway`r`nContent-Length: 3`r`n`r`nnope"
$extraBodyObservation = Assert-Outcome -Name 'ExtraBytesAfterContentLength' -Bytes $extraBody -Termination EOF -ExpectedOutcome UnexpectedExtraResponseBytes -ExpectedStatusCode 502 -ExpectedPass $false
$conflictingContentLength = New-HttpTestBytes "HTTP/1.1 502 Bad Gateway`r`nContent-Length: 3`r`nContent-Length: 4`r`n`r`nnope"
$invalidContentLength = Assert-Outcome -Name 'ConflictingContentLengths' -Bytes $conflictingContentLength -Termination EOF -ExpectedOutcome InvalidHttpResponse -ExpectedStatusCode 502 -ExpectedPass $false

$emptyTimeout = Assert-Outcome -Name 'EmptyTimeout' -Bytes $empty -Termination ReadTimeout -ExpectedOutcome ReadTimeout -ExpectedPass $false
$invalidData = New-HttpTestBytes 'X'
$nonHttp = Assert-Outcome -Name 'NonHttpData' -Bytes $invalidData -Termination EOF -ExpectedOutcome NonHttpData -ExpectedPass $false

$closeDelimited = New-HttpTestBytes "HTTP/1.1 502 Bad Gateway`r`nConnection: close`r`n`r`nerror"
$closeResponse = Assert-Outcome -Name 'CloseDelimitedError' -Bytes $closeDelimited -Termination EOF -ExpectedOutcome HttpResponseComplete -ExpectedStatusCode 502 -ExpectedPass $true
if ($closeResponse.Framing -ne 'CloseDelimited') { throw 'CloseDelimitedError: expected close-delimited response framing.' }

$chunked = New-HttpTestBytes "HTTP/1.1 502 Bad Gateway`r`nTransfer-Encoding: chunked`r`n`r`n4`r`nnope`r`n0`r`n`r`n"
$chunkedResponse = Assert-Outcome -Name 'CompleteChunkedError' -Bytes $chunked -Termination Open -ExpectedOutcome HttpResponseComplete -ExpectedStatusCode 502 -ExpectedPass $true
if ($chunkedResponse.Framing -ne 'Chunked') { throw 'CompleteChunkedError: expected chunked response framing.' }
$partialChunked = New-HttpTestBytes "HTTP/1.1 502 Bad Gateway`r`nTransfer-Encoding: chunked`r`n`r`n5`r`nno"
$partialChunkedObservation = Assert-Outcome -Name 'PartialChunkedBody' -Bytes $partialChunked -Termination EOF -ExpectedOutcome PartialHttpResponseEOF -ExpectedStatusCode 502 -ExpectedPass $false

$ambiguousFraming = New-HttpTestBytes "HTTP/1.1 502 Bad Gateway`r`nContent-Length: 4`r`nTransfer-Encoding: chunked`r`n`r`n4`r`nnope`r`n0`r`n`r`n"
$invalidResponse = Assert-Outcome -Name 'ConflictingFraming' -Bytes $ambiguousFraming -Termination EOF -ExpectedOutcome InvalidHttpResponse -ExpectedPass $false

$originReached = Test-CancelInterceptionObservation -ClientOutcome $httpError.Outcome -ClientStatusCode $httpError.HttpStatusCode -ServerRequestCount 1
if ($originReached.Passed -or $originReached.FailedConditions -notcontains 'OriginDidNotReceiveRequest') {
    throw 'OriginRequestDetected: a server observation must fail no-origin-receive validation.'
}

$testId = 'phase4a-' + ('a' * 32)
$validDeliveryRecord = [pscustomobject]@{
    path = '/test-cancel'
    cancellationTestId = $testId
    cancellationTestIdVerified = $true
    cancellationRequestVerified = $true
}
$noDeliveryEvidence = Test-CancelServerDeliveryEvidence -Records @() -TestId $testId
$wrongIdRecord = $validDeliveryRecord.PSObject.Copy()
$wrongIdRecord.cancellationTestId = 'phase4a-' + ('b' * 32)
$wrongIdEvidence = Test-CancelServerDeliveryEvidence -Records @($wrongIdRecord) -TestId $testId
$duplicateEvidence = Test-CancelServerDeliveryEvidence -Records @($validDeliveryRecord, $validDeliveryRecord.PSObject.Copy()) -TestId $testId
if (-not $noDeliveryEvidence.NoOriginDelivery -or $noDeliveryEvidence.MatchingTestIdRecords -ne 0) {
    throw 'NoDeliveryEvidence: an empty server record set was not verified as zero origin delivery.'
}
if ($wrongIdEvidence.NoOriginDelivery -or $wrongIdEvidence.MatchingTestIdRecords -ne 0 -or $wrongIdEvidence.VerifiedSingleDelivery) {
    throw 'WrongTestIdEvidence: a wrong test ID was not distinguished from the expected ID.'
}
if ($duplicateEvidence.ServerRequestsToTestPath -ne 2 -or $duplicateEvidence.MatchingTestIdRecords -ne 2 -or $duplicateEvidence.VerifiedSingleDelivery) {
    throw 'DuplicateDeliveryEvidence: duplicate matching delivery was not rejected.'
}
if ((Test-CancelInterceptionObservation -ClientOutcome 'EOFWithoutResponse' -ServerRequestCount $wrongIdEvidence.ServerRequestsToTestPath).Passed -or
    (Test-CancelInterceptionObservation -ClientOutcome 'EOFWithoutResponse' -ServerRequestCount $duplicateEvidence.ServerRequestsToTestPath).Passed) {
    throw 'Origin delivery with a wrong or duplicated test ID must fail cancellation validation.'
}

$timeoutSocket = [System.Net.Sockets.SocketException]::new([int][System.Net.Sockets.SocketError]::TimedOut)
$resetSocket = [System.Net.Sockets.SocketException]::new([int][System.Net.Sockets.SocketError]::ConnectionReset)
$abortSocket = [System.Net.Sockets.SocketException]::new([int][System.Net.Sockets.SocketError]::ConnectionAborted)
$otherSocket = [System.Net.Sockets.SocketException]::new([int][System.Net.Sockets.SocketError]::HostNotFound)
if ((Get-CancelSocketTermination -Exception ([System.IO.IOException]::new('synthetic timeout', $timeoutSocket))) -ne 'ReadTimeout') {
    throw 'SocketTimeoutMapping: IOException-wrapped timeout was not identified.'
}
if ((Get-CancelSocketTermination -Exception ([System.IO.IOException]::new('synthetic reset', $resetSocket))) -ne 'ConnectionReset') {
    throw 'SocketResetMapping: IOException-wrapped reset was not identified.'
}
if ((Get-CancelSocketTermination -Exception $abortSocket) -ne 'ConnectionAborted') {
    throw 'SocketAbortMapping: direct abort was not identified.'
}
if ((Get-CancelSocketTermination -Exception $otherSocket) -ne 'SocketError') {
    throw 'OtherSocketMapping: unclassified socket error was not kept distinct.'
}
if ((Get-CancelSocketTermination -Exception ([System.IO.IOException]::new('synthetic read error'))) -ne 'ReadError') {
    throw 'ReadErrorMapping: non-socket I/O failure was not kept distinct.'
}

[pscustomobject]@{
    EmptyEof = 'PASS'
    EmptyReset = 'PASS'
    EmptyAbort = 'PASS'
    CompleteHttpError = 'PASS'
    UnexpectedSuccessResponseRejected = 'PASS'
    OneBytePartialTimeout = 'PASS'
    OneBytePartialEofResetAbort = 'PASS'
    PartialAndMalformedHeaders = 'PASS'
    PartialBodyEof = 'PASS'
    ContentLengthMismatchAndExtraBytes = 'PASS'
    EmptyTimeout = 'PASS'
    NonHttpData = 'PASS'
    CloseDelimitedError = 'PASS'
    CompleteChunkedError = 'PASS'
    PartialChunkedBody = 'PASS'
    ConflictingFramingRejected = 'PASS'
    ServerRequestDetected = 'PASS'
    WrongTestIdAndDuplicateDeliveryRejected = 'PASS'
    SocketExceptionMapping = 'PASS'
    NetworkRequestsSent = 0
} | Format-List
