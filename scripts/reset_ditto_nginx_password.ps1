param(
    [string]$HtpasswdPath = "E:\DUK\SEM3\MINI PROJECT\ditto\deployment\docker\nginx.htpasswd",
    [string]$NginxContainer = "docker-nginx-1",
    [string]$ThingsUri = "http://localhost:8080/api/2/things/iomt:device1",
    [string]$OpenSslPath = "C:\Program Files\Git\usr\bin\openssl.exe"
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

function Set-RestrictedAcl {
    param([Parameter(Mandatory = $true)][string]$Path)

    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $item = Get-Item -LiteralPath $Path

    if ($item.PSIsContainer) {
        $acl = Get-Acl -LiteralPath $Path
        $acl.SetAccessRuleProtection($true, $false)
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $identity,
            "FullControl",
            "ContainerInherit,ObjectInherit",
            "None",
            "Allow"
        )
    }
    else {
        $acl = Get-Acl -LiteralPath $Path
        $acl.SetAccessRuleProtection($true, $false)
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $identity,
            "FullControl",
            "Allow"
        )
    }

    $acl.AddAccessRule($rule)
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function New-Apr1Hash {
    param(
        [Parameter(Mandatory = $true)][string]$OpenSsl,
        [Parameter(Mandatory = $true)][string]$Password
    )

    if (-not (Test-Path -LiteralPath $OpenSsl -PathType Leaf)) {
        throw "OpenSSL was not found at $OpenSsl"
    }

    $start = New-Object System.Diagnostics.ProcessStartInfo
    $start.FileName = $OpenSsl
    $start.Arguments = "passwd -apr1 -stdin"
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $start
    $passwordBytes = $null

    try {
        if (-not $process.Start()) {
            throw "Unable to start OpenSSL."
        }

        $utf8 = New-Object System.Text.UTF8Encoding($false, $true)
        $passwordBytes = $utf8.GetBytes($Password)
        $process.StandardInput.BaseStream.Write(
            $passwordBytes,
            0,
            $passwordBytes.Length
        )
        $process.StandardInput.BaseStream.Flush()
        $process.StandardInput.Close()
        $stdout = $process.StandardOutput.ReadToEnd().Trim()
        $stderr = $process.StandardError.ReadToEnd().Trim()
        $process.WaitForExit()

        if ($process.ExitCode -ne 0 -or [string]::IsNullOrWhiteSpace($stdout)) {
            throw "OpenSSL password hashing failed."
        }

        return $stdout
    }
    finally {
        if ($passwordBytes) {
            [Array]::Clear($passwordBytes, 0, $passwordBytes.Length)
        }
        $process.Dispose()
    }
}

function Test-Apr1Hash {
    param(
        [Parameter(Mandatory = $true)][string]$OpenSsl,
        [Parameter(Mandatory = $true)][string]$Password,
        [Parameter(Mandatory = $true)][string]$ExpectedHash
    )

    if ($ExpectedHash -notmatch '^\$apr1\$([./A-Za-z0-9]{1,8})\$[./A-Za-z0-9]{22}$') {
        throw "The staged ditto entry is not a valid APR1 hash."
    }

    $salt = $Matches[1]
    $start = New-Object System.Diagnostics.ProcessStartInfo
    $start.FileName = $OpenSsl
    $start.Arguments = "passwd -apr1 -salt $salt -stdin"
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $start
    $passwordBytes = $null

    try {
        if (-not $process.Start()) {
            throw "Unable to start the APR1 verifier."
        }

        $utf8 = New-Object System.Text.UTF8Encoding($false, $true)
        $passwordBytes = $utf8.GetBytes($Password)
        $process.StandardInput.BaseStream.Write(
            $passwordBytes,
            0,
            $passwordBytes.Length
        )
        $process.StandardInput.BaseStream.Flush()
        $process.StandardInput.Close()
        $stdout = $process.StandardOutput.ReadToEnd().Trim()
        $stderr = $process.StandardError.ReadToEnd().Trim()
        $process.WaitForExit()

        if ($process.ExitCode -ne 0 -or [string]::IsNullOrWhiteSpace($stdout)) {
            throw "The independent APR1 verifier failed."
        }

        return [string]::Equals(
            $stdout,
            $ExpectedHash,
            [StringComparison]::Ordinal
        )
    }
    finally {
        if ($passwordBytes) {
            [Array]::Clear($passwordBytes, 0, $passwordBytes.Length)
        }
        $process.Dispose()
    }
}

function Test-ByteEqual {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Left,
        [Parameter(Mandatory = $true)][byte[]]$Right
    )

    if ($Left.Length -ne $Right.Length) {
        return $false
    }

    for ($index = 0; $index -lt $Left.Length; $index++) {
        if ($Left[$index] -ne $Right[$index]) {
            return $false
        }
    }

    return $true
}

function Write-FileInPlace {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][byte[]]$Bytes
    )

    $stream = [IO.File]::Open(
        $Path,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Write,
        [IO.FileShare]::None
    )

    try {
        $stream.SetLength(0)
        $stream.Write($Bytes, 0, $Bytes.Length)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }
}

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw "Docker is unavailable in this PowerShell session."
}

if (-not (Test-Path -LiteralPath $HtpasswdPath -PathType Leaf)) {
    throw "Active nginx password file not found: $HtpasswdPath"
}

$nginxState = docker inspect $NginxContainer --format "{{.State.Status}}"
if ($nginxState -ne "running") {
    throw "The nginx container is not running."
}

$mountsJson = docker inspect $NginxContainer --format '{{json .Mounts}}'
if ($LASTEXITCODE -ne 0) {
    throw "Docker mount inspection failed for $NginxContainer."
}

try {
    $mounts = $mountsJson | ConvertFrom-Json
}
catch {
    throw "Docker mount inspection returned unreadable JSON."
}

$htpasswdMounts = @(
    $mounts | Where-Object {
        $_.Destination -eq "/etc/nginx/nginx.htpasswd"
    }
)

if ($htpasswdMounts.Count -ne 1) {
    throw (
        "Verified mount mismatch: expected exactly one active mount at " +
        "/etc/nginx/nginx.htpasswd."
    )
}

$mountedSource = [IO.Path]::GetFullPath(
    [string]$htpasswdMounts[0].Source
)
$intendedSource = [IO.Path]::GetFullPath($HtpasswdPath)

if ($mountedSource -ne $intendedSource) {
    throw (
        "Verified mount mismatch: nginx htpasswd Source is " +
        "'$mountedSource', expected '$intendedSource'."
    )
}

$timestamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssfffZ")
$backupRoot = Join-Path $env:LOCALAPPDATA "IoMT-Lab-Backups\DittoNginxAuth"
$backupDirectory = Join-Path $backupRoot $timestamp
$backupPath = Join-Path $backupDirectory "nginx.htpasswd.bak"
$stagedPath = Join-Path $backupDirectory "nginx.htpasswd.staged"

New-Item -ItemType Directory -Path $backupDirectory -Force | Out-Null
Set-RestrictedAcl -Path $backupDirectory
Copy-Item -LiteralPath $HtpasswdPath -Destination $backupPath
Set-RestrictedAcl -Path $backupPath

$originalBytes = [IO.File]::ReadAllBytes($HtpasswdPath)
$backupBytes = [IO.File]::ReadAllBytes($backupPath)
if (-not (Test-ByteEqual $originalBytes $backupBytes)) {
    throw "The private backup does not match the active file."
}

$originalText = [IO.File]::ReadAllText($HtpasswdPath)
$targetAclSddl = (Get-Acl -LiteralPath $HtpasswdPath).Sddl
$hasUtf8Bom = (
    $originalBytes.Length -ge 3 -and
    $originalBytes[0] -eq 0xEF -and
    $originalBytes[1] -eq 0xBB -and
    $originalBytes[2] -eq 0xBF
)
$newline = if ($originalText.Contains("`r`n")) { "`r`n" } else { "`n" }
$hasTrailingNewline = $originalText.EndsWith("`n")
$lines = $originalText -split "\r?\n"

if ($hasTrailingNewline) {
    $lines = $lines[0..($lines.Length - 2)]
}

$dittoIndexes = @()
for ($index = 0; $index -lt $lines.Length; $index++) {
    if ($lines[$index] -match '^ditto:') {
        $dittoIndexes += $index
    }
}

if ($dittoIndexes.Count -ne 1) {
    throw "Expected exactly one existing ditto user entry."
}

$otherUserEntries = @(
    $lines |
        Where-Object {
            $_.Trim() -ne "" -and
            -not $_.TrimStart().StartsWith("#") -and
            -not $_.StartsWith("ditto:")
        }
)

$preflightStream = [IO.File]::Open(
    $HtpasswdPath,
    [IO.FileMode]::Open,
    [IO.FileAccess]::ReadWrite,
    [IO.FileShare]::Read
)
$preflightStream.Dispose()

New-Item -ItemType File -Path $stagedPath -Force | Out-Null
Set-RestrictedAcl -Path $stagedPath

try {
    Add-Type -AssemblyName System.Net.Http -ErrorAction Stop
    $runtimeHandler = New-Object System.Net.Http.HttpClientHandler
    $runtimeHandler.UseProxy = $false
    $runtimeHandler.UseDefaultCredentials = $false
    $runtimeClient = New-Object System.Net.Http.HttpClient($runtimeHandler)
    $runtimeClient.Timeout = [TimeSpan]::FromSeconds(20)
    $runtimeClient.Dispose()
    $runtimeHandler.Dispose()
}
catch {
    throw "The local HTTP client is unavailable; no password was requested."
}

$secure = $null
$credential = $null
$password = $null
$passwordBytes = $null
$basicBytes = $null
$basicToken = $null
$hash = $null
$httpClient = $null
$request = $null
$response = $null
$verificationStatus = $null
$thingId = $null
$changeApplied = $false
$keepChange = $false
$resultStatus = "FAILED"
$failure = $null
$stagedVerified = $false
$aclPreserved = $false
$rollbackOutcome = "NOT_REQUIRED"

try {
    $secure = Read-Host "Enter the new nginx password for user ditto" -AsSecureString
    $credential = New-Object System.Net.NetworkCredential("", $secure)
    $password = $credential.Password

    if ([string]::IsNullOrWhiteSpace($password)) {
        throw "The password must not be empty."
    }

    $utf8 = New-Object System.Text.UTF8Encoding($false, $true)
    $passwordBytes = $utf8.GetBytes($password)
    $hash = New-Apr1Hash -OpenSsl $OpenSslPath -Password $password

    if (-not $hash.StartsWith('$apr1$')) {
        throw "OpenSSL did not produce an APR1 password hash."
    }

    $updatedLines = [string[]]$lines.Clone()
    $updatedLines[$dittoIndexes[0]] = "ditto:$hash"

    $nonDittoBefore = @(
        for ($index = 0; $index -lt $lines.Length; $index++) {
            if ($index -ne $dittoIndexes[0]) {
                $lines[$index]
            }
        }
    )
    $nonDittoAfter = @(
        for ($index = 0; $index -lt $updatedLines.Length; $index++) {
            if ($index -ne $dittoIndexes[0]) {
                $updatedLines[$index]
            }
        }
    )

    if (Compare-Object $nonDittoBefore $nonDittoAfter) {
        throw "The update would modify nginx entries other than ditto."
    }

    $updatedText = $updatedLines -join $newline
    if ($hasTrailingNewline) {
        $updatedText += $newline
    }

    $contentBytes = $utf8.GetBytes($updatedText)
    if ($hasUtf8Bom) {
        $bom = [byte[]](0xEF, 0xBB, 0xBF)
        $updatedBytes = New-Object byte[] ($bom.Length + $contentBytes.Length)
        [Array]::Copy($bom, 0, $updatedBytes, 0, $bom.Length)
        [Array]::Copy(
            $contentBytes,
            0,
            $updatedBytes,
            $bom.Length,
            $contentBytes.Length
        )
    }
    else {
        $updatedBytes = $contentBytes
    }

    Write-FileInPlace -Path $stagedPath -Bytes $updatedBytes
    if (-not (Test-ByteEqual ([IO.File]::ReadAllBytes($stagedPath)) $updatedBytes)) {
        throw "The staged replacement could not be verified byte-for-byte."
    }

    $stagedText = [IO.File]::ReadAllText($stagedPath)
    $stagedLines = @($stagedText -split "\r?\n")
    if ($hasTrailingNewline) {
        $stagedLines = $stagedLines[0..($stagedLines.Length - 2)]
    }
    $stagedDittoEntries = @(
        $stagedLines | Where-Object { $_ -match '^ditto:' }
    )
    if ($stagedDittoEntries.Count -ne 1) {
        throw "The staged file does not contain exactly one ditto entry."
    }

    $stagedDitto = $stagedDittoEntries[0].Substring(6)
    if (-not (Test-Apr1Hash `
        -OpenSsl $OpenSslPath `
        -Password $password `
        -ExpectedHash $stagedDitto)) {
        throw "The staged ditto entry failed independent password verification."
    }

    if (-not (Test-ByteEqual ([IO.File]::ReadAllBytes($HtpasswdPath)) $originalBytes)) {
        throw "The active password file changed while staging."
    }
    if ((Get-Acl -LiteralPath $HtpasswdPath).Sddl -ne $targetAclSddl) {
        throw "The active password file permissions changed while staging."
    }

    $stagedVerified = $true
    Write-FileInPlace -Path $HtpasswdPath -Bytes $updatedBytes
    $changeApplied = $true

    if (-not (Test-ByteEqual ([IO.File]::ReadAllBytes($HtpasswdPath)) $updatedBytes)) {
        throw "The active replacement could not be verified byte-for-byte."
    }
    if ((Get-Acl -LiteralPath $HtpasswdPath).Sddl -ne $targetAclSddl) {
        throw "The active password file permissions changed during replacement."
    }
    $aclPreserved = $true

    $basicBytes = New-Object byte[] (6 + $passwordBytes.Length)
    [Text.Encoding]::ASCII.GetBytes('ditto:').CopyTo($basicBytes, 0)
    [Array]::Copy($passwordBytes, 0, $basicBytes, 6, $passwordBytes.Length)
    $basicToken = [Convert]::ToBase64String($basicBytes)

    $handler = New-Object System.Net.Http.HttpClientHandler
    $handler.UseProxy = $false
    $handler.UseDefaultCredentials = $false
    $httpClient = New-Object System.Net.Http.HttpClient($handler)
    $httpClient.Timeout = [TimeSpan]::FromSeconds(20)
    $request = New-Object System.Net.Http.HttpRequestMessage(
        [Net.Http.HttpMethod]::Get,
        $ThingsUri
    )
    $request.Headers.Authorization = New-Object `
        Net.Http.Headers.AuthenticationHeaderValue('Basic', $basicToken)
    $response = $httpClient.SendAsync($request).GetAwaiter().GetResult()
    $verificationStatus = [int]$response.StatusCode

    if ($verificationStatus -eq 200) {
        $body = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        $thing = $body | ConvertFrom-Json
        $thingId = $thing.thingId
        $resultStatus = "AUTH_AND_THING_READ_VERIFIED"
        $keepChange = $true
    }
    elseif ($verificationStatus -eq 403) {
        $resultStatus = "AUTHENTICATION_VERIFIED_THING_ACCESS_BLOCKED"
        $keepChange = $true
    }
    elseif ($verificationStatus -eq 404) {
        $resultStatus = "AUTHENTICATION_VERIFIED_THING_NOT_FOUND"
        $keepChange = $true
    }
    elseif ($verificationStatus -eq 401) {
        $resultStatus = "NGINX_REJECTED_401"
        $keepChange = $false
    }
    else {
        throw "Inconclusive HTTP status after password replacement."
    }
}
catch {
    $failure = $_.Exception.Message
}
finally {
    if ($response) {
        $response.Dispose()
    }
    if ($request) {
        $request.Dispose()
    }
    if ($httpClient) {
        $httpClient.Dispose()
    }
    if ($passwordBytes) {
        [Array]::Clear($passwordBytes, 0, $passwordBytes.Length)
    }
    if ($basicBytes) {
        [Array]::Clear($basicBytes, 0, $basicBytes.Length)
    }
    $basicToken = $null
    $hash = $null
    $password = $null
    $credential = $null
    if ($secure) {
        $secure.Dispose()
    }
}

if ($changeApplied -and -not $keepChange) {
    try {
        Write-FileInPlace -Path $HtpasswdPath -Bytes $originalBytes
        $restoredBytes = [IO.File]::ReadAllBytes($HtpasswdPath)
        $rollbackMatch = Test-ByteEqual $restoredBytes $backupBytes
        $rollbackAclMatch = (
            (Get-Acl -LiteralPath $HtpasswdPath).Sddl -eq $targetAclSddl
        )
        if ($rollbackMatch -and $rollbackAclMatch) {
            $rollbackOutcome = "VERIFIED"
            $resultStatus = "ROLLED_BACK"
        }
        else {
            $rollbackOutcome = "FAILED"
            $resultStatus = "ROLLBACK_FAILED"
            $failure = "Rollback verification failed."
        }
    }
    catch {
        $rollbackOutcome = "FAILED"
        $resultStatus = "ROLLBACK_FAILED"
        $failure = "Rollback failed: " + $_.Exception.Message
    }
}

if (Test-Path -LiteralPath $stagedPath) {
    Remove-Item -LiteralPath $stagedPath -Force
}

$evidencePath = Join-Path `
    "E:\DUK\SEM3\MINI PROJECT\IoMT-Risk-Assessment\output\evidence_runs" `
    "ditto_nginx_auth_reset_$timestamp.json"

$evidence = [ordered]@{
    timestamp_utc = (Get-Date).ToUniversalTime().ToString("o")
    result = $resultStatus
    nginx_container = $NginxContainer
    active_htpasswd_mount_verified = $true
    http_client_preflight = $true
    private_backup_directory = $backupDirectory
    staged_entry_independently_verified = $stagedVerified
    ditto_entry_updated = $changeApplied -and $keepChange
    preserve_other_user_entries = $true
    preserved_other_user_entry_count = $otherUserEntries.Count
    active_file_acl_preserved = $aclPreserved
    authentication_enabled = $true
    devops_gateway_modified = $false
    things_modified = $false
    policies_modified = $false
    mqtt_connections_modified = $false
    verification_uri = $ThingsUri
    verification_http_status = $verificationStatus
    returned_thing_id = $thingId
    rollback_outcome = $rollbackOutcome
    credentials_recorded = $false
    password_hashes_recorded = $false
    failure = $failure
}

New-Item -ItemType Directory -Path (Split-Path $evidencePath -Parent) -Force |
    Out-Null
$evidence | ConvertTo-Json -Depth 5 |
    Set-Content -LiteralPath $evidencePath -Encoding UTF8

Write-Output $resultStatus
Write-Output "HTTP status: $verificationStatus"
if ($thingId) {
    Write-Output "thingId: $thingId"
}
Write-Output "Rollback: $rollbackOutcome"
Write-Output "Evidence: $evidencePath"
Write-Output "Private backup: $backupDirectory"

if (-not $keepChange) {
    exit 1
}
