param(
    [string]$ComposeFile = "E:\DUK\SEM3\MINI PROJECT\ditto\deployment\docker\docker-compose.yml",
    [string]$ProjectName = "docker",
    [string]$GatewayService = "gateway",
    [string]$GatewayContainer = "docker-gateway-1",
    [string]$BaseUrl = "http://localhost:8080"
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

function Set-RestrictedFileAcl {
    param([Parameter(Mandatory = $true)][string]$Path)

    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $acl = Get-Acl -LiteralPath $Path
    $acl.SetAccessRuleProtection($true, $false)
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $identity,
        "FullControl",
        "Allow"
    )
    $acl.AddAccessRule($rule)
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Wait-GatewayHealthy {
    param(
        [Parameter(Mandatory = $true)][string]$Container,
        [int]$TimeoutSeconds = 120
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)

    while ((Get-Date) -lt $deadline) {
        $health = docker inspect $Container --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' 2>$null

        if ($LASTEXITCODE -eq 0 -and $health -in @("healthy", "running")) {
            return $health
        }

        Start-Sleep -Seconds 2
    }

    throw "Gateway did not become healthy within $TimeoutSeconds seconds."
}

function Test-DevopsAccess {
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [Parameter(Mandatory = $true)][string]$Password
    )

    $token = [Convert]::ToBase64String(
        [Text.Encoding]::UTF8.GetBytes("devops:$Password")
    )
    $headers = @{ Authorization = "Basic $token" }

    try {
        $response = Invoke-WebRequest `
            -Uri $Uri `
            -Method Get `
            -Headers $headers `
            -UseBasicParsing `
            -TimeoutSec 20

        return [pscustomobject]@{
            Succeeded = $true
            StatusCode = [int]$response.StatusCode
            Error = $null
        }
    }
    catch {
        $statusCode = $null
        if ($_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
        }

        return [pscustomobject]@{
            Succeeded = $false
            StatusCode = $statusCode
            Error = $_.Exception.Message
        }
    }
    finally {
        $token = $null
        $headers = $null
    }
}

function Recreate-OriginalGateway {
    & docker compose `
        --project-name $ProjectName `
        -f $ComposeFile `
        up -d --no-deps --force-recreate $GatewayService

    if ($LASTEXITCODE -ne 0) {
        throw "Failed to restore the original gateway configuration."
    }

    Wait-GatewayHealthy -Container $GatewayContainer | Out-Null
}

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw "The docker command is not available in this PowerShell session."
}

if (-not (Test-Path -LiteralPath $ComposeFile -PathType Leaf)) {
    throw "Compose file not found: $ComposeFile"
}

$timestamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssfffZ")
$backupRoot = Join-Path $env:LOCALAPPDATA "IoMT-Lab-Backups\DittoDevOpsReset"
$backupDirectory = Join-Path $backupRoot $timestamp
New-Item -ItemType Directory -Path $backupDirectory -Force | Out-Null

$composeBackup = Join-Path $backupDirectory "docker-compose.yml.bak"
Copy-Item -LiteralPath $ComposeFile -Destination $composeBackup
Set-RestrictedFileAcl -Path $composeBackup

$preStatePath = Join-Path $backupDirectory "gateway-pre-reset.json"
$gatewayInspect = docker inspect $GatewayContainer | ConvertFrom-Json
$preState = [ordered]@{
    collected_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    container_name = $gatewayInspect.Name
    container_id = $gatewayInspect.Id
    image = $gatewayInspect.Config.Image
    image_id = $gatewayInspect.Image
    status = $gatewayInspect.State.Status
    networks = @($gatewayInspect.NetworkSettings.Networks.PSObject.Properties.Name)
    compose_config_file = $ComposeFile
    compose_sha256 = (Get-FileHash -LiteralPath $ComposeFile -Algorithm SHA256).Hash
}
$preState | ConvertTo-Json -Depth 6 |
    Set-Content -LiteralPath $preStatePath -Encoding UTF8
Set-RestrictedFileAcl -Path $preStatePath

$firstSecure = Read-Host "Enter the new Ditto DevOps password" -AsSecureString
$confirmSecure = Read-Host "Confirm the new Ditto DevOps password" -AsSecureString
$firstCredential = New-Object System.Net.NetworkCredential("", $firstSecure)
$confirmCredential = New-Object System.Net.NetworkCredential("", $confirmSecure)
$password = $firstCredential.Password
$confirmation = $confirmCredential.Password

if ([string]::IsNullOrWhiteSpace($password)) {
    throw "The password must not be empty."
}

if ($password -cne $confirmation) {
    throw "The password entries do not match."
}

$overridePath = Join-Path $env:TEMP (
    "ditto-devops-reset-" + [guid]::NewGuid().ToString("N") + ".override.yml"
)
$evidencePath = Join-Path `
    "E:\DUK\SEM3\MINI PROJECT\IoMT-Risk-Assessment\output\evidence_runs" `
    "ditto_devops_access_reset_$timestamp.json"
$previousOverrideValue = $env:DEVOPS_PASSWORD
$verificationSucceeded = $false
$configurationChanged = $false
$gatewayWasRecreated = $false
$failureMessage = $null
$httpStatus = $null

try {
    $env:DEVOPS_PASSWORD = $password
    $uri = "$BaseUrl/api/2/connections?ids-only=true"
    $gateway = docker inspect $GatewayContainer | ConvertFrom-Json
    $currentEnvironmentNames = @(
        $gateway.Config.Env | ForEach-Object { ($_ -split "=", 2)[0] }
    )
    $currentConfigurationHasOverride = (
        $currentEnvironmentNames -contains "DEVOPS_PASSWORD"
    )

    if ($currentConfigurationHasOverride) {
        $existingAccess = Test-DevopsAccess -Uri $uri -Password $password
        $httpStatus = $existingAccess.StatusCode

        if ($existingAccess.Succeeded -and $httpStatus -eq 200) {
            $verificationSucceeded = $true
        }
    }

    if (-not $verificationSucceeded) {
        @'
services:
  gateway:
    environment:
      DEVOPS_PASSWORD: "${DEVOPS_PASSWORD}"
'@ | Set-Content -LiteralPath $overridePath -Encoding ASCII
        Set-RestrictedFileAcl -Path $overridePath

        & docker compose `
            --project-name $ProjectName `
            -f $ComposeFile `
            -f $overridePath `
            up -d --no-deps --force-recreate $GatewayService

        if ($LASTEXITCODE -ne 0) {
            throw "Gateway recreation failed."
        }

        $configurationChanged = $true
        $gatewayWasRecreated = $true
        Wait-GatewayHealthy -Container $GatewayContainer | Out-Null

        $newAccess = Test-DevopsAccess -Uri $uri -Password $password
        $httpStatus = $newAccess.StatusCode

        if (-not $newAccess.Succeeded -or $httpStatus -ne 200) {
            throw (
                "Authenticated connection API verification failed " +
                "with HTTP $httpStatus."
            )
        }

        $verificationSucceeded = $true
    }

    $successEvidence = [ordered]@{
        timestamp_utc = (Get-Date).ToUniversalTime().ToString("o")
        status = "ADMIN_ACCESS_VERIFIED"
        authentication_mechanism = "Ditto DevOps Basic authentication"
        devops_username = "devops"
        endpoint = "$BaseUrl/api/2/connections?ids-only=true"
        http_status = $httpStatus
        gateway_recreated = $gatewayWasRecreated
        existing_gateway_access_verified = (-not $gatewayWasRecreated)
        gateway_connections_modified = $false
        mqtt_connections_activated = $false
        messages_published = $false
        password_recorded = $false
        password_retained_in_container_environment_metadata = $true
        affected_compose_file = $ComposeFile
        affected_compose_backup = $composeBackup
        rollback_procedure = (
            "Run: docker compose --project-name $ProjectName " +
            "-f `"$ComposeFile`" up -d --no-deps --force-recreate $GatewayService. " +
            "This restores the original gateway container configuration and the " +
            "image default DevOps password; only use it with approved handling " +
            "of the default credential."
        )
    }

    New-Item -ItemType Directory -Path (Split-Path $evidencePath -Parent) -Force |
        Out-Null
    $successEvidence | ConvertTo-Json -Depth 5 |
        Set-Content -LiteralPath $evidencePath -Encoding UTF8
}
catch {
    $failureMessage = $_.Exception.Message
}
finally {
    if ($null -eq $previousOverrideValue) {
        Remove-Item Env:DEVOPS_PASSWORD -ErrorAction SilentlyContinue
    }
    else {
        $env:DEVOPS_PASSWORD = $previousOverrideValue
    }

    $password = $null
    $confirmation = $null
    $firstCredential = $null
    $confirmCredential = $null
    $firstSecure.Dispose()
    $confirmSecure.Dispose()
    $basicToken = $null

    if (Test-Path -LiteralPath $overridePath) {
        Remove-Item -LiteralPath $overridePath -Force
    }
}

if (-not $verificationSucceeded) {
    $rollbackRequired = $configurationChanged
    $rollbackSucceeded = (-not $rollbackRequired)

    if ($rollbackRequired) {
        try {
            Recreate-OriginalGateway
            $rollbackSucceeded = $true
        }
        catch {
            $failureMessage = (
                "$failureMessage Rollback also failed: " +
                "$($_.Exception.Message)"
            )
        }
    }

    $failureEvidence = [ordered]@{
        timestamp_utc = (Get-Date).ToUniversalTime().ToString("o")
        status = "FAILED"
        authentication_mechanism = "Ditto DevOps Basic authentication"
        gateway_recreated = $gatewayWasRecreated
        verification_http_status = $httpStatus
        failure = $failureMessage
        rollback_required = $rollbackRequired
        rollback_succeeded = $rollbackSucceeded
        rollback_command = (
            "docker compose --project-name $ProjectName " +
            "-f `"$ComposeFile`" up -d --no-deps --force-recreate $GatewayService"
        )
        secure_backup_directory = $backupDirectory
        password_recorded = $false
    }

    New-Item -ItemType Directory -Path (Split-Path $evidencePath -Parent) -Force |
        Out-Null
    $failureEvidence | ConvertTo-Json -Depth 5 |
        Set-Content -LiteralPath $evidencePath -Encoding UTF8

    Write-Output "RESET_FAILED: $failureMessage"
    Write-Output "Evidence: $evidencePath"
    Write-Output "Secure backup: $backupDirectory"
    exit 1
}

Write-Output "ADMIN_ACCESS_VERIFIED"
Write-Output "Endpoint: $BaseUrl/api/2/connections?ids-only=true"
Write-Output "Evidence: $evidencePath"
Write-Output "Secure backup: $backupDirectory"
