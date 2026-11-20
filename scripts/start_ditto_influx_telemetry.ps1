param(
    [string]$ConfigPath = ""
)

$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
$python = Join-Path $root "venv\Scripts\python.exe"
$control = Join-Path $PSScriptRoot "ditto_influx_link_control.py"
$arguments = @($control, "start")
if ($ConfigPath) {
    $arguments += @("--config", $ConfigPath)
}

& $python @arguments
exit $LASTEXITCODE
