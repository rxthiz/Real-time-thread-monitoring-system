param(
    [ValidateSet("start", "stop", "status", "restart")]
    [string]$Action = "status",
    [string]$BindHost = "127.0.0.1",
    [int]$Port = 8000
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$logDir = Join-Path $projectRoot "tmp_dev_logs"
$apiPidFile = Join-Path $logDir "api.pid"
$workerPidFile = Join-Path $logDir "worker.pid"

function Resolve-Python {
    if ($env:VIRTUAL_ENV) {
        $active = Join-Path $env:VIRTUAL_ENV "Scripts\python.exe"
        if (Test-Path $active) { return $active }
    }
    foreach ($candidate in @(
        (Join-Path $projectRoot ".venv_local\Scripts\python.exe"),
        (Join-Path $projectRoot ".venv\Scripts\python.exe")
    )) {
        if (Test-Path $candidate) { return $candidate }
    }
    return "python"
}

function Read-Pid([string]$Path) {
    if (-not (Test-Path $Path)) { return $null }
    try {
        return [int](Get-Content -Raw $Path).Trim()
    } catch {
        return $null
    }
}

function Write-Pid([string]$Path, [int]$ProcessId) {
    Set-Content -Path $Path -Value "$ProcessId" -NoNewline
}

function Is-Alive([int]$ProcessId) {
    try {
        $p = Get-Process -Id $ProcessId -ErrorAction Stop
        return $null -ne $p
    } catch {
        return $false
    }
}

function Remove-IfExists([string]$Path) {
    if (Test-Path $Path) { Remove-Item $Path -Force }
}

function Start-ManagedProcess {
    param(
        [string]$Name,
        [string]$PidFile,
        [string]$Exe,
        [string[]]$CmdArgs,
        [string]$OutLog,
        [string]$ErrLog
    )
    $existingPid = Read-Pid $PidFile
    if ($existingPid -and (Is-Alive $existingPid)) {
        Write-Host "$Name already running (PID $existingPid)"
        return
    }
    Remove-IfExists $PidFile
    $proc = Start-Process -FilePath $Exe -ArgumentList $CmdArgs -WorkingDirectory $projectRoot -PassThru -RedirectStandardOutput $OutLog -RedirectStandardError $ErrLog
    Write-Pid -Path $PidFile -ProcessId $proc.Id
    Write-Host "$Name started (PID $($proc.Id))"
}

function Stop-ManagedProcess {
    param(
        [string]$Name,
        [string]$PidFile
    )
    $procId = Read-Pid $PidFile
    if (-not $procId) {
        Write-Host "$Name not running (no PID file)"
        return
    }
    if (-not (Is-Alive $procId)) {
        Write-Host "$Name not running (stale PID $procId)"
        Remove-IfExists $PidFile
        return
    }
    Stop-Process -Id $procId -Force
    Remove-IfExists $PidFile
    Write-Host "$Name stopped (PID $procId)"
}

function Show-Status {
    param(
        [string]$Name,
        [string]$PidFile
    )
    $procId = Read-Pid $PidFile
    if ($procId -and (Is-Alive $procId)) {
        Write-Host ("{0}: running (PID {1})" -f $Name, $procId)
    } elseif ($procId) {
        Write-Host ("{0}: not running (stale PID {1})" -f $Name, $procId)
    } else {
        Write-Host ("{0}: not running" -f $Name)
    }
}

New-Item -ItemType Directory -Path $logDir -Force | Out-Null
$pythonExe = Resolve-Python

switch ($Action) {
    "start" {
        Start-ManagedProcess -Name "api" -PidFile $apiPidFile -Exe $pythonExe -CmdArgs @("-m", "uvicorn", "api.main:app", "--host", $BindHost, "--port", "$Port") -OutLog (Join-Path $logDir "api.out.log") -ErrLog (Join-Path $logDir "api.err.log")
        Start-ManagedProcess -Name "worker" -PidFile $workerPidFile -Exe $pythonExe -CmdArgs @("workers/alert_worker.py") -OutLog (Join-Path $logDir "worker.out.log") -ErrLog (Join-Path $logDir "worker.err.log")
        Write-Host "Logs: $logDir"
    }
    "stop" {
        Stop-ManagedProcess -Name "worker" -PidFile $workerPidFile
        Stop-ManagedProcess -Name "api" -PidFile $apiPidFile
    }
    "restart" {
        Stop-ManagedProcess -Name "worker" -PidFile $workerPidFile
        Stop-ManagedProcess -Name "api" -PidFile $apiPidFile
        Start-ManagedProcess -Name "api" -PidFile $apiPidFile -Exe $pythonExe -CmdArgs @("-m", "uvicorn", "api.main:app", "--host", $BindHost, "--port", "$Port") -OutLog (Join-Path $logDir "api.out.log") -ErrLog (Join-Path $logDir "api.err.log")
        Start-ManagedProcess -Name "worker" -PidFile $workerPidFile -Exe $pythonExe -CmdArgs @("workers/alert_worker.py") -OutLog (Join-Path $logDir "worker.out.log") -ErrLog (Join-Path $logDir "worker.err.log")
        Write-Host "Logs: $logDir"
    }
    default {
        Show-Status -Name "api" -PidFile $apiPidFile
        Show-Status -Name "worker" -PidFile $workerPidFile
        Write-Host "Logs: $logDir"
    }
}
