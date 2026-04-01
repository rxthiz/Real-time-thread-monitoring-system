param(
    [ValidateSet("core", "full")]
    [string]$InfraProfile = "core",
    [switch]$SkipEnv,
    [switch]$SkipDeps,
    [switch]$UseBrokerDeps,
    [switch]$SkipDocker,
    [switch]$SkipMigrate
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Invoke-CheckedNative {
    param(
        [string]$Label,
        [scriptblock]$Action
    )
    & $Action
    if ($LASTEXITCODE -ne 0) {
        throw "$Label failed with exit code $LASTEXITCODE"
    }
}

function Resolve-Python {
    if ($env:VIRTUAL_ENV) {
        $activePython = Join-Path $env:VIRTUAL_ENV "Scripts\python.exe"
        if (Test-Path $activePython) {
            return $activePython
        }
    }
    $venvPython = Join-Path $PSScriptRoot "..\.venv\Scripts\python.exe"
    $venvPython = [System.IO.Path]::GetFullPath($venvPython)
    if (Test-Path $venvPython) {
        return $venvPython
    }
    return "python"
}

function Test-PythonModule {
    param(
        [string]$PythonExe,
        [string]$ModuleName
    )
    & $PythonExe -c "import importlib.util,sys;sys.exit(0 if importlib.util.find_spec('$ModuleName') else 1)" *> $null
    return $LASTEXITCODE -eq 0
}

function Ensure-Pip {
    param([string]$PythonExe)
    if (-not (Test-PythonModule -PythonExe $PythonExe -ModuleName "pip")) {
        Write-Host "Module 'pip' missing. Bootstrapping pip with ensurepip..."
        Invoke-CheckedNative -Label "python -m ensurepip --upgrade" -Action { & $PythonExe -m ensurepip --upgrade }
    }
}

function Ensure-PythonModule {
    param(
        [string]$PythonExe,
        [string]$ModuleName,
        [string]$PackageName = ""
    )
    $pkg = if ([string]::IsNullOrWhiteSpace($PackageName)) { $ModuleName } else { $PackageName }
    if (-not (Test-PythonModule -PythonExe $PythonExe -ModuleName $ModuleName)) {
        Write-Host "Module '$ModuleName' missing. Installing package '$pkg'..."
        Ensure-Pip -PythonExe $PythonExe
        Invoke-CheckedNative -Label "python -m pip install $pkg" -Action { & $PythonExe -m pip install $pkg }
    }
}

$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
Set-Location $projectRoot

Write-Step "Project root: $projectRoot"

if (-not $SkipEnv) {
    Write-Step "Preparing .env"
    $envFile = Join-Path $projectRoot ".env"
    $envExample = Join-Path $projectRoot ".env.example"
    if (-not (Test-Path $envExample)) {
        throw ".env.example not found at $envExample"
    }
    if (-not (Test-Path $envFile)) {
        Copy-Item -Path $envExample -Destination $envFile
        Write-Host "Created .env from .env.example"
    } else {
        Write-Host ".env already exists, keeping current values"
    }
}

$pythonExe = Resolve-Python
Write-Step "Using Python: $pythonExe"

if (-not $SkipDeps) {
    Write-Step "Installing Python dependencies"
    Ensure-Pip -PythonExe $pythonExe
    Invoke-CheckedNative -Label "python -m pip install --upgrade pip" -Action { & $pythonExe -m pip install --upgrade pip }
    Invoke-CheckedNative -Label "python -m pip install -r requirements.txt" -Action { & $pythonExe -m pip install -r requirements.txt }
    if ($UseBrokerDeps) {
        Invoke-CheckedNative -Label "python -m pip install -r requirements-broker.txt" -Action { & $pythonExe -m pip install -r requirements-broker.txt }
    }
}

if (-not $SkipDocker) {
    Write-Step "Starting Docker infra ($InfraProfile)"
    $null = Get-Command docker -ErrorAction Stop
    if ($InfraProfile -eq "full") {
        Invoke-CheckedNative -Label "docker compose up (full)" -Action { docker compose up -d postgres redis rabbitmq zookeeper kafka }
    } else {
        Invoke-CheckedNative -Label "docker compose up (core)" -Action { docker compose up -d postgres redis }
    }
}

if (-not $SkipMigrate) {
    Write-Step "Running database migrations"
    Ensure-PythonModule -PythonExe $pythonExe -ModuleName "alembic" -PackageName "alembic"
    Invoke-CheckedNative -Label "python -m alembic upgrade head" -Action { & $pythonExe -m alembic upgrade head }
}

Write-Step "Bootstrap complete"
Write-Host "Start API:    uvicorn api.main:app --host 127.0.0.1 --port 8000"
Write-Host "Start worker: python workers/alert_worker.py"
