param(
    [Parameter(Mandatory)] [string] $StaticSbom,
    [ValidateSet('npm', 'pnpm')] [string] $Manager = 'npm',
    [string] $Script = 'dev',
    [string] $BuildId = $env:SBOM_BUILD_ID,
    [string] $EvidenceDir = (Join-Path ([IO.Path]::GetTempPath()) ('sbom-session-' + [guid]::NewGuid()))
)
$ErrorActionPreference = 'Stop'
$originalOptions = $env:NODE_OPTIONS
$originalFile = $env:SBOM_STATIC_FILE
$originalDirectory = $env:SBOM_EVIDENCE_DIR
$originalBuild = $env:SBOM_BUILD_ID
try {
    if (!$BuildId -and (Get-Command git -ErrorAction SilentlyContinue)) {
        try { $BuildId = git rev-parse --verify HEAD 2>$null } catch { $BuildId = $null }
    }
    $env:SBOM_BUILD_ID = $BuildId
    $env:SBOM_STATIC_FILE = (Resolve-Path -LiteralPath $StaticSbom).Path
    $env:SBOM_EVIDENCE_DIR = [IO.Path]::GetFullPath($EvidenceDir)
    $agent = (Join-Path $PSScriptRoot 'session-agent.cjs').Replace('\', '/')
    $env:NODE_OPTIONS = ($originalOptions + ' --require "' + $agent + '"').Trim()
    Write-Host "Backend evidence: $env:SBOM_EVIDENCE_DIR"
    & "$Manager.cmd" run $Script
    $captureExitCode = $LASTEXITCODE
} finally {
    $env:NODE_OPTIONS = $originalOptions
    $env:SBOM_STATIC_FILE = $originalFile
    $env:SBOM_EVIDENCE_DIR = $originalDirectory
    $env:SBOM_BUILD_ID = $originalBuild
}
exit $captureExitCode
