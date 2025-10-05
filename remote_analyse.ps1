param(
  [string]$RemoteHost = "172.24.8.6",
  [int]   $Port       = 22,
  [string]$RemoteUser = "sixsquare",
  [string]$ProjWin    = "",
  [string]$RemoteDir  = "/home/sixsquare/codeQL",
  [string]$SecurityDir  = "/home/sixsquare/.codeql/packages/codeql/python-queries/1.6.5/Security",
  [string]$Cwes         = "022,078",
  [string]$OutWin       = "",
  [string[]]$RemotePathPrepend = @('/home/sixsquare/codeql', '/home/sixsquare/.local/bin')
)
$ErrorActionPreference = "Stop"

if (-not (Get-Command scp -ErrorAction SilentlyContinue)) { throw "OpenSSH scp not found (install OpenSSH Client in Windows Features)." }
if (-not (Get-Command ssh -ErrorAction SilentlyContinue)) { throw "OpenSSH ssh not found (install OpenSSH Client in Windows Features)." }

$ProjWinNorm = $ProjWin.Trim('"').TrimEnd('\','/')
if (-not (Test-Path -LiteralPath $ProjWinNorm)) { throw "ProjWin not found: $ProjWinNorm" }
$ProjWinResolved = (Resolve-Path -LiteralPath $ProjWinNorm).Path

$ProjectName = Split-Path -Leaf $ProjWinResolved

if (-not (Test-Path -LiteralPath $OutWin)) { New-Item -ItemType Directory -Force -Path $OutWin | Out-Null }
$OutWinResolved = (Resolve-Path -LiteralPath $OutWin).Path.TrimEnd('\')

$RemoteProjRoot = "$RemoteDir/projects"
$RemoteProjDir  = "$RemoteProjRoot/$ProjectName"
$RemoteResRoot  = "$RemoteDir/result"
$RemoteResDir   = "$RemoteResRoot/$ProjectName"
$RemoteDbDir    = "$RemoteDir/testing_db"

$Target = "$($RemoteUser)@$($RemoteHost)"

Write-Host "==> Prepare remote dirs..."
ssh -p $Port $Target "mkdir -p '$RemoteProjRoot' '$RemoteResRoot' '$RemoteDbDir' && rm -rf '$RemoteProjDir'"

Write-Host "==> Upload project: $ProjWinResolved  ->  $RemoteProjRoot/"
scp -r -P $Port -C "$ProjWinResolved" "$($Target):$RemoteProjRoot/"

$remoteCmd = @'
set -Eeuo pipefail
. ~/.profile  2>/dev/null || true
. ~/.bashrc   2>/dev/null || true
export CODEQL_ALLOW_INSTALLATION_ANYWHERE=true
export PATH="__PATH_PREPEND__:$PATH"

mkdir -p __OUT_DIR__

cd __REMOTE_DIR__
source .venv/bin/activate
chmod +x ./is_cwe_testing.sh 2>/dev/null || true

echo '===== RUN is_cwe_testing.sh ====='
set -x
./is_cwe_testing.sh \
  --project __REMOTE_PROJ_DIR__/ \
  --cwe __CWES__ \
  --security-dir __SECURITY_DIR__ \
  --db-dir __REMOTE_DB_DIR__/ \
  --out __OUT_DIR__/ \
  --overwrite
set +x

echo '===== OUTPUT TREE ====='
ls -la __OUT_DIR__ || true
'@
$prependJoined = ($RemotePathPrepend -join ':')
$tokens = @{
  '__REMOTE_DIR__'      = $RemoteDir
  '__REMOTE_PROJ_DIR__' = $RemoteProjDir
  '__REMOTE_DB_DIR__'   = $RemoteDbDir
  '__SECURITY_DIR__'    = $SecurityDir
  '__CWES__'            = $Cwes
  '__OUT_DIR__'         = $RemoteResRoot
  '__PATH_PREPEND__'    = $prependJoined
}

foreach ($k in $tokens.Keys) {
  $remoteCmd = $remoteCmd.Replace($k, $tokens[$k])
}
$remoteCmd = $remoteCmd -replace "`r", ""

if ($remoteCmd -match '__[A-Z0-9_]+__') {
  throw "Template token not replaced: $($matches[0])"
}

$remoteCmd | ssh -p $Port $Target 'bash -s'

Write-Host "==> Download results: $OutOnRemote -> $OutWinResolved"
scp -r -P $Port -C "$($Target):$RemoteResDir" "$OutWinResolved"
