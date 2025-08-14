# PowerShell Script: Install Mosint (Go version) on Windows
# Should be run with user rights, will prompt for Go install if missing

param(
    [switch]$Unattended
)


# Ensure destination bin exists
if (-not (Test-Path $InstallBin)) {
    New-Item -ItemType Directory -Path $InstallBin -Force | Out-Null
}

# Check if mosint is already installed in PATH
if (Get-Command mosint -ErrorAction SilentlyContinue) {
    Write-Host "Mosint is already installed."
    exit 0
}

$InstallBin = Join-Path $env:USERPROFILE "bin"
$MosintBin = Join-Path $InstallBin "mosint.exe"
$configPath = "$HOME\.mosint.yaml"

Write-Host "Mosint not found. Installing Mosint..."


# Function: Test network connectivity (HTTP, then ICMP as fallback)
function Test-NetworkConnectivity {
    # First, try HTTP(S) connection
    try {
        $response = Invoke-WebRequest -Uri "https://www.google.com" -Method Head -UseBasicParsing -TimeoutSec 5
        if ($response.StatusCode -ge 200 -and $response.StatusCode -lt 400) {
            return $true
        } else {
            Write-Host "Warning: Received HTTP status $($response.StatusCode) from google.com."
        }
    } catch {}

    # Fallback: ICMP ping
    try {
        $icmp = Test-Connection -ComputerName "8.8.8.8" -Count 1 -Quiet -ErrorAction SilentlyContinue
        if ($icmp) {
            return $true
        }
    } catch {}

    return $false
}

# Usage
if (-not (Test-NetworkConnectivity)) {
    Write-Host "Error: Unable to connect to the internet (HTTP and ICMP test failed)."
    Write-Host "Please check your network connection or proxy settings, then run this script again."
    exit 1
}


# Check if Go is installed
if (Get-Command go.exe -ErrorAction SilentlyContinue) {
    Write-Host "Go is already installed."
} else {
    Write-Host "Go is not installed."

    if (!$Unattended) {
        $answer = Read-Host "Do you want to install Go now? (y/n)"
        if ($answer -match '^[Nn]$') {
            Write-Host "Go is required to install Mosint. Exiting."
            exit 1
        }
    }

    Write-Host "Opening Go download page in your browser..."
    Start-Process "https://go.dev/dl/"
    Write-Host ("Please download and install Go manually. " + 
        "Restart this script after installation.")
    exit 1
}

# Add InstallBin to PATH temporarily (for session)
if (-not ($env:PATH -split ';' | Where-Object { $_ -eq $InstallBin })) {
    $env:PATH += ";$InstallBin"
    Write-Warning "$InstallBin is not permanently in your PATH."
    Write-Host "You should add it to your PATH for easier access to mosint."
}

# Install Mosint
Write-Host "Installing Mosint..."
$env:GOBIN = $InstallBin
$installCommand = "go install -v github.com/alpkeskin/mosint/v3/cmd/mosint@latest"
Invoke-Expression $installCommand

# Verify installation
if (Test-Path $MosintBin) {
    & "$MosintBin" --version
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Mosint was installed successfully at $MosintBin."
        exit 0
    } else {
        Write-Host "Error: Mosint was installed, but cannot be used. Manual intervention needed."
        exit 1
    }
} else {
    Write-Host "Mosint binary was not found at $MosintBin. Manual intervention needed."
    exit 1
}

# Checking for config file
$defaultConfig = @"
services:
  breach_directory_api_key: SET_YOUR_API_KEY_HERE
  emailrep_api_key: SET_YOUR_API_KEY_HERE
  hunter_api_key: SET_YOUR_API_KEY_HERE
  intelx_api_key: SET_YOUR_API_KEY_HERE
  haveibeenpwned_api_key: SET_YOUR_API_KEY_HERE

settings:
  intelx_max_results: 20
"@

if (Test-Path -Path $configPath -PathType Leaf) {
    Write-Host ".mosint.yaml was found."
} else {
    Write-Host ".mosint.yaml config file was not found. Creating a default one in $HOME"
    # Create the file with the default content
    $defaultConfig | Out-File -FilePath $configPath -Encoding utf8
}