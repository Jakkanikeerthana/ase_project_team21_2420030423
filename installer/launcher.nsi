; Tiny native launchers (no console window). Built twice: START and STOP.
Unicode true
SilentInstall silent
RequestExecutionLevel user
Icon "app.ico"
!ifdef STOP
  OutFile "build\Stop Adaptive Honeypot.exe"
  Name "Stop Adaptive Honeypot"
!else
  OutFile "build\AdaptiveHoneypot.exe"
  Name "Adaptive Honeypot"
!endif
VIProductVersion "1.0.0.0"
VIAddVersionKey "ProductName" "Adaptive Honeypot"
VIAddVersionKey "FileDescription" "Adaptive Cybersecurity Honeypot launcher"
VIAddVersionKey "FileVersion" "1.0.0"
VIAddVersionKey "ProductVersion" "1.0.0"
VIAddVersionKey "LegalCopyright" "MIT License"

Section
  SetOutPath "$EXEDIR"
!ifdef STOP
  ExecWait '"$EXEDIR\python\pythonw.exe" "$EXEDIR\app\stop.py"'
!else
  Exec '"$EXEDIR\python\pythonw.exe" "$EXEDIR\app\run.py"'
!endif
SectionEnd
