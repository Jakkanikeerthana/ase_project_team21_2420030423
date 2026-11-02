; Adaptive Cybersecurity Honeypot - Windows installer (per-user, no admin rights needed)
Unicode true
!include "MUI2.nsh"
!include "FileFunc.nsh"

!define APPNAME "Adaptive Honeypot"
!define APPID "AdaptiveHoneypot"
!define VERSION "1.0.0"
!define PUBLISHER "Adaptive Honeypot Project"
!define UNINSTKEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPID}"

Name "${APPNAME} ${VERSION}"
OutFile "build\AdaptiveHoneypot-Setup-${VERSION}.exe"
InstallDir "$LOCALAPPDATA\Programs\${APPID}"
InstallDirRegKey HKCU "Software\${APPID}" "InstallDir"
RequestExecutionLevel user
SetCompressor /SOLID lzma
BrandingText "${APPNAME} ${VERSION}"

VIProductVersion "${VERSION}.0"
VIAddVersionKey "ProductName" "${APPNAME}"
VIAddVersionKey "FileDescription" "${APPNAME} Setup"
VIAddVersionKey "FileVersion" "${VERSION}"
VIAddVersionKey "ProductVersion" "${VERSION}"
VIAddVersionKey "LegalCopyright" "MIT License"

!define MUI_ICON "app.ico"
!define MUI_UNICON "app.ico"
!define MUI_WELCOMEFINISHPAGE_BITMAP "wizard.bmp"
!define MUI_UNWELCOMEFINISHPAGE_BITMAP "wizard.bmp"
!define MUI_HEADERIMAGE
!define MUI_HEADERIMAGE_BITMAP "header.bmp"
!define MUI_HEADERIMAGE_RIGHT
!define MUI_ABORTWARNING
!define MUI_WELCOMEPAGE_TITLE "Welcome to ${APPNAME} ${VERSION}"
!define MUI_WELCOMEPAGE_TEXT "This wizard installs the Adaptive Cybersecurity Honeypot: five decoy services, an adaptive learning engine and a web console.$\r$\n$\r$\nEverything (including its own Python runtime) is installed for your user only. No administrator rights and no internet connection are needed.$\r$\n$\r$\nClick Next to continue."
!define MUI_FINISHPAGE_RUN "$INSTDIR\AdaptiveHoneypot.exe"
!define MUI_FINISHPAGE_RUN_TEXT "Launch ${APPNAME} now"
!define MUI_FINISHPAGE_SHOWREADME "$INSTDIR\README.md"
!define MUI_FINISHPAGE_SHOWREADME_TEXT "Open the README"
!define MUI_FINISHPAGE_SHOWREADME_NOTCHECKED

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "..\LICENSE"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH
!insertmacro MUI_LANGUAGE "English"

Section "Install"
  ; stop a running copy before overwriting files
  IfFileExists "$INSTDIR\python\pythonw.exe" 0 +3
    nsExec::Exec '"$INSTDIR\python\pythonw.exe" "$INSTDIR\app\stop.py"'
    Sleep 1500
  SetOutPath "$INSTDIR"
  File "app.ico"
  File "..\README.md"
  File "..\LICENSE"
  File "build\AdaptiveHoneypot.exe"
  File "build\Stop Adaptive Honeypot.exe"
  SetOutPath "$INSTDIR\python"
  File /r "build\python\*.*"
  SetOutPath "$INSTDIR\app"
  File /r /x "__pycache__" "..\app\*.*"
  SetOutPath "$INSTDIR"

  ; shortcuts
  CreateDirectory "$SMPROGRAMS\${APPNAME}"
  CreateShortcut "$SMPROGRAMS\${APPNAME}\${APPNAME}.lnk" "$INSTDIR\AdaptiveHoneypot.exe" "" "$INSTDIR\app.ico"
  CreateShortcut "$SMPROGRAMS\${APPNAME}\Stop ${APPNAME}.lnk" "$INSTDIR\Stop Adaptive Honeypot.exe" "" "$INSTDIR\app.ico"
  CreateShortcut "$SMPROGRAMS\${APPNAME}\Uninstall ${APPNAME}.lnk" "$INSTDIR\Uninstall.exe"
  CreateShortcut "$DESKTOP\${APPNAME}.lnk" "$INSTDIR\AdaptiveHoneypot.exe" "" "$INSTDIR\app.ico"

  ; uninstaller + Apps & features registration (works with Revo Uninstaller too)
  WriteUninstaller "$INSTDIR\Uninstall.exe"
  WriteRegStr HKCU "Software\${APPID}" "InstallDir" "$INSTDIR"
  WriteRegStr HKCU "${UNINSTKEY}" "DisplayName" "${APPNAME}"
  WriteRegStr HKCU "${UNINSTKEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKCU "${UNINSTKEY}" "Publisher" "${PUBLISHER}"
  WriteRegStr HKCU "${UNINSTKEY}" "DisplayIcon" "$INSTDIR\app.ico"
  WriteRegStr HKCU "${UNINSTKEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKCU "${UNINSTKEY}" "UninstallString" '"$INSTDIR\Uninstall.exe"'
  WriteRegStr HKCU "${UNINSTKEY}" "QuietUninstallString" '"$INSTDIR\Uninstall.exe" /S'
  WriteRegStr HKCU "${UNINSTKEY}" "URLInfoAbout" "http://127.0.0.1:8765/"
  WriteRegDWORD HKCU "${UNINSTKEY}" "NoModify" 1
  WriteRegDWORD HKCU "${UNINSTKEY}" "NoRepair" 1
  ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
  IntFmt $0 "0x%08X" $0
  WriteRegDWORD HKCU "${UNINSTKEY}" "EstimatedSize" "$0"
SectionEnd

Section "Uninstall"
  ; stop the app so files are not locked
  IfFileExists "$INSTDIR\python\pythonw.exe" 0 +3
    nsExec::Exec '"$INSTDIR\python\pythonw.exe" "$INSTDIR\app\stop.py"'
    Sleep 2000
  Delete "$DESKTOP\${APPNAME}.lnk"
  RMDir /r "$SMPROGRAMS\${APPNAME}"
  RMDir /r "$INSTDIR\python"
  RMDir /r "$INSTDIR\app"
  Delete "$INSTDIR\AdaptiveHoneypot.exe"
  Delete "$INSTDIR\Stop Adaptive Honeypot.exe"
  Delete "$INSTDIR\app.ico"
  Delete "$INSTDIR\README.md"
  Delete "$INSTDIR\LICENSE"
  Delete "$INSTDIR\Uninstall.exe"
  RMDir "$INSTDIR"
  DeleteRegKey HKCU "${UNINSTKEY}"
  DeleteRegKey HKCU "Software\${APPID}"
  ; user data (database, logs, reports) - ask, keep by default in silent mode
  IfFileExists "$LOCALAPPDATA\${APPID}\*.*" 0 done
    MessageBox MB_YESNO|MB_ICONQUESTION "Also delete your honeypot data (database, logs, reports) in$\r$\n$LOCALAPPDATA\${APPID}?" /SD IDNO IDNO done
    RMDir /r "$LOCALAPPDATA\${APPID}"
  done:
SectionEnd
