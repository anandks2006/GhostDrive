; GhostDrive Windows Installer — Inno Setup 6
; ==========================================
; Build:
;   1. poetry run pyinstaller ghostdrive.spec --noconfirm
;   2. iscc installer\GhostDrive.iss
; Output: installer\Output\GhostDrive-<version>-setup.exe
;
; The installer ships the one-dir PyInstaller bundle, creates an optional
; Start-Menu/Desktop shortcut, and registers the app in Programs & Features.
; It deliberately does NOT touch the user's data directory
; (%LOCALAPPDATA%\GhostDrive) so uninstall never deletes a vault.

#define MyAppName "GhostDrive"
#define MyAppVersion "0.1.0-alpha"
#define MyAppPublisher "GhostDrive Project"
#define MyAppURL "https://github.com/ghostdrive/ghostdrive"
#define MyAppExeName "GhostDrive.exe"
#define BuildDir "..\dist\GhostDrive"

[Setup]
AppId={{8F3C6A19-5B7E-4D2C-9A64-2E1C0B7D4F82}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}/issues
VersionInfoVersion={#MyAppVersion}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
; Per-user install: no admin prompt, HKCU-only shortcuts.
PrivilegesRequired=lowest
OutputDir=Output
OutputBaseFilename=GhostDrive-{#MyAppVersion}-setup
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64compatible
ArchitecturesAllowed=x64compatible
UninstallDisplayIcon={app}\{#MyAppExeName}
UninstallDisplayName={#MyAppName}
CloseApplications=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; \
    GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "startup"; Description: "Start GhostDrive when I sign in"; \
    GroupDescription: "Startup:"; Flags: unchecked

[Files]
Source: "{#BuildDir}\*"; DestDir: "{app}"; \
    Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\Recovery Tool (offline)"; \
    Filename: "{app}\{#MyAppExeName}"; Parameters: "restore --help"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; \
    Tasks: desktopicon

[Registry]
; "Start with Windows" — mirrors ghostdrive/platform/autostart.py (HKCU Run).
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; \
    ValueType: string; ValueName: "GhostDrive"; ValueData: """{app}\{#MyAppExeName}"""; \
    Flags: uninsdeletevalue; Tasks: startup

[Run]
Filename: "{app}\{#MyAppExeName}"; \
    Description: "{cm:LaunchProgram,{#MyAppName}}"; \
    Flags: nowait postinstall skipifsilent

[UninstallDelete]
; Only logs/caches inside the install dir — NEVER the user's vault.
Type: files; Name: "{app}\ghostdrive.log"
Type: filesandordirs; Name: "{app}\build_cache"
