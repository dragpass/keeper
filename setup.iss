[Setup]
AppId={{38599DE5-0295-498E-94DA-EFC66F72F6EB}}
AppName=Dragpass Keeper
AppVersion=1.0
; C:\Program Files\Dragpass
DefaultDirName={commonpf}\Dragpass
OutputBaseFilename=dragpass-keeper
PrivilegesRequired=admin
SolidCompression=yes
WizardStyle=modern
OutputDir=output\windows

[Files]
Source: "dragpass-keeper.exe"; DestDir: "{app}"

[Registry]
Root: HKLM; Subkey: "SOFTWARE\Google\Chrome\NativeMessagingHosts\com.dragpass.keeper"; ValueType: string; ValueName: ""; ValueData: "{app}\com.dragpass.keeper.json"; Flags: uninsdeletekey

[Code]
// Generate the JSON manifest file dynamically.
procedure CurStepChanged(CurStep: TSetupStep);
var
  JsonPath: string;
  JsonContent: TStringList;
  AppPath: string;
begin
  if CurStep = ssPostInstall then
  begin
    // Actual install path (e.g. C:\Program Files\Dragpass).
    AppPath := ExpandConstant('{app}');

    // Escape backslashes (\) as (\\) for the JSON "path" value.
    StringChange(AppPath, '\', '\\');

    // Full path of the JSON file to write.
    JsonPath := ExpandConstant('{app}\com.dragpass.keeper.json');

    // Build JSON file contents dynamically.
    JsonContent := TStringList.Create;
    try
      JsonContent.Add('{');
      JsonContent.Add('  "name": "com.dragpass.keeper",');
      JsonContent.Add('  "description": "Dragpass Device Key Storage",');
      JsonContent.Add('  "path": "' + AppPath + '\\dragpass-keeper.exe",');
      JsonContent.Add('  "type": "stdio",');
      JsonContent.Add('  "allowed_origins": [');
      JsonContent.Add('    "chrome-extension://cmgjlocmnppfpknaipdfodjhbplnhimk/"');
      JsonContent.Add('  ]');
      JsonContent.Add('}');
            
      JsonContent.SaveToFile(JsonPath);
    finally
      JsonContent.Free;
    end;
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  JsonPath: string;
begin
  if CurUninstallStep = usUninstall then
  begin
    JsonPath := ExpandConstant('{app}\com.dragpass.keeper.json');
    DeleteFile(JsonPath);
  end;
end;