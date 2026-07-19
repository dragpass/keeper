# Windows distribution

Keeper releases publish one Inno Setup installer to GitHub Releases. WinGet
references that same installer and its SHA-256 digest.

## WinGet

The package identifier is `DragPass.Keeper`:

```powershell
winget install --exact --id DragPass.Keeper
```

Microsoft requires the first package version to be submitted interactively.
After a tagged Keeper release exists, run this once on Windows:

```powershell
winget install Microsoft.WingetCreate
wingetcreate new https://github.com/dragpass/keeper/releases/download/vX.Y.Z/dragpass-keeper.exe
```

Use `DragPass.Keeper` as the package identifier and submit the generated
manifest. Complete the Microsoft CLA and wait for the PR to be merged. Then add
a repository secret named `WINGET_GITHUB_TOKEN`. It must be a GitHub personal
access token accepted by WingetCreate for creating a fork branch and submission
PR. Every later `v*` tag updates the manifest and opens a WinGet PR.

Do not enable the secret before the first package is present in the WinGet
Community Repository. The automated `wingetcreate update` command only updates
an existing package.

## Release prerequisites

- The Inno Setup `AppVersion` is supplied from the `vX.Y.Z` tag.
- The GitHub release must be public before the WinGet Community Repository
  validates the installer URL.
- Public Windows releases should be Authenticode signed. Detached GPG signatures
  verify downloads but do not establish Windows publisher reputation or avoid
  SmartScreen warnings.
