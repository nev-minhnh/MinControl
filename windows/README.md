# MinControl Windows agent (M0 skeleton)

Portable .NET 10 SDK lives in `../../tools/dotnet` (outside git). Always source the env first:

    # bash
    source D:/Coding_Project/MinControl/tools/env-dotnet.sh
    # PowerShell
    . D:\Coding_Project\MinControl\tools\env-dotnet.ps1

Build and test (from this folder):

    dotnet build MinControl.sln -c Release
    dotnet test MinControl.sln -c Release

Contract tests (`tests/MinControl.Core.Tests`) walk up to the repo `protocol/` folder and validate all
`fixtures/` against the JSON Schemas (JsonSchema.Net). Never edit schemas/fixtures to make them pass.
`MinControl.Core` must stay platform-neutral (net10.0); the other projects target net10.0-windows.
