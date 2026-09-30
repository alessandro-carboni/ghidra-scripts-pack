$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
    Push-Location web
    try {
        npm.cmd ci
        if ($LASTEXITCODE -ne 0) { throw 'npm ci failed' }
        npm.cmd run format
        if ($LASTEXITCODE -ne 0) { throw 'web format failed' }
        npm.cmd run build
        if ($LASTEXITCODE -ne 0) { throw 'web build failed' }
        npm.cmd test
        if ($LASTEXITCODE -ne 0) { throw 'web tests failed' }
    } finally { Pop-Location }
    dotnet restore GhidraTriage.Gui.sln
    if ($LASTEXITCODE -ne 0) { throw 'restore failed' }
    dotnet format GhidraTriage.Gui.sln --no-restore
    if ($LASTEXITCODE -ne 0) { throw 'format failed' }
    dotnet build GhidraTriage.Gui.sln -c Debug --no-restore
    if ($LASTEXITCODE -ne 0) { throw 'build failed' }
    dotnet test GhidraTriage.Gui.sln -c Debug --no-build
    if ($LASTEXITCODE -ne 0) { throw 'tests failed' }
    git diff --check
    if ($LASTEXITCODE -ne 0) { throw 'diff check failed' }
} finally { Pop-Location }
