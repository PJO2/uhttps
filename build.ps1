# build-uhttps.ps1
# PowerShell version of your batch build

# ---------- Config ----------
$VSVCVARS  = 'C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat'

# OpenSSL (adjust LIB paths to where your static libs live)
$OPENSSL32_INC = 'C:\Program Files (x86)\OpenSSL-Win32\include'
$OPENSSL32_BIN = 'C:\Program Files (x86)\OpenSSL-Win32\bin'
$OPENSSL32_LIB = 'C:\Program Files (x86)\OpenSSL-Win32\lib\VC\x86'  # do not add MT or MD

$OPENSSL64_INC = 'C:\Program Files\OpenSSL-Win64\include'
$OPENSSL64_BIN = 'C:\Program Files\OpenSSL-Win64\bin'
$OPENSSL64_LIB = 'C:\Program Files\OpenSSL-Win64\lib\VC\x64'  # do not add MT or MD

$OUTDIR   = 'WindowsBinaries'
$RCFILE   = 'uhttps.rc'
$SOURCES  = 'uhttps.c log.c cmd_line.c win-dyn-load-tls.c addrs2txt.c'  

# Signing (optional)
$SignTool = 'C:\Program Files (x86)\Windows Kits\10\App Certification Kit\signtool.exe'
$Thumb    = '8c9500b6640c811005fb8cb7bbf6848cfac2e3ea'  # SHA1 thumbprint; leave empty to skip signing
# ----------------------------

if (!(Test-Path $OUTDIR)) { New-Item -ItemType Directory -Path $OUTDIR | Out-Null }
if (!(Test-Path $RCFILE)) { throw "RC file not found: $RCFILE" }

function Invoke-Build {
    param(
        [Parameter(Mandatory)] [ValidateSet('x64','x86')] $Arch,
        [Parameter(Mandatory)] [ValidateSet('DYNAMIC','STATIC')] $Flavor,
        [Parameter(Mandatory)] [ValidateSet('/MD','/MT')] $CRT,
        [Parameter(Mandatory)] [string] $OPENSSL_INC,
        [Parameter(Mandatory)] [string] $OPENSSL_LIB,
        [Parameter(Mandatory)] [string] $OPENSSL_BIN,
        [Parameter(Mandatory)] [string] $OutExe
    )

    Write-Host "`n--- Building $Arch $Flavor ($CRT) ---"

    # Common flags
    $cdefs   = '/DWIN32_LEAN_AND_MEAN /D_CRT_SECURE_NO_WARNINGS'
    $libs    = 'ws2_32.lib iphlpapi.lib user32.lib crypt32.lib bcrypt.lib'
    $ldflags = '/link /DYNAMICBASE /NXCOMPAT /guard:cf /INCREMENTAL:NO /OPT:REF /OPT:ICF'
    $includes = "/I `"$OPENSSL_INC`""
    $crtpath = $crt.SubString(1)
    $libpath  = "/LIBPATH:`"$OPENSSL_LIB\$crtpath`""

    if ($Flavor -eq 'DYNAMIC') {
        # Keep dyn loader; just mark it if you branch behavior by macro
        $cdefs += ' /DUHTTPS_OPENSSL_DYNAMIC=1'
        # No libssl/libcrypto added here (LoadLibrary path)
    } else {
        # Static OpenSSL link
        $libs  += ' libssl_static.lib libcrypto_static.lib'
        # If you hit unresolved externals, you may need: advapi32.lib zlibstatic.lib
        $libs  += ' advapi32.lib zlibstatic.lib'
    }

    # Build one pass inside a fresh cmd.exe so vcvarsall doesn't pollute the PS session
    $cmd = @(
        "call `"$VSVCVARS`" $Arch"
        "rc /nologo /fo uhttps.res `"$RCFILE`""
        # cl note: /LIBPATH must be AFTER /link
        $cmdLine = "cl /nologo /W4 /O2 $CRT /Gy /Zc:inline $cdefs $includes /Fe:`"$OutExe`" $SOURCES uhttps.res $ldflags $libpath $libs"
        Write-Host $cmdLine -ForegroundColor Cyan
        "cl /nologo /W4 /O2 $CRT /Gy /Zc:inline $cdefs $includes /Fe:`"$OutExe`" $SOURCES uhttps.res $ldflags $libpath $libs"
        # Clean intermediates (quiet)
        "del /q *.obj *.exp *.lib *.res 2>nul"
    ) -join " && "

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = 'cmd.exe'
    $psi.Arguments = "/c $cmd"
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $p = [System.Diagnostics.Process]::Start($psi)
    $stdOut = $p.StandardOutput.ReadToEnd()
    $stdErr = $p.StandardError.ReadToEnd()
    $p.WaitForExit()

    if ($stdOut) { Write-Host $stdOut }
    if ($stdErr) { Write-Host $stdErr -ForegroundColor Yellow }

    if ($p.ExitCode -ne 0) {
        throw "[ERROR] Build failed for $Arch $Flavor (exit $($p.ExitCode))"
    }

    # Sign (optional)
    if ($Thumb -and (Test-Path $SignTool)) {
        Write-Host "Signing $OutExe"
        & "$SignTool" sign /sha1 $Thumb /tr http://time.certum.pl /td sha256 /fd sha256 /v "$OutExe"
        if ($LASTEXITCODE -ne 0) { throw "[ERROR] Signing failed: $OutExe" }
    } else {
        if (-not (Test-Path $SignTool)) { Write-Host "[WARN] signtool not found at $SignTool; skipping signing." -ForegroundColor Yellow }
        if (-not $Thumb) { Write-Host "[WARN] SIGN_CERT_THUMBPRINT not set; skipping signing." -ForegroundColor Yellow }
    }

    if ($Flavor -eq 'DYNAMIC') {
        Write-Host "To run: set UHTTPS_OPENSSL_DIR=$OPENSSL_BIN`n"
    } else {
        Write-Host "Static build: no OpenSSL DLLs required.`n"
    }
}

# ---- Build matrix ----
Invoke-Build -Arch x64 -Flavor DYNAMIC -CRT /MD -OPENSSL_INC $OPENSSL64_INC -OPENSSL_LIB $OPENSSL64_LIB -OPENSSL_BIN $OPENSSL64_BIN -OutExe (Join-Path $OUTDIR 'uhttps64.exe')
Invoke-Build -Arch x86 -Flavor DYNAMIC -CRT /MD -OPENSSL_INC $OPENSSL32_INC -OPENSSL_LIB $OPENSSL32_LIB -OPENSSL_BIN $OPENSSL32_BIN -OutExe (Join-Path $OUTDIR 'uhttps32.exe')
Invoke-Build -Arch x64 -Flavor STATIC  -CRT /MT -OPENSSL_INC $OPENSSL64_INC -OPENSSL_LIB $OPENSSL64_LIB -OPENSSL_BIN $OPENSSL64_BIN -OutExe (Join-Path $OUTDIR 'uhttps64-nodll.exe')
Invoke-Build -Arch x86 -Flavor STATIC  -CRT /MT -OPENSSL_INC $OPENSSL32_INC -OPENSSL_LIB $OPENSSL32_LIB -OPENSSL_BIN $OPENSSL32_BIN -OutExe (Join-Path $OUTDIR 'uhttps32-nodll.exe')

Write-Host "`n==== Build complete ===="
