REM @echo off
setlocal

REM =========================================================
REM Build uhttps in 4 flavors: {x64,x86} x {DYNAMIC, STATIC}
REM - DYNAMIC: /MD + dynamic OpenSSL via DLLs (keep win-dyn-load-tls.c)
REM - STATIC : /MT + static OpenSSL (libssl_static.lib, libcrypto_static.lib)
REM            and bypass DLL loading (define UHTTPS_OPENSSL_STATIC)
REM =========================================================


REM ==== Config section ====

REM ===== Visual Studio vcvarsall path =====
set "VSVCVARS=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat"
 REM Use /MD for dynamic CRT (small exe + needs vcruntime DLLs)
set "CRT=/MT"      
set "OPENSSL32_INC=C:\Program Files (x86)\OpenSSL-Win32\include"
set "OPENSSL32_BIN=C:\Program Files (x86)\OpenSSL-Win32\bin"
set "OPENSSL32_LIB=C:\Program Files (x86)\OpenSSL-Win32\lib\VC\static\MT"

set "OPENSSL64_INC=C:\Program Files\OpenSSL-Win64\include"
set "OPENSSL64_BIN=C:\Program Files\OpenSSL-Win64\bin"
set "OPENSSL64_LIB=C:\Program Files\OpenSSL-Win64\lib\VC\static\MT"

set "OUTDIR=WindowsBinaries"
set "SOURCES=uhttps.c log.c cmd_line.c win-dyn-load-tls.c addrs2txt.c"
set "RCFILE=uhttps.rc"

set SIGNTOOL="C:\Program Files (x86)\Windows Kits\10\App Certification Kit\signtool.exe"
set SIGN_CERT_THUMBPRINT=8c9500b6640c811005fb8cb7bbf6848cfac2e3ea

REM ========================


REM -- Check thumbprint --
if "%SIGN_CERT_THUMBPRINT%"=="" (
    echo [ERROR] SIGN_CERT_THUMBPRINT is not defined. Please set it before running this script.
    exit /b 1
)

if not exist "%OUTDIR%" mkdir "%OUTDIR%"

call :build one x64 DYNAMIC "/MD" "%OPENSSL64_INC%" "%OPENSSL64_LIB%" "%OPENSSL64_BIN%" "%OUTDIR%\uhttps64.exe" || goto :eof
call :build one x86 DYNAMIC "/MD" "%OPENSSL32_INC%" "%OPENSSL32_LIB%" "%OPENSSL32_BIN%" "%OUTDIR%\uhttps32.exe" || goto :eof
call :build one x64 STATIC  "/MT" "%OPENSSL64_INC%" "%OPENSSL64_LIB%" "%OPENSSL64_BIN%" "%OUTDIR%\uhttps64-nodll.exe" || goto :eof
call :build one x86 STATIC  "/MT" "%OPENSSL32_INC%" "%OPENSSL32_LIB%" "%OPENSSL32_BIN%" "%OUTDIR%\uhttps32-nodll.exe" || goto :eof


echo.
echo ==== Build complete ====
endlocal
goto :eof

:build
REM Args:
REM  %2=>arch (x64|x86)
REM  %3=>flavor (DYNAMIC|STATIC)
REM  %4=>crt (/MD or /MT)
REM  %5=>OPENSSL_INC
REM  %6=>OPENSSL_LIB
REM  %7=>OPENSSL_BIN
REM  %8=>OUTEXE
setlocal
set "ARCH=%~2"
set "FLAVOR=%~3"
set "CRT=%~4"
set "OPENSSL_INC=%~5"
set "OPENSSL_LIB=%~6"
set "OPENSSL_BIN=%~7"
set "OUTEXE=%~8"

echo.
echo --- Building %ARCH% %FLAVOR% (%CRT%) ---
call "%VSVCVARS%" %ARCH%
echo on
if errorlevel 1 (echo [ERROR] vcvarsall failed for %ARCH% & endlocal & exit /b 1)

if not exist "%RCFILE%" (
  echo [ERROR] "%RCFILE%" not found.
  endlocal & exit /b 1
)

REM Compile resource
rc /nologo /fo uhttps.res "%RCFILE%"
if errorlevel 1 (echo [ERROR] rc failed for %ARCH% %FLAVOR% & endlocal & exit /b 1)

REM Select sources & linker inputs per flavor
set "LDFLAGS=/link /DYNAMICBASE /NXCOMPAT /guard:cf /INCREMENTAL:NO /OPT:REF /OPT:ICF"
set "LIBS=ws2_32.lib iphlpapi.lib user32.lib crypt32.lib bcrypt.lib"
set "CDEFS=/DWIN32_LEAN_AND_MEAN /D_CRT_SECURE_NO_WARNINGS"
set "INCLUDES=/I "%OPENSSL_INC%""
set "LIBPATH=/LIBPATH:"%OPENSSL_LIB%""

if /I "%FLAVOR%"=="DYNAMIC" (
    echo on
    REM Dynamic OpenSSL: keep dynamic loader source, do NOT link libssl/libcrypto directly.
    set "CDEFS=%CDEFS% /DUHTTPS_OPENSSL_DYNAMIC=1"    
) else (
    REM Static OpenSSL: define a macro to bypass DLL loading and link static libs
    set "LIBS=%LIBS% libssl_static.lib libcrypto_static.lib"
)

REM Compile + link
echo on
cl /nologo /W4 /O2 %CRT% /Gy /Zc:inline ^
   %CDEFS% %INCLUDES% ^
   /Fe:"%OUTEXE%" ^
   %SOURCES% uhttps.res^
   %LDFLAGS% ^
   %LIBPATH% ^
   %LIBS%
if errorlevel 1 (echo [ERROR] build failed for %ARCH% %FLAVOR% & endlocal & exit /b 1)

REM Clean intermediates for this pass
del /q *.obj *.exp *.lib *.res >nul 2>&1
echo on
REM Sign executable
echo %SIGNTOOL%
if not exist %SIGNTOOL% (
  echo [WARN] signtool not found at: %SIGNTOOL%
) else (
  if "%SIGN_CERT_THUMBPRINT%"=="" (
    echo [WARN] SIGN_CERT_THUMBPRINT not set; skipping signing for %OUTEXE%
  ) else (
    echo Signing "%OUTEXE%"
    %SIGNTOOL% sign /sha1 %SIGN_CERT_THUMBPRINT% /tr http://time.certum.pl /td sha256 /fd sha256 /v "%OUTEXE%"
    if errorlevel 1 (echo [ERROR] signing failed: %OUTEXE% & endlocal & exit /b 1)
  )
)

echo Built: "%OUTEXE%"
if /I "%FLAVOR%"=="DYNAMIC" (
  echo To run: set UHTTPS_OPENSSL_DIR=%OPENSSL_BIN%
) else (
  echo Static build: no OpenSSL DLLs required.
)

endlocal

exit /b 0

