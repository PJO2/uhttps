@echo off
setlocal
REM ==== Config section ====
set "CRT=/MT"       REM Use /MD for dynamic CRT (small exe + needs vcruntime DLLs)
set "VSVCVARS=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat"
set "OPENSSL32_INC=C:\Program Files (x86)\OpenSSL-Win32\include"
set "OPENSSL32_BIN=C:\Program Files (x86)\OpenSSL-Win32\bin"
set "OPENSSL64_INC=C:\Program Files\OpenSSL-Win64\include"
set "OPENSSL64_BIN=C:\Program Files\OpenSSL-Win64\bin"
set "OUTDIR=WindowsBinaries"
set "SOURCES=uhttps.c log.c cmd_line.c win-dyn-load-tls.c addrs2txt.c"
set "RCFILE=uhttps.rc"
REM ========================

if not exist "%OUTDIR%" mkdir "%OUTDIR%"

call :build x64 "%OPENSSL64_INC%" "%OPENSSL64_BIN%" "%OUTDIR%\uhttps64.exe" || goto :eof
call :build x86 "%OPENSSL32_INC%" "%OPENSSL32_BIN%" "%OUTDIR%\uhttps32.exe" || goto :eof

echo.
echo ==== Build complete ====
endlocal
goto :eof

:build
REM Args: %1=arch %2=openssl-include %3=openssl-bin %4=output-exe
setlocal
set "ARCH=%~1"
set "OPENSSL_INC=%~2"
set "OPENSSL_BIN=%~3"
set "OUTEXE=%~4"

echo.
echo --- Building %ARCH% ---

call "%VSVCVARS%" %ARCH%
if errorlevel 1 (echo [ERROR] vcvarsall failed for %ARCH% & endlocal & exit /b 1)

rc /nologo /fo uhttps.res "%RCFILE%"
if errorlevel 1 (echo [ERROR] rc failed for %ARCH% & endlocal & exit /b 1)

cl /nologo /W4 /O2 %CRT% ^
   /DWIN32_LEAN_AND_MEAN /D_CRT_SECURE_NO_WARNINGS ^
   /I "%OPENSSL_INC%" ^
   /Fe:"%OUTEXE%" ^
   %SOURCES% uhttps.res ^
   /link ws2_32.lib iphlpapi.lib user32.lib crypt32.lib bcrypt.lib ^
   /DYNAMICBASE /NXCOMPAT /guard:cf /INCREMENTAL:NO /OPT:REF /OPT:ICF
if errorlevel 1 (echo [ERROR] build failed for %ARCH% & endlocal & exit /b 1)

del /q *.obj *.exp *.lib *.res >nul 2>&1

echo Built: "%OUTEXE%"
echo To run: set UHTTPS_OPENSSL_DIR=%OPENSSL_BIN%
echo         "%OUTEXE%" -v --tls --cert server.crt --key server.key

endlocal
exit /b 0

