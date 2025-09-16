if "%INCLUDE%"=="" call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x64
cl /nologo /W4 /O2 /MT ^
                  /DWIN32_LEAN_AND_MEAN /D_CRT_SECURE_NO_WARNINGS ^
                  /Fe: WindowsBinaries/uhttps64.exe ^
                  -I "C:\Program Files\OpenSSL-Win64\include" ^
                   uhttps.c log.c cmd_line.c win-dyn-load-tls.c dump_addrs.c ^
                   /link ws2_32.lib  iphlpapi.lib user32.lib crypt32.lib bcrypt.lib ^
                   /DYNAMICBASE /NXCOMPAT /guard:cf /INCREMENTAL:NO /OPT:REF /OPT:ICF
del *.obj
