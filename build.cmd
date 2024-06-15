@echo off

set GCC_BIN=
where /q gcc.exe
if %ERRORLEVEL%==0 (
	set GCC_BIN=gcc
)
if "%GCC_BIN%"=="" (
    echo "Cannot find g++ binary.\n"
    goto END
) else (
    echo "Found GCC binary.\n"
)
set CFLAGS=""

set BUILD_FLAGS=""
@REM set BUILD_FLAGS=""

%GCC_BIN% main.c -o main.exe -lversion
if %ERRORLEVEL%==0 (
	echo "Done!"
)
:ENDs
pause 1