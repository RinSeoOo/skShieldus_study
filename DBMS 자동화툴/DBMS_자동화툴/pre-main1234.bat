@echo off
echo [ Main Batch File Start ]

REM ====== 타임스탬프/출력 폴더 및 파일 ======
set "TS=%date%_%time%"
set "TS=%TS:/=%"
set "TS=%TS::=%"
set "TS=%TS: =0%"
set "OUTDIR=REALoracle_final_report_%TS%"

echo Creating report folder: %OUTDIR%
mkdir "%OUTDIR%" >nul 2>nul


echo.
echo --- 1. win1.bat 실행 ---
call win1.bat

echo.
echo --- 2. win2.bat 실행 ---
call win2.bat

echo.
echo --- 3. win3.bat 실행 ---
call win3.bat

echo.
echo --- 4. win4.bat 실행 ---
call win4.bat

echo.
echo --- 5. win5.bat 실행 ---
call win5.bat

echo.
echo --- 6. win6.bat 실행 ---
call win6.bat

echo.
echo [ Main Batch File End ]
pause