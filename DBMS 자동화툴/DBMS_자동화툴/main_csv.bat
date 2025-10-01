@echo off
setlocal enableextensions enabledelayedexpansion

REM ==================== 콘솔/인코딩 설정(한글깨짐 방지) ====================
REM chcp 65001 >nul

echo [ Main Batch File Start ]

REM ====== 타임스탬프/출력 폴더 생성 ======
set "TS=%date%_%time%"
set "TS=%TS:/=%"
set "TS=%TS::=%"
set "TS=%TS: =0%"
set "OUTDIR=REALoracle_final_report_%TS%"

echo Creating report folder: %OUTDIR%
mkdir "%OUTDIR%" >nul 2>nul
if not exist "%OUTDIR%" (
    echo [ERROR] Failed to create report folder.
    pause
    exit /b 1
)


echo.
echo --- 1. Running win1.bat... ---
call win1.bat

echo.
echo --- 2. Running win2.bat... ---
call win2.bat

echo.
echo --- 3. Running win3.bat... ---
call win3.bat

echo.
echo --- 4. Running win4.bat... ---
call win4.bat

echo.
echo --- 5. Running win5.bat... ---
call win5.bat

echo.
echo --- 6. Running win6.bat... ---
call win6.bat

echo.
echo --- 7. Converting text reports to CSV... ---
powershell -ExecutionPolicy Bypass -File ".\convert_to_csv.ps1" -ReportDir "%CD%\%OUTDIR%"

if %errorlevel% neq 0 (
    echo [ERROR] Failed to create CSV report.
) else (
    echo [SUCCESS] CSV report created successfully.
)

echo.
echo [ Main Batch File End ]
echo All tasks are complete. Reports are saved in "%OUTDIR%" folder.
pause
endlocal