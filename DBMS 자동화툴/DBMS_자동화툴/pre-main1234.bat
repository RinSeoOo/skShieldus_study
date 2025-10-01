@echo off
echo [ Main Batch File Start ]

REM ====== Ÿ�ӽ�����/��� ���� �� ���� ======
set "TS=%date%_%time%"
set "TS=%TS:/=%"
set "TS=%TS::=%"
set "TS=%TS: =0%"
set "OUTDIR=REALoracle_final_report_%TS%"

echo Creating report folder: %OUTDIR%
mkdir "%OUTDIR%" >nul 2>nul


echo.
echo --- 1. win1.bat ���� ---
call win1.bat

echo.
echo --- 2. win2.bat ���� ---
call win2.bat

echo.
echo --- 3. win3.bat ���� ---
call win3.bat

echo.
echo --- 4. win4.bat ���� ---
call win4.bat

echo.
echo --- 5. win5.bat ���� ---
call win5.bat

echo.
echo --- 6. win6.bat ���� ---
call win6.bat

echo.
echo [ Main Batch File End ]
pause