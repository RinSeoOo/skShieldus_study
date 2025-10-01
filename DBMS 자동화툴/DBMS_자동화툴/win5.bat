@echo off
setlocal enableextensions enabledelayedexpansion

REM ==================== 콘솔/인코딩 설정 ====================
REM chcp 65001 >nul
REM set NLS_LANG=AMERICAN_AMERICA.AL32UTF8
chcp 949 >nul
set NLS_LANG=KOREAN_KOREA.KO16MSWIN949
REM set NLS_LANG=AMERICAN_AMERICA.AL32UTF8
REM 필요 시 chcp 949 / NLS_LANG=KOREAN_KOREA.KO16MSWIN949 사용

REM ==================== 사용자 입력/사전 조건 ====================
REM OS 인증이 안 되면 ORA_CONN을 채워주세요 (예: system/Passw0rd@//127.0.0.1:1521/ORCLPDB1)
REM set ORA_CONN=system/ChangeMe1!@//127.0.0.1:1521/XEPDB1
set "ORA_CONN=c##test/1234@//10.0.8.8:1521/XE"

REM ---- (중요) Oracle 홈/인스턴스 기본값 세팅 ----
if not defined ORACLE_HOME set "ORACLE_HOME=C:\app\Administrator\product\21c\dbhomeXE"
if not defined ORACLE_SID  set "ORACLE_SID=XE"
set "PATH=%ORACLE_HOME%\bin;%PATH%"

REM sqlplus는 5.1 점검에 필수는 아니지만, 기존 포맷 유지
where sqlplus >nul 2>nul || (
  echo [ERROR] sqlplus.exe not found in PATH. Install Oracle Client or add to PATH.
  REM 계속 진행해도 무방하지만, 기존 포맷을 따라 오류만 알리고 종료
  REM 필요 시 exit /b 1 주석 해제
  REM exit /b 1
)

set "REPORT_FILE_5=%CD%\%OUTDIR%\security_report_chapter_5.txt"

REM ======================================================================
REM ==================== 5장. 보안 패치 적용 (엑셀 5.1) ====================
REM  OPatch lsinventory 실행. 하드코딩 경로 사용 + 결과 자동 판정
REM ======================================================================
set "ORA_HOME_HC=C:\app\Administrator\product\21c\dbhomeXE"
set "OPATCH=%ORA_HOME_HC%\OPatch\opatch.bat"
if not exist "%OPATCH%" set "OPATCH=%ORA_HOME_HC%\OPatch\opatch.cmd"
if not exist "%OPATCH%" set "OPATCH=%ORA_HOME_HC%\OPatch\opatch"

set "TMP_OPATCH=%TEMP%\opatch_%RANDOM%.txt"

> "%REPORT_FILE_5%"  echo [5. 보안 패치] (엑셀 '3-1. 진단 결과' 시트 5.1)
>>"%REPORT_FILE_5%" echo =================================================================
>>"%REPORT_FILE_5%" echo ### [5.1] 보안 패치 적용 현황 ^(OPatch lsinventory^)
>>"%REPORT_FILE_5%" echo [판단 기준]
>>"%REPORT_FILE_5%" echo   - 양호: 운영 정책 기준의 최신 RU/CPU 적용
>>"%REPORT_FILE_5%" echo   - 취약: 미적용/구버전 또는 OPatch 실행/부재로 이력 확인 불가
>>"%REPORT_FILE_5%" echo.

echo [INFO] Chapter 5. Security Patch...

if exist "%OPATCH%" (
  >>"%REPORT_FILE_5%" echo [Command]
  >>"%REPORT_FILE_5%" echo   "%OPATCH%" lsinventory -oh "%ORA_HOME_HC%"
  "%OPATCH%" lsinventory -oh "%ORA_HOME_HC%" > "%TMP_OPATCH%" 2>&1

  >>"%REPORT_FILE_5%" echo.
  >>"%REPORT_FILE_5%" echo [원문 출력]
  type "%TMP_OPATCH%" >> "%REPORT_FILE_5%"

  rem --- 자동 판정 ---
  set "EXITCODE=%ERRORLEVEL%"
  set "PATCHCOUNT="
  for /f %%N in ('findstr /R /I /C:"Patch [0-9][0-9][0-9]" "%TMP_OPATCH%" ^| find /c /v ""') do set "PATCHCOUNT=%%N"

  set "NOINT="
  findstr /I /C:"no interim" "%TMP_OPATCH%" >nul && set "NOINT=1"
  findstr /I /C:"There are no Interim patches installed" "%TMP_OPATCH%" >nul && set "NOINT=1"
  REM (선택) 한글/로캘 깨짐 대응 키워드 추가
  findstr /I /C:"Interim 패치가 없" "%TMP_OPATCH%" >nul && set "NOINT=1"

  >>"%REPORT_FILE_5%" echo.
  >>"%REPORT_FILE_5%" echo [진단 결론]
  if not "!EXITCODE!"=="0" (
    >>"%REPORT_FILE_5%" echo 취약 - OPatch 실행 오류로 패치 이력 확인 불가^(EXITCODE=!EXITCODE!^).
  ) else if "!PATCHCOUNT!"=="0" (
    >>"%REPORT_FILE_5%" echo 취약 - 적용된 패치가 확인되지 않음 ^(Interim 0건^).
  ) else if defined NOINT (
    >>"%REPORT_FILE_5%" echo 취약 - ^"There are no Interim patches installed^" 문구 확인됨.
  ) else (
    >>"%REPORT_FILE_5%" echo 정보 - 적용 패치 !PATCHCOUNT!건 확인. 최신 RU/CPU 여부는 운영 정책과 대조 필요.
  )
) else (
  >>"%REPORT_FILE_5%" echo [ERROR] OPatch not found at "%ORA_HOME_HC%\OPatch"
  >>"%REPORT_FILE_5%" echo [진단 결론]
  >>"%REPORT_FILE_5%" echo 취약 - OPatch 도구 부재로 패치 이력 확인 불가.
)

del "%TMP_OPATCH%" >nul 2>nul

echo.
echo [OK] Oracle security report created (5.1 only).
echo    - Folder: "%OUTDIR%"
echo    - Report 5: "security_report_chapter_5.txt"

endlocal
