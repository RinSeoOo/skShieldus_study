@echo off
setlocal EnableExtensions EnableDelayedExpansion
chcp 65001 >nul
set NLS_LANG=AMERICAN_AMERICA.AL32UTF8

REM === 경로 ===
set "OUTDIR=%OUTDIR%"
mkdir "%OUTDIR%" >nul 2>nul
echo [INFO] 통합 점검 시작 (4.1~4.8). 결과 폴더: "%OUTDIR%"
echo.

REM ==================== 4.1~4.3 실행 ====================
call :RUN_41_43

REM ==================== 4.4 실행 ====================
call :RUN_44

REM ==================== 4.5 실행 ====================
call :RUN_45

REM ==================== 4.6 실행 ====================
call :RUN_46

REM ==================== 4.7 실행 ====================
call :RUN_47

REM ==================== 4.8 실행 ====================
call :RUN_48

echo.
echo [ALL DONE] 4.1~4.8 통합 점검 완료.
echo    - Folder: "%OUTDIR%"
exit /b 0


::==============================================================================
:: 4.1~4.3 (원본 코드 그대로 포함)
::==============================================================================
:RUN_41_43
@echo off
setlocal enableextensions enabledelayedexpansion

REM ======================== ★★★ 중요 사용자 설정 ★★★ ========================
REM OS 인증 오류(ORA-12560)를 방지하려면, 아래 ORA_CONN 변수에 접속 정보를 정확히 입력하고
REM 맨 앞의 REM을 제거하여 주석을 해제해 주세요. 이것이 가장 확실한 방법입니다.
REM 형식: set "ORA_CONN=계정/비밀번호@//DB서버IP:포트/서비스이름"
REM 예시: set "ORA_CONN=system/your_password@//127.0.0.1:1521/XE"
set "ORA_CONN=c##test/1234@//10.0.8.8:1521/XE"

REM Oracle Client(sqlplus.exe) 가 PATH에 있어야 합니다.
where sqlplus >nul 2>nul || (
  echo [ERROR] sqlplus.exe not found in PATH. Install Oracle Client or add to PATH.
  exit /b 1
)

REM ====== 보고서 파일 경로 정의 ======
set "REPORT_FILE_4=%CD%\%OUTDIR%\security_report_chapter_4_1_2_3.txt"

REM ====== 임시 SQL 파일 경로 정의 ======
set "TMP_SQL_4=%TEMP%\ora_ch4_%RANDOM%.sql"

REM ====== ORACLE 환경변수 초기화 ======
set "FOUND_ORACLE_HOME="
set "FOUND_ORACLE="
set "FOUND_TNS_ADMIN_PATH="
set "LISTNER_PATH=C:\app\Administrator\product\21c\homes\OraDB21Home1\network\admin"

REM --- 1단계: 레지스트리에서 ORACLE_HOME 찾기 ---
for /f "tokens=*" %%k in ('reg query "HKLM\SOFTWARE\ORACLE" /reg:64 2^>nul') do (
    if not defined FOUND_ORACLE_HOME (
        for /f "tokens=2,*" %%i in ('reg query "%%k" /v ORACLE_HOME /reg:64 2^>nul ^| findstr /I "ORACLE_HOME"') do (
            set "TEMP_ORACLE_HOME=%%j"
            REM -- 경로 앞의 모든 종류의 공백을 완벽하게 제거합니다.
            for /f "tokens=*" %%x in ("!TEMP_ORACLE_HOME!") do set "FOUND_ORACLE_HOME=%%x"

            REM --- ★★★ 상위 폴더 경로를 새로운 FOUND_ORACLE 변수에 저장 ★★★ ---
            for %%p in ("!FOUND_ORACLE_HOME!") do set "FOUND_ORACLE=%%~dpp"

            REM --- 2단계: ORACLE_HOME을 찾은 키에서 TNS_ADMIN도 찾아보기 ---
            for /f "tokens=2,*" %%a in ('reg query "%%k" /v TNS_ADMIN /reg:64 2^>nul ^| findstr /I "TNS_ADMIN"') do (
                set "TEMP_TNS_ADMIN=%%b"
                REM -- TNS_ADMIN 경로 앞의 공백도 완벽하게 제거합니다.
                for /f "tokens=*" %%y in ("!TEMP_TNS_ADMIN!") do set "FOUND_TNS_ADMIN_PATH=%%y"
            )
        )
    )
)

REM --- 3단계: TNS_ADMIN을 못 찾았으면, 기본 경로로 설정 ---
if not defined FOUND_TNS_ADMIN_PATH (
    if defined FOUND_ORACLE_HOME (
        set "FOUND_TNS_ADMIN_PATH=!FOUND_ORACLE_HOME!\network\admin"
    )
)

REM --- 최종 경로 확인 ---
if not defined FOUND_ORACLE_HOME (
    echo [치명적 오류] 레지스트리에서 ORACLE_HOME을 찾을 수 없습니다. 스크립트를 계속할 수 없습니다.
    pause
    exit /b 1
)
echo  - 찾은 ORACLE_HOME: "!FOUND_ORACLE_HOME!"
echo  - 찾은 설정 파일 경로(TNS_ADMIN): "!FOUND_TNS_ADMIN_PATH!"
echo 상위 경로 (FOUND_ORACLE): "!FOUND_ORACLE!"

REM =================================================================
REM ====== [4.1] 항목 진단을 위해 파일 내용을 미리 검사 ======
REM =================================================================
REM 1. 기본 진단 결과를 '해당 없음'으로 설정 (Windows 환경 적응)
set "HISTORY_CHECK_RESULT=해당 없음: PowerShell 히스토리 파일이 존재하지 않습니다."
set "PS_HISTORY_FILE=%APPDATA%\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"

REM 2. PowerShell 히스토리 파일 존재 여부 및 권한 확인
if exist "!PS_HISTORY_FILE!" (
    REM Everyone, Authenticated Users, Users 그룹에 권한이 부여되었는지 확인
    icacls "!PS_HISTORY_FILE!" | findstr /I /C:"Everyone:" /C:"Authenticated Users:" /C:"BUILTIN\Users:" >nul
    if !errorlevel! equ 0 (
        set "HISTORY_CHECK_RESULT=취약: PowerShell 히스토리 파일에 불필요한 계정(Everyone, Users 등)의 접근 권한이 부여되어 있을 수 있습니다."
    ) else (
        set "HISTORY_CHECK_RESULT=양호: PowerShell 히스토리 파일의 접근 권한이 소유자 위주로 적절하게 설정되어 있습니다."
    )
)

REM =================================================================
REM ====== [4.2] 항목 진단을 위해 파일 내용을 미리 검사 ======
REM =================================================================
REM 1. 기본 진단 결과 설정
set "DB_DIR=!FOUND_ORACLE!\database"
set "INIT_FILE_RESULT=정보 없음: !DB_DIR! 에서 초기화 파일(init*.ora, spfile*.ora)을 찾을 수 없습니다."
set "INIT_FILES_FOUND="

REM 2. 초기화 파일(init*.ora, spfile*.ora) 존재 여부 확인
if exist "!DB_DIR!\spfile*.ora" set "INIT_FILES_FOUND=YES"
if exist "!DB_DIR!\init*.ora" set "INIT_FILES_FOUND=YES"

REM 3. 파일이 존재하면 권한 검사
if defined INIT_FILES_FOUND (
    set "INIT_FILE_RESULT=양호: 초기화 파일의 접근 권한이 적절하게 설정되어 있습니다."
    REM dir 명령으로 찾은 각 파일에 대해 반복
    for /f "tokens=*" %%f in ('dir /b "!DB_DIR!\spfile*.ora" "!DB_DIR!\init*.ora" 2^>nul') do (
        REM Everyone, Authenticated Users, Users 그룹에 권한이 있는지 확인
        icacls "!DB_DIR!\%%f" | findstr /I /C:"Everyone:" /C:"Authenticated Users:" /C:"BUILTIN\Users:" >nul
        if !errorlevel! equ 0 (
            REM 취약점이 발견되면 결과를 설정하고 반복 중단
            set "INIT_FILE_RESULT=취약: 초기화 파일(%%f)에 불필요한 그룹(Everyone, Users 등)의 접근 권한이 있습니다."
            goto :Check4_2_Done
        )
    )
)
:Check4_2_Done

REM =================================================================
REM ====== [4.3] 항목 진단을 위해 파일 내용을 미리 검사 ======
REM =================================================================
REM 1. 기본 진단 결과 설정
set "DB_DIR=!FOUND_ORACLE!\database"
set "PASSWORD_FILE_RESULT=정보 없음: !DB_DIR! 에서 Oracle 패스워드 파일(PWD*.ora)을 찾을 수 없습니다."
set "PWD_FILES_FOUND="

REM 2. 패스워드 파일(PWD*.ora) 존재 여부 확인
for /f "tokens=*" %%f in ('dir /b "!DB_DIR!\PWD*.ora" 2^>nul') do (
    set "PWD_FILES_FOUND=YES"
)

REM 3. 파일이 존재하면 권한 검사
if defined PWD_FILES_FOUND (
    set "PASSWORD_FILE_RESULT=양호: Oracle 패스워드 파일의 접근 권한이 적절하게 설정되어 있습니다."
    REM dir 명령으로 찾은 각 파일에 대해 반복
    for /f "tokens=*" %%f in ('dir /b "!DB_DIR!\PWD*.ora" 2^>nul') do (
        REM Everyone, Authenticated Users, Users 그룹에 권한이 있는지 확인
        icacls "!DB_DIR!\%%f" | findstr /I /C:"Everyone:" /C:"Authenticated Users:" /C:"BUILTIN\Users:" >nul
        if !errorlevel! equ 0 (
            REM 취약점이 발견되면 결과를 설정하고 반복 중단
            set "PASSWORD_FILE_RESULT=취약: Oracle 패스워드 파일(%%f)에 불필요한 그룹(Everyone, Users 등)의 접근 권한이 있습니다."
            goto :Check4_3_Done
        )
    )
)
:Check4_3_Done

REM =================================================================
REM ====== 4장. 환경 파일 점검 진단 SQL 생성 ======
REM =================================================================
> "%TMP_SQL_4%" echo set echo off feedback off verify off pages 999 trimspool on
>>"%TMP_SQL_4%" echo set linesize 120
>>"%TMP_SQL_4%" echo whenever sqlerror continue
>>"%TMP_SQL_4%" echo spool "%REPORT_FILE_4%"
>>"%TMP_SQL_4%" echo prompt [4장. 환경 파일 점검] Oracle DB 보안 점검 자동 진단 보고서
>>"%TMP_SQL_4%" echo prompt =================================================================

REM -- [4.1] SQL*PLUS 명령 히스토리 검사 --
>>"%TMP_SQL_4%" echo prompt
>>"%TMP_SQL_4%" echo prompt ### [4.1] SQL*PLUS 명령 히스토리 검사 ###
>>"%TMP_SQL_4%" echo prompt [판단 기준]
>>"%TMP_SQL_4%" echo prompt  - 양호: 히스토리 파일 접근 권한이 소유자에게만 제한된 경우 (Windows: PowerShell History)
>>"%TMP_SQL_4%" echo prompt  - 취약: 히스토리 파일에 불필요한 사용자/그룹의 접근이 가능한 경우
>>"%TMP_SQL_4%" echo prompt
>>"%TMP_SQL_4%" echo prompt [진단 방법 (Windows)]
>>"%TMP_SQL_4%" echo prompt   - PowerShell 히스토리 파일의 권한을 확인합니다.
>>"%TMP_SQL_4%" echo prompt   - 경로: %APPDATA%\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
>>"%TMP_SQL_4%" echo prompt
>>"%TMP_SQL_4%" echo prompt [OS Command]
>>"%TMP_SQL_4%" echo prompt   host icacls "!PS_HISTORY_FILE!"
>>"%TMP_SQL_4%" echo host icacls "!PS_HISTORY_FILE!"

>>"%TMP_SQL_4%" echo prompt
>>"%TMP_SQL_4%" echo prompt [진단 결론]
REM --- 미리 생성한 진단 결과 변수를 SQL 파일에 기록 ---
>>"%TMP_SQL_4%" echo prompt !HISTORY_CHECK_RESULT!
>>"%TMP_SQL_4%" echo prompt

REM -- [4.2] Initialization 파일 접근 권한 설정 --
>>"%TMP_SQL_4%" echo prompt
>>"%TMP_SQL_4%" echo prompt ### [4.2] Initialization 파일 접근 권한 설정 ###
>>"%TMP_SQL_4%" echo prompt [판단 기준]
>>"%TMP_SQL_4%" echo prompt  - 양호: Administrators, SYSTEM, Owner 그룹 위주로 권한이 설정된 경우
>>"%TMP_SQL_4%" echo prompt  - 취약: 기타 다른 그룹(Everyone, Users 등)에 권한이 부여된 경우
>>"%TMP_SQL_4%" echo prompt
>>"%TMP_SQL_4%" echo prompt [진단 방법 (Windows)]
>>"%TMP_SQL_4%" echo prompt   - 초기화 파일(init*.ora, spfile*.ora)의 권한을 확인합니다.
>>"%TMP_SQL_4%" echo prompt   - 일반적인 경로: !FOUND_ORACLE_HOME!\database
>>"%TMP_SQL_4%" echo prompt
>>"%TMP_SQL_4%" echo prompt [OS Command]
>>"%TMP_SQL_4%" echo prompt   host icacls "!FOUND_ORACLE_HOME!\database\init*.ora"
>>"%TMP_SQL_4%" echo prompt   host icacls "!FOUND_ORACLE_HOME!\database\spfile*.ora"
>>"%TMP_SQL_4%" echo host icacls "!FOUND_ORACLE_HOME!\database\init*.ora"
>>"%TMP_SQL_4%" echo host icacls "!FOUND_ORACLE_HOME!\database\spfile*.ora"
>>"%TMP_SQL_4%" echo prompt
>>"%TMP_SQL_4%" echo prompt [진단 결론]
>>"%TMP_SQL_4%" echo prompt !INIT_FILE_RESULT!
>>"%TMP_SQL_4%" echo prompt

REM -- [4.3] Oracle Password 파일 접근 권한 설정 --
>>"%TMP_SQL_4%" echo prompt
>>"%TMP_SQL_4%" echo prompt ### [4.3] Oracle Password 파일 접근 권한 설정 ###
>>"%TMP_SQL_4%" echo prompt [판단 기준]
>>"%TMP_SQL_4%" echo prompt  - 양호: Administrators, SYSTEM, Owner 그룹 위주로 권한이 설정된 경우
>>"%TMP_SQL_4%" echo prompt  - 취약: 기타 다른 그룹(Everyone, Users 등)에 권한이 부여된 경우
>>"%TMP_SQL_4%" echo prompt
>>"%TMP_SQL_4%" echo prompt [진단 방법 (Windows)]
>>"%TMP_SQL_4%" echo prompt   - Oracle 패스워드 파일(PWD*.ora)의 권한을 확인합니다.
>>"%TMP_SQL_4%" echo prompt   - 일반적인 경로: !FOUND_ORACLE_HOME!\database
>>"%TMP_SQL_4%" echo prompt
>>"%TMP_SQL_4%" echo prompt [OS Command]
>>"%TMP_SQL_4%" echo prompt   host icacls "!FOUND_ORACLE_HOME!\database\PWD*.ora"
>>"%TMP_SQL_4%" echo host icacls "!FOUND_ORACLE_HOME!\database\PWD*.ora"
>>"%TMP_SQL_4%" echo prompt
>>"%TMP_SQL_4%" echo prompt [진단 결론]
>>"%TMP_SQL_4%" echo prompt !PASSWORD_FILE_RESULT!
>>"%TMP_SQL_4%" echo prompt

>>"%TMP_SQL_4%" echo spool off
>>"%TMP_SQL_4%" echo exit;

echo [INFO] Chapter 4. Configuration Management Audit...
if defined ORA_CONN ( sqlplus -s "%ORA_CONN%" @"%TMP_SQL_4%" ) else ( sqlplus -s / as sysdba @"%TMP_SQL_4%" )
echo    - Report 4: "security_report_chapter_4.txt"

REM ====== 정리 ======
del "%TMP_SQL_4%" >nul 2>nul

echo.
echo [COMPLETE] 모든 진단이 완료되었습니다.
echo          - 결과 폴더: %OUTDIR%
echo.
endlocal
goto :EOF


::==============================================================================
:: 4.4 (원본 함수 본문)
::==============================================================================
:RUN_44
setlocal EnableExtensions EnableDelayedExpansion

REM set ORA_CONN=c##test/1234//localhost:1521/xe

set "REPORT_FILE=%CD%\%OUTDIR%\security_report_chapter_4_4.txt"

echo [INFO] 4.4 Alert Log 파일 접근 제한 자동 점검 시작...

set "TRACE_DIR=C:\app\Administrator\product\21c\diag\rdbms\xe\xe\trace"
set "ALERT_FILE=%TRACE_DIR%\alert_xe.log"
set "ATTN_FILE=%TRACE_DIR%\attention_xe.log"

type nul > "%REPORT_FILE%"
>>"%REPORT_FILE%" echo ### [4.4] Alert Log 파일 접근 제한 (자동 진단) ###
>>"%REPORT_FILE%" echo [판단 기준]
>>"%REPORT_FILE%" echo   - 양호: Administrators, SYSTEM, Owner, Oracle 서비스 계정(ORA_*_SVCACCTS/OracleService*), ORA_DBA만 권한
>>"%REPORT_FILE%" echo   - 취약: Everyone/Users/Authenticated Users/Guests/Domain Users 등 불필요 그룹 존재
>>"%REPORT_FILE%" echo.
>>"%REPORT_FILE%" echo [OS Command]
>>"%REPORT_FILE%" echo   icacls "%TRACE_DIR%"
>>"%REPORT_FILE%" echo   icacls "%ALERT_FILE%"
>>"%REPORT_FILE%" echo   icacls "%ATTN_FILE%"
>>"%REPORT_FILE%" echo.
>>"%REPORT_FILE%" echo [대상 경로]
>>"%REPORT_FILE%" echo   - Trace Dir : %TRACE_DIR%
>>"%REPORT_FILE%" echo   - Alert Log : %ALERT_FILE%
>>"%REPORT_FILE%" echo   - Attention : %ATTN_FILE%
>>"%REPORT_FILE%" echo.

if not exist "%TRACE_DIR%" (
  >>"%REPORT_FILE%" echo [ERROR] Trace 디렉터리 없음: "%TRACE_DIR%"
  >>"%REPORT_FILE%" echo 스크린샷과 다른 경로면 알려주세요.
  echo [FAIL] 4.4 종료.
  endlocal & goto :EOF
)

set "ACL_DIR=%TEMP%\acl_dir_%RANDOM%.txt"
set "ACL_ALERT=%TEMP%\acl_alert_%RANDOM%.txt"
set "ACL_ATTN=%TEMP%\acl_attn_%RANDOM%.txt"

icacls "%TRACE_DIR%" > "%ACL_DIR%" 2>nul
if exist "%ALERT_FILE%" icacls "%ALERT_FILE%" > "%ACL_ALERT%" 2>nul
if exist "%ATTN_FILE%"  icacls "%ATTN_FILE%"  > "%ACL_ATTN%"  2>nul

set "VULN=0"
call :SCAN_44 "%ACL_DIR%"  "Everyone"
call :SCAN_44 "%ACL_DIR%"  "모든 사용자"
call :SCAN_44 "%ACL_DIR%"  "Users"
call :SCAN_44 "%ACL_DIR%"  "BUILTIN\Users"
call :SCAN_44 "%ACL_DIR%"  "사용자"
call :SCAN_44 "%ACL_DIR%"  "Authenticated Users"
call :SCAN_44 "%ACL_DIR%"  "인증된 사용자"
call :SCAN_44 "%ACL_DIR%"  "Guests"
call :SCAN_44 "%ACL_DIR%"  "게스트"
call :SCAN_44 "%ACL_DIR%"  "Domain Users"
call :SCAN_44 "%ACL_DIR%"  "도메인 사용자"

if exist "%ACL_ALERT%" (
  call :SCAN_44 "%ACL_ALERT%" "Everyone"
  call :SCAN_44 "%ACL_ALERT%" "모든 사용자"
  call :SCAN_44 "%ACL_ALERT%" "Users"
  call :SCAN_44 "%ACL_ALERT%" "BUILTIN\Users"
  call :SCAN_44 "%ACL_ALERT%" "사용자"
  call :SCAN_44 "%ACL_ALERT%" "Authenticated Users"
  call :SCAN_44 "%ACL_ALERT%" "인증된 사용자"
  call :SCAN_44 "%ACL_ALERT%" "Guests"
  call :SCAN_44 "%ACL_ALERT%" "게스트"
  call :SCAN_44 "%ACL_ALERT%" "Domain Users"
  call :SCAN_44 "%ACL_ALERT%" "도메인 사용자"
)

if exist "%ACL_ATTN%" (
  call :SCAN_44 "%ACL_ATTN%" "Everyone"
  call :SCAN_44 "%ACL_ATTN%" "모든 사용자"
  call :SCAN_44 "%ACL_ATTN%" "Users"
  call :SCAN_44 "%ACL_ATTN%" "BUILTIN\Users"
  call :SCAN_44 "%ACL_ATTN%" "사용자"
  call :SCAN_44 "%ACL_ATTN%" "Authenticated Users"
  call :SCAN_44 "%ACL_ATTN%" "인증된 사용자"
  call :SCAN_44 "%ACL_ATTN%" "Guests"
  call :SCAN_44 "%ACL_ATTN%" "게스트"
  call :SCAN_44 "%ACL_ATTN%" "Domain Users"
  call :SCAN_44 "%ACL_ATTN%" "도메인 사용자"
)

>>"%REPORT_FILE%" echo [수집된 ACL - 디렉터리]
>>"%REPORT_FILE%" type "%ACL_DIR%"
>>"%REPORT_FILE%" echo.

if exist "%ACL_ALERT%" (
  set "ALERT_SUM="
  for /f "usebackq delims=" %%L in (`findstr /C:"Successfully processed" "%ACL_ALERT%"`) do set "ALERT_SUM=%%L"
  >>"%REPORT_FILE%" echo [Alert Log 파일 처리 요약]
  if defined ALERT_SUM (>>"%REPORT_FILE%" echo !ALERT_SUM!) else (>>"%REPORT_FILE%" echo Alert Log 파일 ACL 처리 완료)
  >>"%REPORT_FILE%" echo.
) else (
  >>"%REPORT_FILE%" echo [참고] Alert Log 파일 없음
  >>"%REPORT_FILE%" echo.
)

if exist "%ACL_ATTN%" (
  set "ATTN_SUM="
  for /f "usebackq delims=" %%L in (`findstr /C:"Successfully processed" "%ACL_ATTN%"`) do set "ATTN_SUM=%%L"
  >>"%REPORT_FILE%" echo [Attention Log 파일 처리 요약]
  if defined ATTN_SUM (>>"%REPORT_FILE%" echo !ATTN_SUM!) else (>>"%REPORT_FILE%" echo Attention Log 파일 ACL 처리 완료)
  >>"%REPORT_FILE%" echo.
) else (
  >>"%REPORT_FILE%" echo [참고] Attention Log 파일 없음
  >>"%REPORT_FILE%" echo.
)

>>"%REPORT_FILE%" echo [진단 결론]
if "%VULN%"=="0" (
  >>"%REPORT_FILE%" echo 양호: 불필요 그룹 권한이 확인되지 않았습니다. ^(Administrators/SYSTEM/Owner/Oracle 서비스 계정만 존재^)
) else (
  >>"%REPORT_FILE%" echo 취약: Everyone/Users/Authenticated Users/Guests/Domain Users 등 불필요 그룹 권한이 감지되었습니다.
  >>"%REPORT_FILE%" echo 조치: icacls "%TRACE_DIR%" /remove:g "Everyone" "Authenticated Users" "Users" "Guests" "Domain Users"
  if exist "%ALERT_FILE%" >>"%REPORT_FILE%" echo       icacls "%ALERT_FILE%" /remove:g "Everyone" "Authenticated Users" "Users" "Guests" "Domain Users"
  if exist "%ATTN_FILE%" >>"%REPORT_FILE%" echo       icacls "%ATTN_FILE%" /remove:g "Everyone" "Authenticated Users" "Users" "Guests" "Domain Users"
)
>>"%REPORT_FILE%" echo.

del "%ACL_DIR%" >nul 2>nul
del "%ACL_ALERT%" >nul 2>nul
del "%ACL_ATTN%" >nul 2>nul

echo [OK] 4.4 완료 - Report: "security_report_chapter_4_4.txt"
endlocal & goto :EOF

:SCAN_44
findstr /I /C:%2 "%~1" >nul 2>nul
if not errorlevel 1 set "VULN=1"
exit /b 0


::==============================================================================
:: 4.5 (원본 함수 본문)
::==============================================================================
:RUN_45
setlocal EnableExtensions EnableDelayedExpansion

REM set ORA_CONN=c##test/1234@//localhost:1521/xe
set "ORA_CONN=c##test/1234@//10.0.8.8:1521/XE"

where sqlplus >nul 2>nul || (
  echo [ERROR] sqlplus.exe not found in PATH.
  endlocal & exit /b 1
)

set "REPORT_FILE=%CD%\%OUTDIR%\security_report_chapter_4_5.txt"
set "TMP_SQL=%TEMP%\ora_get_tracedir_%RANDOM%.sql"
set "TMP_OUT=%TEMP%\ora_get_tracedir_%RANDOM%.out"

echo [INFO] 4.5 Trace Log 파일 접근 제한 자동 점검 시작...

set "TRACE_DIR=C:\app\Administrator\product\21c\diag\rdbms\xe\xe\trace"

> "%TMP_SQL%" echo set head off feed off verify off pages 0 lines 400 trimspool on
>>"%TMP_SQL%" echo set termout off
>>"%TMP_SQL%" echo select value from v^$diag_info where name='Diag Trace';
>>"%TMP_SQL%" echo exit

if defined ORA_CONN (
  sqlplus -s "%ORA_CONN%" @"%TMP_SQL%" > "%TMP_OUT%" 2>nul
) else (
  sqlplus -s / as sysdba @"%TMP_SQL%" > "%TMP_OUT%" 2>nul
)
for /f "usebackq delims=" %%A in ("%TMP_OUT%") do (
  set "CAND=%%~A"
  for /f "tokens=* delims= " %%B in ("!CAND!") do set "CAND=%%~B"
  if exist "!CAND!" set "TRACE_DIR=!CAND!"
)
del "%TMP_SQL%" >nul 2>nul
del "%TMP_OUT%" >nul 2>nul

type nul > "%REPORT_FILE%"
>>"%REPORT_FILE%" echo ### [4.5] Trace Log 파일 접근 제한 (자동 진단) ###
>>"%REPORT_FILE%" echo [판단 기준]
>>"%REPORT_FILE%" echo   - 양호(Windows): Administrators, SYSTEM, Owner, Oracle 서비스 계정(ORA_*_SVCACCTS/OracleService*) 등만 권한
>>"%REPORT_FILE%" echo   - 취약        : Everyone/Users/Authenticated Users/Guests/Domain Users 등 불필요 그룹 존재
>>"%REPORT_FILE%" echo.
>>"%REPORT_FILE%" echo [경로 결정 우선순위] 1^) 스크린샷  2^) v$diag_info(Diag Trace)
>>"%REPORT_FILE%" echo [OS Command]
>>"%REPORT_FILE%" echo   icacls "%TRACE_DIR%"
>>"%REPORT_FILE%" echo   icacls "%TRACE_DIR%\*.trc"
>>"%REPORT_FILE%" echo.
>>"%REPORT_FILE%" echo [대상 Trace 디렉터리]
>>"%REPORT_FILE%" echo   %TRACE_DIR%
>>"%REPORT_FILE%" echo.

if not exist "%TRACE_DIR%" (
  >>"%REPORT_FILE%" echo [ERROR] Trace 디렉터리 없음: "%TRACE_DIR%"
  >>"%REPORT_FILE%" echo 스크린샷과 다른 경로면 알려주세요.
  echo [FAIL] 4.5 종료.
  endlocal & goto :EOF
)

set "ACL_DIR=%TEMP%\acl_dir_%RANDOM%.txt"
set "ACL_FILE=%TEMP%\acl_file_%RANDOM%.txt"
icacls "%TRACE_DIR%"        > "%ACL_DIR%"  2>nul
icacls "%TRACE_DIR%\*.trc"  > "%ACL_FILE%" 2>nul

set "PROC_SUM="
for /f "usebackq delims=" %%L in (`findstr /C:"Successfully processed" "%ACL_FILE%"`) do set "PROC_SUM=%%L"

set "VULN=0"
call :SCAN_45 "%ACL_DIR%"  "Everyone"
call :SCAN_45 "%ACL_FILE%" "Everyone"
call :SCAN_45 "%ACL_DIR%"  "모든 사용자"
call :SCAN_45 "%ACL_FILE%" "모든 사용자"

call :SCAN_45 "%ACL_DIR%"  "Users"
call :SCAN_45 "%ACL_FILE%" "Users"
call :SCAN_45 "%ACL_DIR%"  "BUILTIN\Users"
call :SCAN_45 "%ACL_FILE%" "BUILTIN\Users"
call :SCAN_45 "%ACL_DIR%"  "사용자"
call :SCAN_45 "%ACL_FILE%" "사용자"

call :SCAN_45 "%ACL_DIR%"  "Authenticated Users"
call :SCAN_45 "%ACL_FILE%" "Authenticated Users"
call :SCAN_45 "%ACL_DIR%"  "인증된 사용자"
call :SCAN_45 "%ACL_FILE%" "인증된 사용자"

call :SCAN_45 "%ACL_DIR%"  "Guests"
call :SCAN_45 "%ACL_FILE%" "Guests"
call :SCAN_45 "%ACL_DIR%"  "게스트"
call :SCAN_45 "%ACL_FILE%" "게스트"

call :SCAN_45 "%ACL_DIR%"  "Domain Users"
call :SCAN_45 "%ACL_FILE%" "Domain Users"
call :SCAN_45 "%ACL_DIR%"  "도메인 사용자"
call :SCAN_45 "%ACL_FILE%" "도메인 사용자"

>>"%REPORT_FILE%" echo [수집된 ACL - 디렉터리]
>>"%REPORT_FILE%" type "%ACL_DIR%"
>>"%REPORT_FILE%" echo.
>>"%REPORT_FILE%" echo [트레이스 파일 처리 요약]
if defined PROC_SUM (>>"%REPORT_FILE%" echo %PROC_SUM%) else (>>"%REPORT_FILE%" echo Successfully processed files summary not available.)
>>"%REPORT_FILE%" echo.
>>"%REPORT_FILE%" echo [진단 결론]
if "%VULN%"=="0" (
  >>"%REPORT_FILE%" echo 양호: 불필요 그룹 권한이 확인되지 않았습니다. ^(Administrators/SYSTEM/Owner/Oracle 서비스 계정만 존재^)
) else (
  >>"%REPORT_FILE%" echo 취약: Everyone/Users/Authenticated Users/Guests/Domain Users 등 불필요 그룹 권한이 감지되었습니다.
  >>"%REPORT_FILE%" echo 조치: icacls "%TRACE_DIR%" /remove:g "Everyone" "Authenticated Users" "Users" "Guests" "Domain Users"
)
>>"%REPORT_FILE%" echo.

del "%ACL_DIR%"  >nul 2>nul
del "%ACL_FILE%" >nul 2>nul

echo [OK] 4.5 완료 - Report: "security_report_chapter_4_5.txt"
endlocal & goto :EOF

:SCAN_45
findstr /I /C:%2 "%~1" >nul 2>nul
if not errorlevel 1 set "VULN=1"
exit /b 0


::==============================================================================
:: 4.6 (원본 함수 본문)
::==============================================================================
:RUN_46
setlocal EnableExtensions EnableDelayedExpansion

set "REPORT_FILE=%CD%\%OUTDIR%\security_report_chapter_4_6.txt"

echo [INFO] 4.6 컨트롤/Redo/데이터 파일 접근 제한 점검 시작...

set "ORADATA_DIR=C:\app\Administrator\product\21c\oradata\XE"
set "FILELIST="

for %%F in ("%ORADATA_DIR%\CONTROL*.CTL" "%ORADATA_DIR%\REDO*.LOG" "%ORADATA_DIR%\*.DBF") do (
  if exist "%%~fF" set "FILELIST=!FILELIST!;%%~fF"
)

type nul > "%REPORT_FILE%"
>>"%REPORT_FILE%" echo ### [4.6] 컨트롤, Redo, 데이터 파일 접근 제한 (자동 진단) ###
>>"%REPORT_FILE%" echo [판단 기준]
>>"%REPORT_FILE%" echo   - 양호: Administrators, SYSTEM, Owner, Oracle 서비스 계정만 권한
>>"%REPORT_FILE%" echo   - 취약: Everyone, Users, Authenticated Users, Guests, Domain Users 등 불필요 그룹 존재
>>"%REPORT_FILE%" echo.
>>"%REPORT_FILE%" echo [OS Command]
>>"%REPORT_FILE%" echo   icacls ^<각 파일 경로^>
>>"%REPORT_FILE%" echo.
>>"%REPORT_FILE%" echo [대상 파일 디렉터리]
>>"%REPORT_FILE%" echo   %ORADATA_DIR%
>>"%REPORT_FILE%" echo.

if "%FILELIST%"=="" (
  >>"%REPORT_FILE%" echo [ERROR] 지정한 경로에서 컨트롤/Redo/데이터 파일을 찾을 수 없습니다.
  echo [FAIL] 4.6 종료.
  endlocal & goto :EOF
)

set "VULN=0"
for %%F in (%FILELIST:;= %) do (
  set "ACL_FILE=%TEMP%\acl_chk_%RANDOM%.txt"
  icacls "%%~F" > "!ACL_FILE!" 2>nul

  >>"%REPORT_FILE%" echo [ACL: %%~F]
  >>"%REPORT_FILE%" type "!ACL_FILE!"
  >>"%REPORT_FILE%" echo.

  call :SCAN_46 "!ACL_FILE!" "Everyone:"
  call :SCAN_46 "!ACL_FILE!" "Authenticated Users:"
  call :SCAN_46 "!ACL_FILE!" "BUILTIN\Users:"
  call :SCAN_46 "!ACL_FILE!" "Guests:"
  call :SCAN_46 "!ACL_FILE!" "Domain Users:"
  call :SCAN_46 "!ACL_FILE!" "모든 사용자:"
  call :SCAN_46 "!ACL_FILE!" "인증된 사용자:"
  call :SCAN_46 "!ACL_FILE!" "사용자:"
  call :SCAN_46 "!ACL_FILE!" "게스트:"
  call :SCAN_46 "!ACL_FILE!" "도메인 사용자:"

  del "!ACL_FILE!" >nul 2>nul
)

>>"%REPORT_FILE%" echo [진단 결론]
if "%VULN%"=="0" (
  >>"%REPORT_FILE%" echo 양호: 불필요 그룹 권한이 확인되지 않았습니다.
) else (
  >>"%REPORT_FILE%" echo 취약: 불필요 그룹 권한이 감지되었습니다.
  >>"%REPORT_FILE%" echo 조치: icacls "파일경로" /remove:g "Everyone" "Authenticated Users" "Users" "Guests" "Domain Users"
)
>>"%REPORT_FILE%" echo.

echo [OK] 4.6 완료 - Report: "security_report_chapter_4_6.txt"
endlocal & goto :EOF

:SCAN_46
findstr /I /C:"%~2" "%~1" >nul 2>nul
if not errorlevel 1 set "VULN=1"
exit /b 0


::==============================================================================
:: 4.7 (원본 함수 본문)
::==============================================================================
:RUN_47
setlocal EnableExtensions EnableDelayedExpansion

set "REPORT_FILE=%CD%\%OUTDIR%\security_report_chapter_4_7.txt"

echo [INFO] 4.7 ^$TNS_ADMIN 파일 접근 제한 점검 시작...

type nul > "%REPORT_FILE%"
>>"%REPORT_FILE%" echo ### [4.7] ^$TNS_ADMIN 파일 접근 제한 ^(자동 진단^) ###
>>"%REPORT_FILE%" echo [판단 기준]
>>"%REPORT_FILE%" echo   - 양호^(Windows^): Administrators, SYSTEM, Owner, Oracle 서비스 계정, DBA 만 권한
>>"%REPORT_FILE%" echo   - 취약        : Everyone/Users/Authenticated Users/Guests/Domain Users 등 불필요 그룹 존재
>>"%REPORT_FILE%" echo.

set "CANDIDATE_DIRS="

if defined FORCE_TNS_DIR if exist "%FORCE_TNS_DIR%" set "CANDIDATE_DIRS=%CANDIDATE_DIRS% "%FORCE_TNS_DIR%""
if defined TNS_ADMIN    if exist "%TNS_ADMIN%"    set "CANDIDATE_DIRS=%CANDIDATE_DIRS% "%TNS_ADMIN%""
if defined ORACLE_HOME  if exist "%ORACLE_HOME%\network\admin" set "CANDIDATE_DIRS=%CANDIDATE_DIRS% "%ORACLE_HOME%\network\admin""

for %%K in ("HKLM\SOFTWARE\Oracle" "HKLM\SOFTWARE\WOW6432Node\Oracle") do (
  for /f "skip=2 tokens=*" %%A in ('reg query %%~K 2^>nul ^| findstr /I "KEY_"') do (
    for /f "tokens=1,2,*" %%x in ('reg query "%%~A" /v TNS_ADMIN 2^>nul ^| findstr /I "TNS_ADMIN"') do (
      if exist "%%z" set "CANDIDATE_DIRS=%CANDIDATE_DIRS% "%%z""
    )
    for /f "tokens=1,2,*" %%x in ('reg query "%%~A" /v ORACLE_HOME 2^>nul ^| findstr /I "ORACLE_HOME"') do (
      if exist "%%z\network\admin" set "CANDIDATE_DIRS=%CANDIDATE_DIRS% "%%z\network\admin""
    )
  )
)

if exist "C:\app\infra-db\product\21c\homes\OraDB21Home1\network\admin" (
  set "CANDIDATE_DIRS=%CANDIDATE_DIRS% "C:\app\infra-db\product\21c\homes\OraDB21Home1\network\admin""
)
if exist "C:\app\Administrator\product\21c\homes\OraDB21Home1\network\admin" (
  set "CANDIDATE_DIRS=%CANDIDATE_DIRS% "C:\app\Administrator\product\21c\homes\OraDB21Home1\network\admin""
)

>>"%REPORT_FILE%" echo [탐지한 TNS 디렉터리 후보]
if defined CANDIDATE_DIRS (
  for %%D in (%CANDIDATE_DIRS%) do >>"%REPORT_FILE%" echo   - %%~D
) else (
  >>"%REPORT_FILE%" echo   - (없음)
)
>>"%REPORT_FILE%" echo.

set "ANY_FOUND=0"
set "OVERALL_VULN=0"

for %%D in (%CANDIDATE_DIRS%) do (
  if exist "%%~D" (
    set "FOUND_IN_DIR=0"
    for %%F in ("%%~D\sqlnet.ora" "%%~D\listener.ora" "%%~D\tnsnames.ora") do (
      if exist "%%~F" (
        set "ANY_FOUND=1"
        set "FOUND_IN_DIR=1"
        call :CHECK_ONE_47 "%%~F"
      )
    )
    if "!!FOUND_IN_DIR!!"=="0" (
      >>"%REPORT_FILE%" echo [INFO] 표준 파일 미존재: %%~D
      >>"%REPORT_FILE%" echo.
    )
  )
)

if "%ANY_FOUND%"=="0" (
  >>"%REPORT_FILE%" echo [WARN] 어느 후보 디렉터리에서도 sqlnet.ora/listener.ora/tnsnames.ora 를 찾지 못했습니다.
  >>"%REPORT_FILE%" echo.
)

>>"%REPORT_FILE%" echo [진단 결론]
if "%OVERALL_VULN%"=="0" (
  >>"%REPORT_FILE%" echo 양호: 불필요 그룹 권한이 확인되지 않았습니다.
) else (
  >>"%REPORT_FILE%" echo 취약: Everyone/Users/Authenticated Users/Guests/Domain Users 등 불필요 그룹 권한이 감지되었습니다.
  >>"%REPORT_FILE%" echo 조치 예시:
  >>"%REPORT_FILE%" echo   icacls "경로\sqlnet.ora"   /remove:g "Everyone" "Authenticated Users" "Users" "Guests" "Domain Users"
  >>"%REPORT_FILE%" echo   icacls "경로\listener.ora" /remove:g "Everyone" "Authenticated Users" "Users" "Guests" "Domain Users"
  >>"%REPORT_FILE%" echo   icacls "경로\tnsnames.ora" /remove:g "Everyone" "Authenticated Users" "Users" "Guests" "Domain Users"
)
>>"%REPORT_FILE%" echo.

echo [OK] 4.7 완료 - Report: "security_report_chapter_4_7.txt"
endlocal & goto :EOF

:CHECK_ONE_47
set "CF=%~1"
set "ACL_TMP=%TEMP%\tns_acl_%RANDOM%.txt"
icacls "%CF%" > "%ACL_TMP%" 2>nul

>>"%REPORT_FILE%" echo [ACL: %CF%]
>>"%REPORT_FILE%" type "%ACL_TMP%"
>>"%REPORT_FILE%" echo.

set "FILE_VULN=0"
for %%P in (
  "Everyone"
  "Users"
  "BUILTIN\Users"
  "Authenticated Users"
  "Guests"
  "Domain Users"
  "모든 사용자"
  "사용자"
  "인증된 사용자"
  "게스트"
  "도메인 사용자"
) do (
  findstr /I /C:"%%~P" "%ACL_TMP%" >nul 2>nul
  if not errorlevel 1 set "FILE_VULN=1"
)

if "%FILE_VULN%"=="0" (
  >>"%REPORT_FILE%" echo [파일 판정] 양호: 불필요 그룹 권한 미검출
) else (
  >>"%REPORT_FILE%" echo [파일 판정] 취약: 불필요 그룹 권한 검출
  set "OVERALL_VULN=1"
)
>>"%REPORT_FILE%" echo.

del "%ACL_TMP%" >nul 2>nul
goto :EOF


::==============================================================================
:: 4.8 (원본 함수 본문)
::==============================================================================
:RUN_48
setlocal EnableExtensions EnableDelayedExpansion

set "REPORT_FILE=%CD%\%OUTDIR%\security_report_chapter_4_8.txt"

echo [INFO] 4.8 감사 로그 파일 접근 제한 점검 시작...

set "AUDIT_DIR=C:\app\Administrator\product\21c\admin\XE\adump"

type nul > "%REPORT_FILE%"
>>"%REPORT_FILE%" echo ### [4.8] 감사 로그 파일 접근 제한 (자동 진단)
>>"%REPORT_FILE%" echo [판단 기준]
>>"%REPORT_FILE%" echo   - 양호^(Windows^): Administrators, SYSTEM, Owner, Oracle 서비스 계정, DBA 만 권한
>>"%REPORT_FILE%" echo   - 취약        : Everyone/Users/Authenticated Users/Guests/Domain Users 등 불필요 그룹 존재
>>"%REPORT_FILE%" echo.
>>"%REPORT_FILE%" echo [OS Command]
>>"%REPORT_FILE%" echo   icacls "%AUDIT_DIR%"
>>"%REPORT_FILE%" echo   icacls "%AUDIT_DIR%\*.*"
>>"%REPORT_FILE%" echo.
>>"%REPORT_FILE%" echo [대상 감사 로그 디렉터리]
>>"%REPORT_FILE%" echo   %AUDIT_DIR%
>>"%REPORT_FILE%" echo.

if not exist "%AUDIT_DIR%" (
  >>"%REPORT_FILE%" echo [ERROR] 감사 로그 디렉터리를 찾을 수 없습니다: "%AUDIT_DIR%"
  goto :WRITE_SUMMARY_48
)

set "VULN=0"
set "ACL_TMP=%TEMP%\audit_acl_%RANDOM%.txt"
icacls "%AUDIT_DIR%" > "!ACL_TMP!" 2>nul

>>"%REPORT_FILE%" echo [ACL: %AUDIT_DIR%]
>>"%REPORT_FILE%" type "!ACL_TMP!"
>>"%REPORT_FILE%" echo.

for %%P in (
  "Everyone"
  "Users"
  "BUILTIN\Users"
  "Authenticated Users"
  "Guests"
  "Domain Users"
  "모든 사용자"
  "사용자"
  "인증된 사용자"
  "게스트"
  "도메인 사용자"
) do (
  findstr /I /C:%%P "!ACL_TMP!" >nul 2>nul
  if not errorlevel 1 set "VULN=1"
)

del "!ACL_TMP!" >nul 2>nul

:WRITE_SUMMARY_48
>>"%REPORT_FILE%" echo [진단 결론]
if "%VULN%"=="0" (
  >>"%REPORT_FILE%" echo 양호: 불필요 그룹 권한이 확인되지 않았습니다.
) else (
  >>"%REPORT_FILE%" echo 취약: 감사 로그 디렉터리에 불필요 그룹 권한이 감지되었습니다.
  >>"%REPORT_FILE%" echo 조치 예시:
  >>"%REPORT_FILE%" echo   icacls "%AUDIT_DIR%" /remove:g "Everyone" "Authenticated Users" "Users" "Guests" "Domain Users"
)
>>"%REPORT_FILE%" echo.

echo [OK] 4.8 완료 - Report: "security_report_chapter_4_8.txt"
endlocal & goto :EOF
