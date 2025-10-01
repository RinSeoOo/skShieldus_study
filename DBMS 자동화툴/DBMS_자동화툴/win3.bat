@echo off
setlocal enableextensions enabledelayedexpansion

REM ====== 사용자 설정(필요시 수정) ======
REM OS 인증이 안 되면 ORA_CONN을 채워주세요 (예: system/Passw0rd@//127.0.0.1:1521/ORCLPDB1)
set "ORA_CONN=c##test/1234@//10.0.8.8:1521/XE"

REM Oracle Client(sqlplus.exe) 가 PATH에 있어야 합니다.
where sqlplus >nul 2>nul || (
  echo [ERROR] sqlplus.exe not found in PATH. Install Oracle Client or add to PATH.
  exit /b 1
)

REM ====== 보고서 파일 경로 정의 ======
set "REPORT_FILE_3=%CD%\%OUTDIR%\security_report_chapter_3.txt"

REM ====== 임시 SQL 파일 경로 정의 ======
set "TMP_SQL_3=%TEMP%\ora_ch3_%RANDOM%.sql"

REM ====== ORACLE 환경변수 초기화 ======
set "FOUND_ORACLE_HOME="
set "FOUND_ORACLE="
set "FOUND_TNS_ADMIN_PATH="

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
REM ====== [3.3] 항목 진단을 위해 파일 내용을 미리 검사 (수정된 버전) ======
REM =================================================================
set "ORACLE_VERSION="
set "MAJOR_VERSION="
set "LISTENER_SEC_RESULT="

REM --- ★★★ 수정: 임시 파일을 사용한 안전한 버전 확인 로직 ★★★
set "TMP_VERSION_SQL=%TEMP%\ora_version_check_%RANDOM%.sql"
set "TMP_VERSION_OUT=%TEMP%\ora_version_out_%RANDOM%.txt"

REM --- 1. 임시 SQL 파일 생성 ---
> "%TMP_VERSION_SQL%" echo set echo off feedback off verify off heading off pagesize 0 trimspool on;
>>"%TMP_VERSION_SQL%" echo select version from v$instance;
>>"%TMP_VERSION_SQL%" echo exit;

echo  - Oracle 버전 정보를 확인하는 중...

REM --- 2. Oracle 버전 정보 가져오기 (임시 파일로 출력) ---
if defined ORA_CONN (
    sqlplus -s "!ORA_CONN!" @"%TMP_VERSION_SQL%" > "!TMP_VERSION_OUT!" 2>&1
) else (
    sqlplus -s / as sysdba @"%TMP_VERSION_SQL%" > "!TMP_VERSION_OUT!" 2>&1
)

REM --- 3. 임시 파일에서 버전 정보 읽기 ---
if exist "!TMP_VERSION_OUT!" (
    for /f "usebackq delims=" %%v in ("!TMP_VERSION_OUT!") do (
        if not defined ORACLE_VERSION (
            set "ORACLE_VERSION=%%v"
        )
    )
)

REM --- 4. 임시 파일들 삭제 ---
del "%TMP_VERSION_SQL%" >nul 2>nul
del "!TMP_VERSION_OUT!" >nul 2>nul

REM --- 5. 가져온 정보 유효성 검사 및 분기 처리 ---
if not defined ORACLE_VERSION (
    echo  - [경고] Oracle 버전 정보를 가져오지 못했습니다.
    goto :ContinueListenerCheck
)

REM 공백 및 특수문자 제거
set "ORACLE_VERSION=!ORACLE_VERSION: =!"
for /f "tokens=*" %%a in ("!ORACLE_VERSION!") do set "ORACLE_VERSION=%%a"

REM Oracle/TNS 오류 메시지 확인
echo "!ORACLE_VERSION!" | findstr /I "ORA-" >nul
if !errorlevel! equ 0 (
    echo  - [경고] Oracle 연결 오류: !ORACLE_VERSION!
    goto :ContinueListenerCheck
)

echo "!ORACLE_VERSION!" | findstr /I "TNS-" >nul
if !errorlevel! equ 0 (
    echo  - [경고] TNS 연결 오류: !ORACLE_VERSION!
    goto :ContinueListenerCheck
)

REM SP2- 등 다른 오류 메시지 확인
echo "!ORACLE_VERSION!" | findstr /I "SP2-\|ERROR\|ORA-\|TNS-" >nul
if !errorlevel! equ 0 (
    echo  - [경고] SQL*Plus 오류: !ORACLE_VERSION!
    goto :ContinueListenerCheck
)

REM --- 6. 정상적인 버전 정보 처리 ---
echo  - 확인된 Oracle 버전:!ORACLE_VERSION!

REM 주요 버전 번호 추출 (첫 번째 숫자)
for /f "tokens=1 delims=." %%a in ("!ORACLE_VERSION!") do set "MAJOR_VERSION=%%a"

if not defined MAJOR_VERSION (
    echo  - [경고] 버전 번호를 추출할 수 없습니다.
    goto :ContinueListenerCheck
)

REM 숫자인지 확인 및 12 이상 버전 체크
set /a "VERSION_NUM=!MAJOR_VERSION!" 2>nul

if !VERSION_NUM! GEQ 12 (
    echo  - Oracle 12c 이상 버전이 확인되었습니다.
    set "LISTENER_SEC_RESULT=양호: Oracle 12.1 이상 버전은 Local OS 인증을 사용하므로 보안 설정이 필수가 아닙니다."
    goto :EndListenerCheck
)

echo  - Oracle 12c 미만 버전입니다. Listener 보안 설정을 확인합니다.

:ContinueListenerCheck
REM --- 7. 버전이 12 미만이거나 확인 실패 시 Listener 파일 직접 검사 ---
set "LISTENER_SEC_RESULT=취약: Listener 패스워드가 설정되어 있지 않습니다. (12.1 미만 버전에 해당)"
set "PASSWORD_SET="
set "ADMIN_RESTRICTIONS_SET="

if exist "!FOUND_TNS_ADMIN_PATH!\listener.ora" (
    echo  - listener.ora 파일을 확인하는 중...
    
    REM Listener 서비스 상태 확인
    lsnrctl status > "%TEMP%\lsnrctl_status.txt" 2>nul
    findstr /C:"Services Summary..." "%TEMP%\lsnrctl_status.txt" >nul
    if !errorlevel! equ 0 (
        REM listener.ora 파일에서 보안 설정 확인
        for /f "usebackq tokens=*" %%L in ("!FOUND_TNS_ADMIN_PATH!\listener.ora") do (
            echo "%%L" | findstr /R /I /C:"^ *PASSWORDS_" >nul
            if !errorlevel! equ 0 ( 
                set "PASSWORD_SET=YES"
                echo  - PASSWORDS_ 설정 발견
            )
            echo "%%L" | findstr /R /I /C:"^ *ADMIN_RESTRICTIONS_.*= *ON" >nul
            if !errorlevel! equ 0 ( 
                set "ADMIN_RESTRICTIONS_SET=YES"
                echo  - ADMIN_RESTRICTIONS 설정 발견
            )
        )
        
        if defined PASSWORD_SET if defined ADMIN_RESTRICTIONS_SET (
            set "LISTENER_SEC_RESULT=양호: Listener 패스워드 및 관리 제한이 설정되어 있습니다."
        )
    ) else (
        set "LISTENER_SEC_RESULT=해당 없음: 활성화된 Listener가 없습니다."
    )
    del "%TEMP%\lsnrctl_status.txt" >nul 2>nul
) else (
    echo  - [경고] listener.ora 파일을 찾을 수 없습니다: !FOUND_TNS_ADMIN_PATH!\listener.ora
    set "LISTENER_SEC_RESULT=취약: listener.ora 파일을 찾을 수 없습니다."
)

:EndListenerCheck
echo  - Listener 보안 검사 완료: !LISTENER_SEC_RESULT!

REM =================================================================
REM ====== [3.4] 항목 진단을 위해 파일 내용을 미리 검사 ======
REM =================================================================
set "IP_CONTROL_RESULT=취약: IP 차단이 설정되어 있지 않습니다."
set "VALIDNODE_CHECKING_SET="
set "INVITED_NODES_SET="

if exist "!FOUND_TNS_ADMIN_PATH!\sqlnet.ora" (
    for /f "tokens=*" %%L in ('type "!FOUND_TNS_ADMIN_PATH!\sqlnet.ora"') do (
        echo "%%L" | findstr /R /I /C:"^ *TCP\.VALIDNODE_CHECKING *= *YES" >nul
        if !errorlevel! equ 0 ( set "VALIDNODE_CHECKING_SET=YES" )
        echo "%%L" | findstr /R /I /C:"^ *TCP\.INVITED_NODES" >nul
        if !errorlevel! equ 0 ( set "INVITED_NODES_SET=YES" )
    )
    if defined VALIDNODE_CHECKING_SET if defined INVITED_NODES_SET (
        set "IP_CONTROL_RESULT=양호: IP 차단이 설정되어 있습니다."
    )
)

REM =================================================================
REM ====== 3장. 설정 관리 진단 SQL 생성 ======
REM =================================================================
> "%TMP_SQL_3%" echo set echo off feedback off verify off pages 999 lines 200 trimspool on
>>"%TMP_SQL_3%" echo whenever sqlerror continue
>>"%TMP_SQL_3%" echo spool "%REPORT_FILE_3%"
>>"%TMP_SQL_3%" echo prompt [3장. 설정 관리] Oracle DB 보안 점검 자동 진단 보고서
>>"%TMP_SQL_3%" echo prompt =================================================================

REM -- [3.1] 백업 관리 (인터뷰) --
>>"%TMP_SQL_3%" echo prompt
>>"%TMP_SQL_3%" echo prompt ### [3.1] 백업 관리 (인터뷰) ###
>>"%TMP_SQL_3%" echo prompt
>>"%TMP_SQL_3%" echo prompt [판단 기준]
>>"%TMP_SQL_3%" echo prompt  - 양호: 백업 정책에 따라 주기적으로 백업을 수행하고 안전하게 관리하는 경우
>>"%TMP_SQL_3%" echo prompt  - 취약: 주기적인 백업 정책이 없거나 제대로 수행되지 않는 경우
>>"%TMP_SQL_3%" echo prompt
>>"%TMP_SQL_3%" echo prompt [진단 방법]
>>"%TMP_SQL_3%" echo prompt  - 담당자에게 아래 내용을 질문하고 확인합니다.
>>"%TMP_SQL_3%" echo prompt    1) DB 백업 정책이 수립되어 있으며, 정기적으로 백업을 수행하고 있습니까? (백업 주기 확인)
>>"%TMP_SQL_3%" echo prompt    2) DB 유지보수나 업그레이드 작업 전에는 전체 백업을 수행합니까?
>>"%TMP_SQL_3%" echo prompt    3) 백업 데이터는 위변조 방지를 위해 별도의 안전한 장소에 보관됩니까?
>>"%TMP_SQL_3%" echo prompt
>>"%TMP_SQL_3%" echo prompt [진단 결론]
>>"%TMP_SQL_3%" echo prompt 수동 확인 필요: 담당자 인터뷰를 통해 백업 정책 및 수행 여부를 확인해야 합니다.

REM -- [3.2] PL/SQL Package의 PUBLIC Role 실행권한 점검 --
>>"%TMP_SQL_3%" echo prompt
>>"%TMP_SQL_3%" echo prompt ### [3.2] PL/SQL Package의 Public Role 점검 ###
>>"%TMP_SQL_3%" echo prompt
>>"%TMP_SQL_3%" echo prompt [판단 기준]
>>"%TMP_SQL_3%" echo prompt  - 양호: PL/SQL package에 접근 권한이 설정되어 있는 경우
>>"%TMP_SQL_3%" echo prompt  - 취약: PL/SQL package에 접근 권한이 설정되어 있지 않은 경우
>>"%TMP_SQL_3%" echo.
>>"%TMP_SQL_3%" echo prompt [SQL Command]
>>"%TMP_SQL_3%" echo prompt   select grantee, owner, grantor, table_name, privilege from dba_tab_privs where grantee='PUBLIC' and privilege='EXECUTE' and table_name in ('UTL_SMTP','UTL_TCP','UTL_HTTP','UTL_FILE','DBMS_RANDOM','DBMS_LOB','DBMS_SQL','DBMS_JOB','DBMS_BACKUP_RESTORE','DBMS_OBFUSCATION_TOOLKIT','UTL_INADDR');
>>"%TMP_SQL_3%" echo prompt
>>"%TMP_SQL_3%" echo col grantee format a15
>>"%TMP_SQL_3%" echo col owner format a15
>>"%TMP_SQL_3%" echo col table_name format a30
>>"%TMP_SQL_3%" echo col privilege format a15
>>"%TMP_SQL_3%" echo select grantee, owner, table_name, privilege from dba_tab_privs where grantee='PUBLIC' and privilege='EXECUTE' and table_name in ('UTL_SMTP','UTL_TCP','UTL_HTTP','UTL_FILE','DBMS_RANDOM','DBMS_LOB','DBMS_SQL','DBMS_JOB','DBMS_BACKUP_RESTORE','DBMS_OBFUSCATION_TOOLKIT','UTL_INADDR');
>>"%TMP_SQL_3%" echo.
>>"%TMP_SQL_3%" echo prompt [진단 결론]
>>"%TMP_SQL_3%" echo.
>>"%TMP_SQL_3%" echo set heading off
>>"%TMP_SQL_3%" echo select case when count(*) ^> 0 then '수동 확인 필요: PUBLIC 롤에 위험한 패키지 실행 권한이 부여되어 있습니다.' else '양호: PUBLIC 롤에 부여된 위험한 패키지 실행 권한이 없습니다.' end from dba_tab_privs where grantee='PUBLIC' and privilege='EXECUTE' and table_name in ('UTL_SMTP','UTL_TCP','UTL_HTTP','UTL_FILE','DBMS_RANDOM','DBMS_LOB','DBMS_SQL','DBMS_JOB','DBMS_BACKUP_RESTORE','DBMS_OBFUSCATION_TOOLKIT','UTL_INADDR');
>>"%TMP_SQL_3%" echo set heading on
>>"%TMP_SQL_3%" echo.

REM -- [3.3] Listener 보안 설정 여부 (listener.ora 파일 확인) --
>>"%TMP_SQL_3%" echo prompt
>>"%TMP_SQL_3%" echo prompt ### [3.3] Listener 보안 설정 여부 ###
>>"%TMP_SQL_3%" echo prompt [판단 기준]
>>"%TMP_SQL_3%" echo prompt  - 양호: Listener 파일의 패스워드 설정이 되어 있는 경우
>>"%TMP_SQL_3%" echo prompt  - 취약: Listener 파일의 패스워드 설정이 되어 있지 않은 경우
>>"%TMP_SQL_3%" echo prompt  (※ Oracle 12.1 Version 부터 Listener 패스워드 기능 미지원)
>>"%TMP_SQL_3%" echo prompt
>>"%TMP_SQL_3%" echo prompt [OS Command]
>>"%TMP_SQL_3%" echo prompt   1. Listener 상태 확인:
>>"%TMP_SQL_3%" echo prompt     C:\^> lsnrctl status
>>"%TMP_SQL_3%" echo prompt
>>"%TMP_SQL_3%" echo prompt   2. 설정 파일 확인:
>>"%TMP_SQL_3%" echo prompt     host findstr /I /C:"PASSWORDS_" /C:"ADMIN_RESTRICTIONS_" "!FOUND_TNS_ADMIN_PATH!\listener.ora"
>>"%TMP_SQL_3%" echo host findstr /I /C:"PASSWORDS_" /C:"ADMIN_RESTRICTIONS_" "!FOUND_TNS_ADMIN_PATH!\listener.ora"
>>"%TMP_SQL_3%" echo prompt
>>"%TMP_SQL_3%" echo prompt [진단 결론]
>>"%TMP_SQL_3%" echo prompt !LISTENER_SEC_RESULT!
>>"%TMP_SQL_3%" echo prompt

REM -- [3.4] DB 접속 IP 통제 (sqlnet.ora 파일 확인) --
>>"%TMP_SQL_3%" echo prompt
>>"%TMP_SQL_3%" echo prompt ### [3.4] DB 접속 IP 통제 ###
>>"%TMP_SQL_3%" echo prompt [판단 기준]
>>"%TMP_SQL_3%" echo prompt  - 양호: IP 차단이 설정되어 있는 경우
>>"%TMP_SQL_3%" echo prompt  - 취약: IP 차단이 설정되어 있지 않은 경우
>>"%TMP_SQL_3%" echo prompt
>>"%TMP_SQL_3%" echo prompt [설정 방법]
>>"%TMP_SQL_3%" echo prompt   $ORACLE_HOME/network/admin/sqlnet.ora 파일에 아래 내용을 추가 또는 수정합니다.
>>"%TMP_SQL_3%" echo prompt   TCP.VALIDNODE_CHECKING = YES
>>"%TMP_SQL_3%" echo prompt   TCP.INVITED_NODES = (허용할 IP1, 허용할 IP2, ...)
>>"%TMP_SQL_3%" echo prompt
>>"%TMP_SQL_3%" echo prompt [OS Command]
>>"%TMP_SQL_3%" echo prompt     host findstr /I "NODES" "!FOUND_TNS_ADMIN_PATH!\sqlnet.ora"
>>"%TMP_SQL_3%" echo host findstr /I "NODES" "!FOUND_TNS_ADMIN_PATH!\sqlnet.ora"
>>"%TMP_SQL_3%" echo prompt
>>"%TMP_SQL_3%" echo prompt [진단 결론]
>>"%TMP_SQL_3%" echo prompt !IP_CONTROL_RESULT!
>>"%TMP_SQL_3%" echo prompt

REM -- [3.5] 로그 저장 주기(정책 부재 시 인터뷰 필요) --
>>"%TMP_SQL_3%" echo prompt
>>"%TMP_SQL_3%" echo prompt ### [3.5] 로그 저장 주기 ###
>>"%TMP_SQL_3%" echo prompt
>>"%TMP_SQL_3%" echo prompt [판단 기준]
>>"%TMP_SQL_3%" echo prompt - 양호: 주기적으로 로그 저장, 백업, 감독되고 있는 경우
>>"%TMP_SQL_3%" echo prompt - 취약: 로그 저장, 백업, 감독하지 않는 경우
>>"%TMP_SQL_3%" echo prompt
>>"%TMP_SQL_3%" echo prompt [진단 방법]
>>"%TMP_SQL_3%" echo prompt   - 담당자에게 아래 내용을 질문하고 확인합니다.
>>"%TMP_SQL_3%" echo prompt     1) '정보통신망이용촉진 및 정보보호등에관한법률', '개인정보보호법', '회사사규' 등에 따라 최소 기간 이상 보관하고 있습니까?
>>"%TMP_SQL_3%" echo prompt     2) 접속 기록이 위변조가 되지 않도록 별도의 물리적인 저장 장치에 보관하고 정기적인 백업을 수행하고 있습니까?
>>"%TMP_SQL_3%" echo prompt
>>"%TMP_SQL_3%" echo prompt [진단 결론]
>>"%TMP_SQL_3%" echo prompt 수동 확인 필요: 담당자 인터뷰를 통해 로그 저장 주기를 확인해야 합니다.

REM -- [3.6] 세션 IDLE_TIMEOUT 설정 --
>>"%TMP_SQL_3%" echo prompt
>>"%TMP_SQL_3%" echo prompt ### [3.6] 세션 IDLE_TIMEOUT 설정 (IDLE_TIME) ###
>>"%TMP_SQL_3%" echo prompt
>>"%TMP_SQL_3%" echo prompt [판단 기준]
>>"%TMP_SQL_3%" echo prompt - 양호: IDLE_TIMEOUT이 5분 이하로 설정되어 있는 경우
>>"%TMP_SQL_3%" echo prompt - 취약: IDLE_TIMEOUT이 5분 초과로 설정되어 있는 경우
>>"%TMP_SQL_3%" echo prompt [SQL Command]
>>"%TMP_SQL_3%" echo prompt   select profile,resource_name,limit from dba_profiles where resource_name = 'IDLE_TIME';
>>"%TMP_SQL_3%" echo col profile format a20
>>"%TMP_SQL_3%" echo col resource_name format a15
>>"%TMP_SQL_3%" echo col limit format a10
>>"%TMP_SQL_3%" echo select profile, resource_name, limit from dba_profiles where resource_name = 'IDLE_TIME';
>>"%TMP_SQL_3%" echo prompt
>>"%TMP_SQL_3%" echo prompt [진단 결론]
>>"%TMP_SQL_3%" echo set heading off
>>"%TMP_SQL_3%" echo select case when count(*) ^>0 then '양호: 모든 프로파일의 세션 IDLE_TIMEOUT이 5분 이하로 설정되었습니다.' else '취약: 세션 IDLE_TIMEOUT이 5분을 초과하거나 제한이 없는 프로파일이 존재합니다.' end from (select limit from dba_profiles where resource_name = 'IDLE_TIME') where limit in ('UNLIMITED', 'DEFAULT') or (regexp_like(limit, '^[0-9]+$') and to_number(limit) ^> 5);
>>"%TMP_SQL_3%" echo set heading on

>>"%TMP_SQL_3%" echo spool off
>>"%TMP_SQL_3%" echo exit

echo [INFO] Chapter 3. Configuration Management Audit...
if defined ORA_CONN ( sqlplus -s "%ORA_CONN%" @"%TMP_SQL_3%" ) else ( sqlplus -s / as sysdba @"%TMP_SQL_3%" )
echo    - Report 3: "security_report_chapter_3.txt"


REM ====== 정리 및 완료 메시지 ======
del "%TMP_SQL_3%" >nul 2>nul

echo.
endlocal