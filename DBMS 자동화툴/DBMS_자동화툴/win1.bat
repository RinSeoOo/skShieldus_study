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
set "REPORT_FILE_1=%CD%\%OUTDIR%\security_report_chapter_1.txt"

REM ====== 임시 SQL 파일 경로 정의 ======
set "TMP_SQL_1=%TEMP%\ora_ch1_%RANDOM%.sql"

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
REM ====== 1장. 계정 관리 진단 SQL 생성 ======
REM =================================================================
> "%TMP_SQL_1%" echo set echo off feedback off verify off pages 999 trimspool on
>>"%TMP_SQL_1%" echo set linesize 120
>>"%TMP_SQL_1%" echo whenever sqlerror continue
>>"%TMP_SQL_1%" echo spool "%REPORT_FILE_1%"
>>"%TMP_SQL_1%" echo prompt [1장. 계정 관리] Oracle DB 보안 점검 자동 진단 보고서
>>"%TMP_SQL_1%" echo prompt =================================================================

REM -- [1.1] 불필요한 계정 확인 --
>>"%TMP_SQL_1%" echo prompt
>>"%TMP_SQL_1%" echo prompt ### [1.1] 불필요한 계정 확인 ###
>>"%TMP_SQL_1%" echo prompt [판단 기준]
>>"%TMP_SQL_1%" echo prompt  - 양호: 불필요한 Default 계정 및 테스트 계정이 비활성화(잠금) 되어 있는 경우
>>"%TMP_SQL_1%" echo prompt  - 취약: 불필요한 Default 계정 또는 테스트 계정이 활성화(OPEN) 상태인 경우
>>"%TMP_SQL_1%" echo prompt [SQL Command] 
>>"%TMP_SQL_1%" echo prompt   select username, account_status from dba_users where account_status='OPEN' and username not in ('AWR_STAGE','AUDSYS','CSMIG','CTXSYS','DIP','DBSNMP','DEMO','DGPDB_INT','DMSYS','DSSYS','DVF','DVSYS','EXFSYS','GGSYS','GSMADMIN_INTERNAL','GSMCATUSER','GSMUSER','LBACSYS','MDSYS','MGMT_VIEW','OLAPSYS','OWBSYS','ORACLE_OCM','ORDDATA','ORDPLUGINS','ORDSYS','OUTLN','SI_INFORMTN_SCHEMA','SYS','SYSBACKUP','SYSDG','SYSKM','SYSRAC','SYSMAN','SYSTEM','TRACESVR','TSMSYS','WK_TEST','WKSYS','WKPROXY','WMSYS','XDB','ODM','PERFSTAT','IMP_FULL_DATABASE','FLOWS_030000');
>>"%TMP_SQL_1%" echo prompt 
>>"%TMP_SQL_1%" echo col username format a20
>>"%TMP_SQL_1%" echo col account_status format a20
>>"%TMP_SQL_1%" echo select username, account_status from dba_users where account_status='OPEN' and username not in ('AWR_STAGE','AUDSYS','CSMIG','CTXSYS','DIP','DBSNMP','DEMO','DGPDB_INT','DMSYS','DSSYS','DVF','DVSYS','EXFSYS','GGSYS','GSMADMIN_INTERNAL','GSMCATUSER','GSMUSER','LBACSYS','MDSYS','MGMT_VIEW','OLAPSYS','OWBSYS','ORACLE_OCM','ORDDATA','ORDPLUGINS','ORDSYS','OUTLN','SI_INFORMTN_SCHEMA','SYS','SYSBACKUP','SYSDG','SYSKM','SYSRAC','SYSMAN','SYSTEM','TRACESVR','TSMSYS','WK_TEST','WKSYS','WKPROXY','WMSYS','XDB','ODM','PERFSTAT','IMP_FULL_DATABASE','FLOWS_030000');
>>"%TMP_SQL_1%" echo clear columns
>>"%TMP_SQL_1%" echo prompt
>>"%TMP_SQL_1%" echo prompt [진단 결론]
>>"%TMP_SQL_1%" echo set heading off
>>"%TMP_SQL_1%" echo SELECT CASE WHEN COUNT(*) = 0 THEN '양호: 현재 불필요한 계정이 존재하지 않습니다.' ELSE '수동 확인 필요: 위 목록에서 불필요한 계정이 있는지 직접 확인하고 조치해야 합니다.' END FROM dba_users WHERE account_status = 'OPEN' AND username NOT IN ('AWR_STAGE','AUDSYS','CSMIG','CTXSYS','DIP','DBSNMP','DEMO','DGPDB_INT','DMSYS','DSSYS','DVF','DVSYS','EXFSYS','GGSYS','GSMADMIN_INTERNAL','GSMCATUSER','GSMUSER','LBACSYS','MDSYS','MGMT_VIEW','OLAPSYS','OWBSYS','ORACLE_OCM','ORDDATA','ORDPLUGINS','ORDSYS','OUTLN','SI_INFORMTN_SCHEMA','SYS','SYSBACKUP','SYSDG','SYSKM','SYSRAC','SYSMAN','SYSTEM','TRACESVR','TSMSYS','WK_TEST','WKSYS','WKPROXY','WMSYS','XDB','ODM','PERFSTAT','IMP_FULL_DATABASE','FLOWS_030000');
>>"%TMP_SQL_1%" echo set heading on

REM -- [1.2] 무제한 로그인 시도 차단 --
>>"%TMP_SQL_1%" echo prompt 
>>"%TMP_SQL_1%" echo prompt ### [1.2] 무제한 로그인 시도 차단 (FAILED_LOGIN_ATTEMPTS) ###
>>"%TMP_SQL_1%" echo prompt [판단 기준]
>>"%TMP_SQL_1%" echo prompt  - 양호: FAILED_LOGIN_ATTEMPTS 설정이 10 이하의 값으로 설정된 경우
>>"%TMP_SQL_1%" echo prompt  - 취약: FAILED_LOGIN_ATTEMPTS 설정이 'UNLIMITED' 또는 10을 초과하는 경우
>>"%TMP_SQL_1%" echo prompt [SQL Command]
>>"%TMP_SQL_1%" echo prompt   select profile, limit from dba_profiles where resource_name = 'FAILED_LOGIN_ATTEMPTS' order by profile;
>>"%TMP_SQL_1%" echo col profile format a20
>>"%TMP_SQL_1%" echo col limit format a10
>>"%TMP_SQL_1%" echo select profile, limit from dba_profiles where resource_name = 'FAILED_LOGIN_ATTEMPTS' order by profile;
>>"%TMP_SQL_1%" echo clear columns
>>"%TMP_SQL_1%" echo prompt 
>>"%TMP_SQL_1%" echo prompt [진단 결론]
>>"%TMP_SQL_1%" echo set heading off
>>"%TMP_SQL_1%" echo select case when count(*)=0 then '양호: 모든 프로파일이 로그인 실패 횟수 제한을 충족합니다.' else '취약: 로그인 실패 횟수 제한이 없거나 10회를 초과하는 프로파일이 존재합니다.' end from (select limit from dba_profiles where resource_name = 'FAILED_LOGIN_ATTEMPTS') where limit = 'UNLIMITED' or (regexp_like(limit, '^[0-9]+$') and to_number(limit) ^> 10);
>>"%TMP_SQL_1%" echo set heading on

REM -- [1.3] 패스워드 주기적 변경 --
>>"%TMP_SQL_1%" echo prompt
>>"%TMP_SQL_1%" echo prompt ### [1.3] 패스워드 주기적 변경 (PASSWORD_LIFE_TIME) ###
>>"%TMP_SQL_1%" echo prompt [판단 기준]
>>"%TMP_SQL_1%" echo prompt  - 양호: PASSWORD_LIFE_TIME 값이 60 이하로 설정된 경우
>>"%TMP_SQL_1%" echo prompt  - 취약: PASSWORD_LIFE_TIME 값이 'UNLIMITED' 또는 60을 초과하는 경우
>>"%TMP_SQL_1%" echo prompt [SQL Command]
>>"%TMP_SQL_1%" echo prompt   select resource_name, limit from user_password_limits where resource_name in ('PASSWORD_LIFE_TIME');
>>"%TMP_SQL_1%" echo col resource_name format a20
>>"%TMP_SQL_1%" echo col limit format a10
>>"%TMP_SQL_1%" echo select resource_name, limit from user_password_limits where resource_name in ('PASSWORD_LIFE_TIME');
>>"%TMP_SQL_1%" echo clear columns
>>"%TMP_SQL_1%" echo prompt
>>"%TMP_SQL_1%" echo prompt [진단 결론]
>>"%TMP_SQL_1%" echo set heading off
>>"%TMP_SQL_1%" echo select case when count(*)=0 then '양호: 모든 프로파일의 패스워드 만료 기간이 60일 이하로 설정되었습니다.' else '취약: 패스워드 만료 기간이 60일을 초과하거나 무제한인 프로파일이 존재합니다.' end from (select limit from user_password_limits where resource_name = 'PASSWORD_LIFE_TIME') where limit = 'UNLIMITED' or (regexp_like(limit, '^[0-9]+$') and to_number(limit) ^> 60);
>>"%TMP_SQL_1%" echo set heading on

REM -- [1.4] 패스워드 복잡도 설정 --
>>"%TMP_SQL_1%" echo prompt
>>"%TMP_SQL_1%" echo prompt ### [1.4] 패스워드 복잡도 설정 (PASSWORD_VERIFY_FUNCTION) ###
>>"%TMP_SQL_1%" echo prompt [판단 기준]
>>"%TMP_SQL_1%" echo prompt  - 양호: 패스워드 복잡도를 검증하는 함수(PASSWORD_VERIFY_FUNCTION)가 설정된 경우
>>"%TMP_SQL_1%" echo prompt  - 취약: 패스워드 검증 함수가 설정되지 않은 경우 (NULL)
>>"%TMP_SQL_1%" echo prompt [SQL Command]
>>"%TMP_SQL_1%" echo prompt   select profile, limit from dba_profiles where resource_name = 'PASSWORD_VERIFY_FUNCTION' order by profile;
>>"%TMP_SQL_1%" echo col profile format a20
>>"%TMP_SQL_1%" echo col limit format a30
>>"%TMP_SQL_1%" echo select profile, limit from dba_profiles where resource_name = 'PASSWORD_VERIFY_FUNCTION' order by profile;
>>"%TMP_SQL_1%" echo clear columns
>>"%TMP_SQL_1%" echo prompt
>>"%TMP_SQL_1%" echo prompt [진단 결론]
>>"%TMP_SQL_1%" echo set heading off
>>"%TMP_SQL_1%" echo select case when count(*)=0 then '양호: 패스워드 검증 함수가 설정되지 않은 프로파일이 없습니다.' else '취약: 패스워드 검증 함수가 설정되지 않은 프로파일(NULL)이 존재합니다.' end from dba_profiles where resource_name = 'PASSWORD_VERIFY_FUNCTION' and limit = 'NULL';
>>"%TMP_SQL_1%" echo set heading on

REM -- [1.5] 취약한 패스워드 사용 점검 (인터뷰) --
>>"%TMP_SQL_1%" echo prompt
>>"%TMP_SQL_1%" echo prompt ### [1.5] 취약한 패스워드 사용 점검 (인터뷰) ###
>>"%TMP_SQL_1%" echo prompt [판단 기준]
>>"%TMP_SQL_1%" echo prompt  - 양호: 추측하기 쉬운 패스워드(사전 단어, 연속된 문자 등) 사용을 금지하고 주기적으로 점검하는 경우
>>"%TMP_SQL_1%" echo prompt  - 취약: 취약한 패스워드에 대한 사용 제한 정책이 없는 경우
>>"%TMP_SQL_1%" echo prompt
>>"%TMP_SQL_1%" echo prompt [진단 방법]
>>"%TMP_SQL_1%" echo prompt  - 담당자에게 아래 내용을 질문하고 확인합니다.
>>"%TMP_SQL_1%" echo prompt    1) 계정명과 동일하거나 유사한 패스워드, 사전에 있는 단어 등을 금지하는 정책이 있습니까?
>>"%TMP_SQL_1%" echo prompt    2) 주기적으로 취약한 패스워드를 사용하는 계정이 있는지 점검하고 조치합니까?
>>"%TMP_SQL_1%" echo prompt
>>"%TMP_SQL_1%" echo prompt [진단 결론]
>>"%TMP_SQL_1%" echo prompt 수동 확인 필요: 담당자 인터뷰를 통해 취약한 패스워드 관리 정책을 확인해야 합니다.

REM --- ★★★ 중요: SQL 스크립트는 여기서 끝냅니다 ★★★ ---
>>"%TMP_SQL_1%" echo spool off
>>"%TMP_SQL_1%" echo exit

REM --- SQL 스크립트 실행 ---
echo [INFO] Auditing Chapter 1 (1.1 ~ 1.5)...
if defined ORA_CONN ( sqlplus -s "%ORA_CONN%" @"%TMP_SQL_1%" ) else ( sqlplus -s / as sysdba @"%TMP_SQL_1%" )


REM --- ★★★ 중요: [1.6] OS 점검은 SQL 종료 후 배치 파일에서 직접 실행 ★★★ ---
echo [INFO] Auditing Chapter 1 (1.6)...
(
    echo.
    echo ### [1.6] OS DBA 그룹 멤버 확인 ###
    echo [판단 기준]
    echo  - 양호: 불필요한 계정이 ORA_DBA 그룹에 존재하지 않는 경우
    echo  - 취약: 불필요한 계정이 ORA_DBA 그룹에 존재하는 경우
    echo.
    echo [OS Command] 
    echo net localgroup "ORA_DBA"
) >> "%REPORT_FILE_1%"

net localgroup "ORA_DBA" >> "%REPORT_FILE_1%" 2>nul

(
    echo.
    echo [진단 결론]
) >> "%REPORT_FILE_1%"

set "VULN_MEMBERS="
set "reading_members=0"
for /f "tokens=*" %%a in ('net localgroup "ORA_DBA" 2^>nul') do (
    set "line=%%a"
    if /i "!line!"=="The command completed successfully." goto end_loop_1_6
    
    if !reading_members! == 1 (
        if not defined line goto end_loop_1_6
        for /f "tokens=*" %%b in ("!line!") do set "member=%%b"
        if /i not "!member!"=="Administrator" if /i not "!member!"=="oracle" if /i not "!member!"=="NT AUTHORITY\SYSTEM" (
            if defined VULN_MEMBERS (
                set "VULN_MEMBERS=!VULN_MEMBERS!, !member!"
            ) else (
                set "VULN_MEMBERS=!member!"
            )
        )
    )
    if "!line:~0,5!"=="-----" set "reading_members=1"
)
:end_loop_1_6

if defined VULN_MEMBERS (
    >>"%REPORT_FILE_1%" echo 수동 확인 필요: 불필요한 계정이 ORA_DBA 그룹에 존재합니다. (대상: !VULN_MEMBERS!)
) else (
    >>"%REPORT_FILE_1%" echo 양호: ORA_DBA 그룹에 불필요한 계정이 존재하지 않습니다. (Administrator, oracle, NT AUTHORITY\SYSTEM 제외)
)


REM ====== 정리 및 완료 메시지 ======
del "%TMP_SQL_1%" >nul 2>nul
echo.
echo [OK] Oracle security chapter 1 report created.
echo   - Folder: "%OUTDIR%"
echo   - Report File: "security_report_chapter_1.txt"


echo.
endlocal