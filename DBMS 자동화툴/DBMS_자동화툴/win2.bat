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
set "REPORT_FILE_2=%CD%\%OUTDIR%\security_report_chapter_2.txt"

REM ====== 임시 SQL 파일 경로 정의 ======
set "TMP_SQL_2=%TEMP%\ora_ch2_%RANDOM%.sql"

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
REM ====== [2.8] 항목 진단을 위해 파일 내용을 미리 검사 (수정된 부분) ======
REM =================================================================
REM 1. 기본 진단 결과를 '취약'으로 설정
set "AUTH_RESULT=취약: 파라미터가 설정되지 않아 기본값(NTS)으로 동작할 수 있습니다."

REM 2. sqlnet.ora 파일이 존재하는지 확인 후 라인 검색
if exist "!FOUND_TNS_ADMIN_PATH!\sqlnet.ora" (
    set "AUTH_LINE="
    for /f "tokens=*" %%a in ('type "!FOUND_TNS_ADMIN_PATH!\sqlnet.ora" 2^>nul ^| findstr /I "SQLNET.AUTHENTICATION_SERVICES"') do (
        set "AUTH_LINE=%%a"
    )

    REM 3. 찾아낸 라인(변수)의 내용을 바탕으로 최종 결과 판단
    if defined AUTH_LINE (
        echo !AUTH_LINE! | findstr /I /C:"(NONE)" >nul
        if !errorlevel! equ 0 (
            set "AUTH_RESULT=양호: OS 인증(NTS)이 아닌 데이터베이스 인증(NONE)을 사용합니다."
        ) else (
            echo !AUTH_LINE! | findstr /I /C:"(NTS)" >nul
            if !errorlevel! equ 0 (
                set "AUTH_RESULT=취약: OS 인증(NTS)을 사용하도록 설정되어 있습니다."
            )
        )
    )
)


REM =================================================================
REM ====== 2장. 권한 관리 진단 SQL 생성 ======
REM =================================================================
> "%TMP_SQL_2%" echo set echo off feedback off verify off pages 999 trimspool on
>>"%TMP_SQL_2%" echo set linesize 120
>>"%TMP_SQL_2%" echo whenever sqlerror continue
>>"%TMP_SQL_2%" echo spool "%REPORT_FILE_2%"
>>"%TMP_SQL_2%" echo prompt [2장. 권한 관리] Oracle DB 보안 점검 자동 진단 보고서
>>"%TMP_SQL_2%" echo prompt =================================================================

REM -- [2.1] 개발 및 운영 시스템 분리 사용 (인터뷰) --
>>"%TMP_SQL_2%" echo prompt
>>"%TMP_SQL_2%" echo prompt ### [2.1] 개발 및 운영 시스템 분리 사용 (인터뷰) ###
>>"%TMP_SQL_2%" echo prompt [판단 기준]
>>"%TMP_SQL_2%" echo prompt  - 양호: 개발, 시험, 운영 환경의 DB가 물리적 또는 논리적으로 분리되어 운영되는 경우
>>"%TMP_SQL_2%" echo prompt  - 취약: 개발 DB와 운영 DB가 분리되지 않고, 동일한 계정으로 접근 가능한 경우
>>"%TMP_SQL_2%" echo prompt
>>"%TMP_SQL_2%" echo prompt [진단 방법]
>>"%TMP_SQL_2%" echo prompt  - 담당자에게 아래 내용을 질문하고 확인합니다.
>>"%TMP_SQL_2%" echo prompt    1) 개발, 시험, 운영 환경의 데이터베이스는 분리되어 있습니까?
>>"%TMP_SQL_2%" echo prompt    2) 개발자가 운영 DB에 직접 접근할 수 있습니까? 접근 정책은 어떻게 됩니까?
>>"%TMP_SQL_2%" echo prompt
>>"%TMP_SQL_2%" echo prompt [진단 결론]
>>"%TMP_SQL_2%" echo prompt 수동 확인 필요: 담당자 인터뷰를 통해 시스템 분리 정책을 확인해야 합니다.

REM -- [2.2] Public에 대한 권한 제한 --
>>"%TMP_SQL_2%" echo prompt
>>"%TMP_SQL_2%" echo prompt ### [2.2] Public 롤에 대한 권한 제한 ###
>>"%TMP_SQL_2%" echo prompt [판단 기준]
>>"%TMP_SQL_2%" echo prompt  - 양호: Public 롤에 불필요한 실행(EXECUTE) 또는 수정(UPDATE, DELETE 등) 권한이 없는 경우
>>"%TMP_SQL_2%" echo prompt  - 취약: Public 롤에 과도하거나 불필요한 권한이 부여된 경우
>>"%TMP_SQL_2%" echo prompt
>>"%TMP_SQL_2%" echo prompt [SQL Command]
>>"%TMP_SQL_2%" echo prompt   select owner,table_name,privilege from dba_tab_privs where grantee='PUBLIC' and owner not in ('SYS','CTXSYS','MDSYS','ODM','OLAPSYS','TSMSYS','ORDPLUGINS','ORDSYS','SYSTEM','WKSYS','WMSYS','XDB','LBACSYS','PERFSTAT','SYSMAN','DMSYS','EXFSYS','WK_TEST','IMP_FULL_DATABASE','FLOWS_030000','MGMT_VIEW');
>>"%TMP_SQL_2%" echo col owner format a20
>>"%TMP_SQL_2%" echo col table_name format a30
>>"%TMP_SQL_2%" echo col privilege format a10
>>"%TMP_SQL_2%" echo col grantable format a10
>>"%TMP_SQL_2%" echo select owner,table_name,privilege from dba_tab_privs where grantee='PUBLIC' and owner not in ('SYS','CTXSYS','MDSYS','ODM','OLAPSYS','TSMSYS','ORDPLUGINS','ORDSYS','SYSTEM','WKSYS','WMSYS','XDB','LBACSYS','PERFSTAT','SYSMAN','DMSYS','EXFSYS','WK_TEST','IMP_FULL_DATABASE','FLOWS_030000','MGMT_VIEW');
>>"%TMP_SQL_2%" echo clear columns
>>"%TMP_SQL_2%" echo prompt
>>"%TMP_SQL_2%" echo prompt [진단 결론]
>>"%TMP_SQL_2%" echo set heading off
>>"%TMP_SQL_2%" echo select case when count(*)=0 then '양호: PUBLIC 롤에 위험한 실행/수정 권한이 없습니다.' else '수동 확인 필요: PUBLIC 롤에 과도한 실행/수정 권한이 존재할 수 있습니다. 점검이 필요합니다.' end from dba_tab_privs where grantee='PUBLIC' and privilege in ('EXECUTE', 'UPDATE', 'INSERT', 'DELETE', 'ALTER', 'DEBUG', 'FLASHBACK', 'MERGE VIEW') and owner not in ('SYS','CTXSYS','MDSYS','ODM','OLAPSYS','TSMSYS','ORDPLUGINS','ORDSYS','SYSTEM','WKSYS','WMSYS','XDB','LBACSYS','PERFSTAT','SYSMAN','DMSYS','EXFSYS','WK_TEST','IMP_FULL_DATABASE','FLOWS_030000','MGMT_VIEW');
>>"%TMP_SQL_2%" echo set heading on

REM -- [2.3] SYS.LINK$ 테이블 접근 제한 --
>>"%TMP_SQL_2%" echo prompt
>>"%TMP_SQL_2%" echo prompt ### [2.3] SYS.LINK$ 테이블 접근 제한 ###
>>"%TMP_SQL_2%" echo prompt [판단 기준]
>>"%TMP_SQL_2%" echo prompt  - 양호: DBA 역할이 없는 계정에 SYS.LINK$ 테이블 접근 권한이 없는 경우
>>"%TMP_SQL_2%" echo prompt  - 취약: DBA 역할이 없는 계정에 SYS.LINK$ 테이블 접근 권한이 부여된 경우
>>"%TMP_SQL_2%" echo prompt
>>"%TMP_SQL_2%" echo prompt [SQL Command]
>>"%TMP_SQL_2%" echo prompt   select grantee, privilege from dba_tab_privs where owner='SYS' and table_name='LINK$' and grantee not in ('SYS','SYSTEM','DBA') order by grantee, privilege;
>>"%TMP_SQL_2%" echo col grantee format a30
>>"%TMP_SQL_2%" echo col privilege format a20
>>"%TMP_SQL_2%" echo select grantee, privilege from dba_tab_privs where owner='SYS' and table_name='LINK$' and grantee not in ('SYS','SYSTEM','DBA') order by grantee, privilege;
>>"%TMP_SQL_2%" echo clear columns
>>"%TMP_SQL_2%" echo prompt
>>"%TMP_SQL_2%" echo prompt [진단 결론]
>>"%TMP_SQL_2%" echo set heading off
>>"%TMP_SQL_2%" echo select case when count(*)=0 then '양호: 불필요한 계정에 권한이 없습니다.' else '취약: 아래 계정에 불필요한 권한이 존재합니다.' end from dba_tab_privs where owner='SYS' and table_name='LINK$' and grantee not in ('SYS','SYSTEM','DBA');
>>"%TMP_SQL_2%" echo set heading on

REM -- [2.4] SYSDBA 권한 제한 --
>>"%TMP_SQL_2%" echo prompt
>>"%TMP_SQL_2%" echo prompt ### [2.4] SYSDBA 권한 제한 ###
>>"%TMP_SQL_2%" echo prompt [판단 기준]
>>"%TMP_SQL_2%" echo prompt  - 양호: SYS 계정을 제외한 다른 계정에 SYSDBA 권한이 없는 경우
>>"%TMP_SQL_2%" echo prompt  - 취약: SYS 계정 외에 SYSDBA 권한을 가진 계정이 존재하는 경우
>>"%TMP_SQL_2%" echo prompt
>>"%TMP_SQL_2%" echo prompt [SQL Command]
>>"%TMP_SQL_2%" echo prompt   select username,sysdba,sysoper from v$pwfile_users where username not in (select grantee from dba_role_privs where granted_role='DBA' and username ^^!='INTERNAL' and sysdba='TRUE');
>>"%TMP_SQL_2%" echo col username format a30
>>"%TMP_SQL_2%" echo select username,sysdba,sysoper from v$pwfile_users where username not in (select grantee from dba_role_privs where granted_role='DBA' and username ^^!='INTERNAL' and sysdba='TRUE');
>>"%TMP_SQL_2%" echo clear columns
>>"%TMP_SQL_2%" echo prompt
>>"%TMP_SQL_2%" echo prompt [진단 결론]
>>"%TMP_SQL_2%" echo set heading off
>>"%TMP_SQL_2%" echo select case when count(*) = 0 then '양호: SYS 외 SYSDBA 권한 계정이 없습니다.' else '취약: SYS 외에 SYSDBA 권한을 가진 계정이 존재합니다.' end AS "진단 결과" from v$pwfile_users where username not in (select grantee from dba_role_privs where granted_role='DBA' and username ^^!='INTERNAL' and sysdba='TRUE');
>>"%TMP_SQL_2%" echo set heading on

REM -- [2.5] DBA 권한 제한 --
>>"%TMP_SQL_2%" echo prompt
>>"%TMP_SQL_2%" echo prompt ### [2.5] DBA 권한 제한 ###
>>"%TMP_SQL_2%" echo prompt [판단 기준]
>>"%TMP_SQL_2%" echo prompt  - 양호: SYS, SYSTEM 외에 DBA 롤을 가진 불필요한 계정이 없는 경우
>>"%TMP_SQL_2%" echo prompt  - 취약: SYS, SYSTEM 외에 DBA 롤을 가진 계정이 존재하는 경우
>>"%TMP_SQL_2%" echo prompt
>>"%TMP_SQL_2%" echo prompt [SQL Command]
>>"%TMP_SQL_2%" echo prompt   select grantee from dba_role_privs where granted_role='DBA' and grantee not in ('SYS','SYSTEM','WKSYS','CTXSYS','CSTA','SYSMAN'); 
>>"%TMP_SQL_2%" echo col grantee format a30
>>"%TMP_SQL_2%" echo select grantee from dba_role_privs where granted_role='DBA' and grantee not in ('SYS','SYSTEM','WKSYS','CTXSYS','CSTA','SYSMAN'); 
>>"%TMP_SQL_2%" echo clear columns
>>"%TMP_SQL_2%" echo prompt
>>"%TMP_SQL_2%" echo prompt [진단 결론]
>>"%TMP_SQL_2%" echo set heading off
>>"%TMP_SQL_2%" echo select case when count(*) = 0 then '양호: 기본 관리자 외 DBA 롤을 가진 계정이 없습니다.' else '수동 확인 필요: 기본 관리자 외 DBA 롤을 가진 계정이 있는지 확인해야 합니다.' end AS "진단 결과" from dba_role_privs where granted_role='DBA' and grantee not in ('SYS','SYSTEM','WKSYS','CTXSYS','CSTA','SYSMAN');
>>"%TMP_SQL_2%" echo set heading on

REM -- [2.6] with grant option 사용 제한 --
>>"%TMP_SQL_2%" echo prompt
>>"%TMP_SQL_2%" echo prompt ### [2.6] with grant option 사용 제한 ###
>>"%TMP_SQL_2%" echo prompt [판단 기준]
>>"%TMP_SQL_2%" echo prompt  - 양호: with grant option이 적절한 사용자에게 부여되어 있는 경우  
>>"%TMP_SQL_2%" echo prompt  - 취약: with grant option이 적절한 사용자에게 부여되어 있지 않은 경우
>>"%TMP_SQL_2%" echo prompt
>>"%TMP_SQL_2%" echo prompt [SQL Command]
>>"%TMP_SQL_2%" echo prompt   select grantee,owner,table_name,grantable from dba_tab_privs where grantable='YES' and owner not in (select distinct owner from dba_objects) and grantee not in (select grantee from dba_role_privs where granted_role='DBA') order by grantee;
>>"%TMP_SQL_2%" echo col grantee format a10
>>"%TMP_SQL_2%" echo col owner format a10
>>"%TMP_SQL_2%" echo col table_name format a25
>>"%TMP_SQL_2%" echo col grantable format a15
>>"%TMP_SQL_2%" echo select grantee,owner,table_name,grantable from dba_tab_privs where grantable='YES' and owner not in (select distinct owner from dba_objects) and grantee not in (select grantee from dba_role_privs where granted_role='DBA') order by grantee;
>>"%TMP_SQL_2%" echo clear columns
>>"%TMP_SQL_2%" echo prompt
>>"%TMP_SQL_2%" echo prompt [진단 결론]
>>"%TMP_SQL_2%" echo set heading off
>>"%TMP_SQL_2%" echo select case when count(*)=0 then '양호: WITH GRANT OPTION 권한이 적절하게 관리되고 있습니다.' else '취약: DBA 역할이 없는 사용자에게 WITH GRANT OPTION이 부여된 권한이 있습니다.' end from dba_tab_privs where grantable='YES' and grantee not in (select distinct owner from dba_objects) and grantee not in (select grantee from dba_role_privs where granted_role='DBA');
>>"%TMP_SQL_2%" echo set heading on


REM -- [2.7] with admin option 사용 제한 --
>>"%TMP_SQL_2%" echo prompt
>>"%TMP_SQL_2%" echo prompt ### [2.7] with admin option 사용 제한 ###
>>"%TMP_SQL_2%" echo prompt
>>"%TMP_SQL_2%" echo prompt [판단 기준]
>>"%TMP_SQL_2%" echo prompt  - 양호: with admin option이 적절한 사용자에게 부여되어 있는 경우  
>>"%TMP_SQL_2%" echo prompt  - 취약: with admin option이 적절한 사용자에게 부여되어 있지 않은 경우
>>"%TMP_SQL_2%" echo prompt
>>"%TMP_SQL_2%" echo prompt [SQL Command]
>>"%TMP_SQL_2%" echo prompt   select grantee,privilege from dba_sys_privs where grantee not in ('SYS','SYSTEM','AQ_ADMINISTRATOR_ROLE','DBA','MDSYS','LBACSYS','SCHEDULER_ADMIN',' MSYS') and admin_option='YES' and grantee not in (select grantee from dba_role_privs where granted_role='DBA');
>>"%TMP_SQL_2%" echo col grantee format a20
>>"%TMP_SQL_2%" echo col privilege format a30
>>"%TMP_SQL_2%" echo select grantee,privilege from dba_sys_privs where grantee not in ('SYS','SYSTEM','AQ_ADMINISTRATOR_ROLE','DBA','MDSYS','LBACSYS','SCHEDULER_ADMIN',' MSYS') and admin_option='YES' and grantee not in (select grantee from dba_role_privs where granted_role='DBA'); 
>>"%TMP_SQL_2%" echo clear columns
>>"%TMP_SQL_2%" echo prompt
>>"%TMP_SQL_2%" echo prompt [진단 결론]
>>"%TMP_SQL_2%" echo set heading off
>>"%TMP_SQL_2%" echo select case when count(*)=0 then '양호: WITH ADMIN OPTION 권한이 적절하게 관리되고 있습니다.' else '수동 확인 필요: 불필요한 사용자에게 WITH ADMIN OPTION이 부여된 시스템 권한이 있습니다.' end from dba_sys_privs where grantee not in ('SYS','SYSTEM','AQ_ADMINISTRATOR_ROLE','DBA','MDSYS','LBACSYS','SCHEDULER_ADMIN',' MSYS') and admin_option='YES' and grantee not in (select grantee from dba_role_privs where granted_role='DBA');
>>"%TMP_SQL_2%" echo set heading on

REM -- [2.8] SYS 계정 인증 방식 설정 (sqlnet.ora 파일 확인)--
>>"%TMP_SQL_2%" echo prompt
>>"%TMP_SQL_2%" echo prompt ### [2.8] SYS 계정 인증 방식 설정 (SQLNET.AUTHENTICATION_SERVICES) ###
>>"%TMP_SQL_2%" echo prompt [판단 기준]
>>"%TMP_SQL_2%" echo prompt  - 양호: sqlnet.ora 파일에 SQLNET.AUTHENTICATION_SERVICES 파라미터가 (NONE)으로 설정된 경우
>>"%TMP_SQL_2%" echo prompt  - 취약: 해당 파라미터가 없거나, 값이 (NTS)로 설정된 경우
>>"%TMP_SQL_2%" echo prompt
>>"%TMP_SQL_2%" echo prompt [OS Command]
>>"%TMP_SQL_2%" echo prompt    host type "!FOUND_TNS_ADMIN_PATH!\sqlnet.ora" 2^>nul ^| findstr /I "SQLNET.AUTHENTICATION_SERVICES"

REM >>"%TMP_SQL_2%" echo host type "!FOUND_TNS_ADMIN_PATH!\sqlnet.ora" 2^>nul ^| findstr /I "SQLNET.AUTHENTICATION_SERVICES"
>>"%TMP_SQL_2%" echo host findstr /I "SQLNET.AUTHENTICATION_SERVICES" "!FOUND_TNS_ADMIN_PATH!\sqlnet.ora"

>>"%TMP_SQL_2%" echo prompt
>>"%TMP_SQL_2%" echo prompt [진단 결론]
REM --- 미리 생성한 진단 결과 변수를 SQL 파일에 기록 ---
>>"%TMP_SQL_2%" echo prompt !AUTH_RESULT!
>>"%TMP_SQL_2%" echo prompt


REM -- [2.9] CREATE ANY DIRECTORY 권한 제한 --
>>"%TMP_SQL_2%" echo prompt
>>"%TMP_SQL_2%" echo prompt ### [2.9] CREATE ANY DIRECTORY 권한 제한 ###
>>"%TMP_SQL_2%" echo prompt
>>"%TMP_SQL_2%" echo prompt [판단 기준]
>>"%TMP_SQL_2%" echo prompt  - 양호: 'CREATE ANY DIRECTORY' 권한이 불필요한 계정에 부여되지 않은 경우
>>"%TMP_SQL_2%" echo prompt  - 취약: 'CREATE ANY DIRECTORY' 권한이 불필요한 계정에 부여된 경우
>>"%TMP_SQL_2%" echo prompt
>>"%TMP_SQL_2%" echo prompt [SQL Command]
>>"%TMP_SQL_2%" echo prompt    select grantee,privilege from dba_sys_privs where privilege='CREATE ANY DIRECTORY' and grantee not in('DBA','IMP_FULL_DATABASE','WKSYS','SYS','SYSDBA'); 
>>"%TMP_SQL_2%" echo col grantee format a20
>>"%TMP_SQL_2%" echo col privilege format a30
>>"%TMP_SQL_2%" echo select grantee,privilege from dba_sys_privs where privilege='CREATE ANY DIRECTORY' and grantee not in('DBA','IMP_FULL_DATABASE','WKSYS','SYS','SYSDBA'); 
>>"%TMP_SQL_2%" echo clear columns
>>"%TMP_SQL_2%" echo prompt
>>"%TMP_SQL_2%" echo prompt [진단 결론]
>>"%TMP_SQL_2%" echo set heading off
>>"%TMP_SQL_2%" echo select case when count(*)=0 then '양호: CREATE ANY DIRECTORY 권한이 적절하게 관리되고 있습니다.' else '취약: (수동 확인 필요) 불필요한 사용자에게 CREATE ANY DIRECTORY 권한이 부여되었습니다.' end from dba_sys_privs where privilege='CREATE ANY DIRECTORY' and grantee not in('DBA','IMP_FULL_DATABASE','WKSYS','SYS','SYSDBA','SYSBACKUP');
>>"%TMP_SQL_2%" echo set heading on

>>"%TMP_SQL_2%" echo spool off
>>"%TMP_SQL_2%" echo exit;

echo [INFO] Chapter 2. Privilege Management Audit...
if defined ORA_CONN ( sqlplus -s "%ORA_CONN%" @"%TMP_SQL_2%" ) else ( sqlplus -s / as sysdba @"%TMP_SQL_2%" )
echo    - Report 2: "security_report_chapter_2.txt"

REM ====== 정리 및 완료 메시지 ======
del "%TMP_SQL_2%" >nul 2>nul

echo.
endlocal