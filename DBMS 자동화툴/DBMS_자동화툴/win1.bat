@echo off
setlocal enableextensions enabledelayedexpansion

REM ====== ����� ����(�ʿ�� ����) ======
REM OS ������ �� �Ǹ� ORA_CONN�� ä���ּ��� (��: system/Passw0rd@//127.0.0.1:1521/ORCLPDB1)
set "ORA_CONN=c##test/1234@//10.0.8.8:1521/XE"

REM Oracle Client(sqlplus.exe) �� PATH�� �־�� �մϴ�.
where sqlplus >nul 2>nul || (
  echo [ERROR] sqlplus.exe not found in PATH. Install Oracle Client or add to PATH.
  exit /b 1
)


REM ====== ���� ���� ��� ���� ======
set "REPORT_FILE_1=%CD%\%OUTDIR%\security_report_chapter_1.txt"

REM ====== �ӽ� SQL ���� ��� ���� ======
set "TMP_SQL_1=%TEMP%\ora_ch1_%RANDOM%.sql"

REM ====== ORACLE ȯ�溯�� �ʱ�ȭ ======
set "FOUND_ORACLE_HOME="
set "FOUND_ORACLE="
set "FOUND_TNS_ADMIN_PATH="

REM --- 1�ܰ�: ������Ʈ������ ORACLE_HOME ã�� ---
for /f "tokens=*" %%k in ('reg query "HKLM\SOFTWARE\ORACLE" /reg:64 2^>nul') do (
    if not defined FOUND_ORACLE_HOME (
        for /f "tokens=2,*" %%i in ('reg query "%%k" /v ORACLE_HOME /reg:64 2^>nul ^| findstr /I "ORACLE_HOME"') do (
            set "TEMP_ORACLE_HOME=%%j"
            REM -- ��� ���� ��� ������ ������ �Ϻ��ϰ� �����մϴ�.
            for /f "tokens=*" %%x in ("!TEMP_ORACLE_HOME!") do set "FOUND_ORACLE_HOME=%%x"

            REM --- �ڡڡ� ���� ���� ��θ� ���ο� FOUND_ORACLE ������ ���� �ڡڡ� ---
            for %%p in ("!FOUND_ORACLE_HOME!") do set "FOUND_ORACLE=%%~dpp"

            REM --- 2�ܰ�: ORACLE_HOME�� ã�� Ű���� TNS_ADMIN�� ã�ƺ��� ---
            for /f "tokens=2,*" %%a in ('reg query "%%k" /v TNS_ADMIN /reg:64 2^>nul ^| findstr /I "TNS_ADMIN"') do (
                set "TEMP_TNS_ADMIN=%%b"
                REM -- TNS_ADMIN ��� ���� ���鵵 �Ϻ��ϰ� �����մϴ�.
                for /f "tokens=*" %%y in ("!TEMP_TNS_ADMIN!") do set "FOUND_TNS_ADMIN_PATH=%%y"
            )
        )
    )
)

REM --- 3�ܰ�: TNS_ADMIN�� �� ã������, �⺻ ��η� ���� ---
if not defined FOUND_TNS_ADMIN_PATH (
    if defined FOUND_ORACLE_HOME (
        set "FOUND_TNS_ADMIN_PATH=!FOUND_ORACLE_HOME!\network\admin"
    )
)

REM --- ���� ��� Ȯ�� ---
if not defined FOUND_ORACLE_HOME (
    echo [ġ���� ����] ������Ʈ������ ORACLE_HOME�� ã�� �� �����ϴ�. ��ũ��Ʈ�� ����� �� �����ϴ�.
    pause
    exit /b 1
)
echo  - ã�� ORACLE_HOME: "!FOUND_ORACLE_HOME!"
echo  - ã�� ���� ���� ���(TNS_ADMIN): "!FOUND_TNS_ADMIN_PATH!"
echo ���� ��� (FOUND_ORACLE): "!FOUND_ORACLE!"

REM =================================================================
REM ====== 1��. ���� ���� ���� SQL ���� ======
REM =================================================================
> "%TMP_SQL_1%" echo set echo off feedback off verify off pages 999 trimspool on
>>"%TMP_SQL_1%" echo set linesize 120
>>"%TMP_SQL_1%" echo whenever sqlerror continue
>>"%TMP_SQL_1%" echo spool "%REPORT_FILE_1%"
>>"%TMP_SQL_1%" echo prompt [1��. ���� ����] Oracle DB ���� ���� �ڵ� ���� ����
>>"%TMP_SQL_1%" echo prompt =================================================================

REM -- [1.1] ���ʿ��� ���� Ȯ�� --
>>"%TMP_SQL_1%" echo prompt
>>"%TMP_SQL_1%" echo prompt ### [1.1] ���ʿ��� ���� Ȯ�� ###
>>"%TMP_SQL_1%" echo prompt [�Ǵ� ����]
>>"%TMP_SQL_1%" echo prompt  - ��ȣ: ���ʿ��� Default ���� �� �׽�Ʈ ������ ��Ȱ��ȭ(���) �Ǿ� �ִ� ���
>>"%TMP_SQL_1%" echo prompt  - ���: ���ʿ��� Default ���� �Ǵ� �׽�Ʈ ������ Ȱ��ȭ(OPEN) ������ ���
>>"%TMP_SQL_1%" echo prompt [SQL Command] 
>>"%TMP_SQL_1%" echo prompt   select username, account_status from dba_users where account_status='OPEN' and username not in ('AWR_STAGE','AUDSYS','CSMIG','CTXSYS','DIP','DBSNMP','DEMO','DGPDB_INT','DMSYS','DSSYS','DVF','DVSYS','EXFSYS','GGSYS','GSMADMIN_INTERNAL','GSMCATUSER','GSMUSER','LBACSYS','MDSYS','MGMT_VIEW','OLAPSYS','OWBSYS','ORACLE_OCM','ORDDATA','ORDPLUGINS','ORDSYS','OUTLN','SI_INFORMTN_SCHEMA','SYS','SYSBACKUP','SYSDG','SYSKM','SYSRAC','SYSMAN','SYSTEM','TRACESVR','TSMSYS','WK_TEST','WKSYS','WKPROXY','WMSYS','XDB','ODM','PERFSTAT','IMP_FULL_DATABASE','FLOWS_030000');
>>"%TMP_SQL_1%" echo prompt 
>>"%TMP_SQL_1%" echo col username format a20
>>"%TMP_SQL_1%" echo col account_status format a20
>>"%TMP_SQL_1%" echo select username, account_status from dba_users where account_status='OPEN' and username not in ('AWR_STAGE','AUDSYS','CSMIG','CTXSYS','DIP','DBSNMP','DEMO','DGPDB_INT','DMSYS','DSSYS','DVF','DVSYS','EXFSYS','GGSYS','GSMADMIN_INTERNAL','GSMCATUSER','GSMUSER','LBACSYS','MDSYS','MGMT_VIEW','OLAPSYS','OWBSYS','ORACLE_OCM','ORDDATA','ORDPLUGINS','ORDSYS','OUTLN','SI_INFORMTN_SCHEMA','SYS','SYSBACKUP','SYSDG','SYSKM','SYSRAC','SYSMAN','SYSTEM','TRACESVR','TSMSYS','WK_TEST','WKSYS','WKPROXY','WMSYS','XDB','ODM','PERFSTAT','IMP_FULL_DATABASE','FLOWS_030000');
>>"%TMP_SQL_1%" echo clear columns
>>"%TMP_SQL_1%" echo prompt
>>"%TMP_SQL_1%" echo prompt [���� ���]
>>"%TMP_SQL_1%" echo set heading off
>>"%TMP_SQL_1%" echo SELECT CASE WHEN COUNT(*) = 0 THEN '��ȣ: ���� ���ʿ��� ������ �������� �ʽ��ϴ�.' ELSE '���� Ȯ�� �ʿ�: �� ��Ͽ��� ���ʿ��� ������ �ִ��� ���� Ȯ���ϰ� ��ġ�ؾ� �մϴ�.' END FROM dba_users WHERE account_status = 'OPEN' AND username NOT IN ('AWR_STAGE','AUDSYS','CSMIG','CTXSYS','DIP','DBSNMP','DEMO','DGPDB_INT','DMSYS','DSSYS','DVF','DVSYS','EXFSYS','GGSYS','GSMADMIN_INTERNAL','GSMCATUSER','GSMUSER','LBACSYS','MDSYS','MGMT_VIEW','OLAPSYS','OWBSYS','ORACLE_OCM','ORDDATA','ORDPLUGINS','ORDSYS','OUTLN','SI_INFORMTN_SCHEMA','SYS','SYSBACKUP','SYSDG','SYSKM','SYSRAC','SYSMAN','SYSTEM','TRACESVR','TSMSYS','WK_TEST','WKSYS','WKPROXY','WMSYS','XDB','ODM','PERFSTAT','IMP_FULL_DATABASE','FLOWS_030000');
>>"%TMP_SQL_1%" echo set heading on

REM -- [1.2] ������ �α��� �õ� ���� --
>>"%TMP_SQL_1%" echo prompt 
>>"%TMP_SQL_1%" echo prompt ### [1.2] ������ �α��� �õ� ���� (FAILED_LOGIN_ATTEMPTS) ###
>>"%TMP_SQL_1%" echo prompt [�Ǵ� ����]
>>"%TMP_SQL_1%" echo prompt  - ��ȣ: FAILED_LOGIN_ATTEMPTS ������ 10 ������ ������ ������ ���
>>"%TMP_SQL_1%" echo prompt  - ���: FAILED_LOGIN_ATTEMPTS ������ 'UNLIMITED' �Ǵ� 10�� �ʰ��ϴ� ���
>>"%TMP_SQL_1%" echo prompt [SQL Command]
>>"%TMP_SQL_1%" echo prompt   select profile, limit from dba_profiles where resource_name = 'FAILED_LOGIN_ATTEMPTS' order by profile;
>>"%TMP_SQL_1%" echo col profile format a20
>>"%TMP_SQL_1%" echo col limit format a10
>>"%TMP_SQL_1%" echo select profile, limit from dba_profiles where resource_name = 'FAILED_LOGIN_ATTEMPTS' order by profile;
>>"%TMP_SQL_1%" echo clear columns
>>"%TMP_SQL_1%" echo prompt 
>>"%TMP_SQL_1%" echo prompt [���� ���]
>>"%TMP_SQL_1%" echo set heading off
>>"%TMP_SQL_1%" echo select case when count(*)=0 then '��ȣ: ��� ���������� �α��� ���� Ƚ�� ������ �����մϴ�.' else '���: �α��� ���� Ƚ�� ������ ���ų� 10ȸ�� �ʰ��ϴ� ���������� �����մϴ�.' end from (select limit from dba_profiles where resource_name = 'FAILED_LOGIN_ATTEMPTS') where limit = 'UNLIMITED' or (regexp_like(limit, '^[0-9]+$') and to_number(limit) ^> 10);
>>"%TMP_SQL_1%" echo set heading on

REM -- [1.3] �н����� �ֱ��� ���� --
>>"%TMP_SQL_1%" echo prompt
>>"%TMP_SQL_1%" echo prompt ### [1.3] �н����� �ֱ��� ���� (PASSWORD_LIFE_TIME) ###
>>"%TMP_SQL_1%" echo prompt [�Ǵ� ����]
>>"%TMP_SQL_1%" echo prompt  - ��ȣ: PASSWORD_LIFE_TIME ���� 60 ���Ϸ� ������ ���
>>"%TMP_SQL_1%" echo prompt  - ���: PASSWORD_LIFE_TIME ���� 'UNLIMITED' �Ǵ� 60�� �ʰ��ϴ� ���
>>"%TMP_SQL_1%" echo prompt [SQL Command]
>>"%TMP_SQL_1%" echo prompt   select resource_name, limit from user_password_limits where resource_name in ('PASSWORD_LIFE_TIME');
>>"%TMP_SQL_1%" echo col resource_name format a20
>>"%TMP_SQL_1%" echo col limit format a10
>>"%TMP_SQL_1%" echo select resource_name, limit from user_password_limits where resource_name in ('PASSWORD_LIFE_TIME');
>>"%TMP_SQL_1%" echo clear columns
>>"%TMP_SQL_1%" echo prompt
>>"%TMP_SQL_1%" echo prompt [���� ���]
>>"%TMP_SQL_1%" echo set heading off
>>"%TMP_SQL_1%" echo select case when count(*)=0 then '��ȣ: ��� ���������� �н����� ���� �Ⱓ�� 60�� ���Ϸ� �����Ǿ����ϴ�.' else '���: �н����� ���� �Ⱓ�� 60���� �ʰ��ϰų� �������� ���������� �����մϴ�.' end from (select limit from user_password_limits where resource_name = 'PASSWORD_LIFE_TIME') where limit = 'UNLIMITED' or (regexp_like(limit, '^[0-9]+$') and to_number(limit) ^> 60);
>>"%TMP_SQL_1%" echo set heading on

REM -- [1.4] �н����� ���⵵ ���� --
>>"%TMP_SQL_1%" echo prompt
>>"%TMP_SQL_1%" echo prompt ### [1.4] �н����� ���⵵ ���� (PASSWORD_VERIFY_FUNCTION) ###
>>"%TMP_SQL_1%" echo prompt [�Ǵ� ����]
>>"%TMP_SQL_1%" echo prompt  - ��ȣ: �н����� ���⵵�� �����ϴ� �Լ�(PASSWORD_VERIFY_FUNCTION)�� ������ ���
>>"%TMP_SQL_1%" echo prompt  - ���: �н����� ���� �Լ��� �������� ���� ��� (NULL)
>>"%TMP_SQL_1%" echo prompt [SQL Command]
>>"%TMP_SQL_1%" echo prompt   select profile, limit from dba_profiles where resource_name = 'PASSWORD_VERIFY_FUNCTION' order by profile;
>>"%TMP_SQL_1%" echo col profile format a20
>>"%TMP_SQL_1%" echo col limit format a30
>>"%TMP_SQL_1%" echo select profile, limit from dba_profiles where resource_name = 'PASSWORD_VERIFY_FUNCTION' order by profile;
>>"%TMP_SQL_1%" echo clear columns
>>"%TMP_SQL_1%" echo prompt
>>"%TMP_SQL_1%" echo prompt [���� ���]
>>"%TMP_SQL_1%" echo set heading off
>>"%TMP_SQL_1%" echo select case when count(*)=0 then '��ȣ: �н����� ���� �Լ��� �������� ���� ���������� �����ϴ�.' else '���: �н����� ���� �Լ��� �������� ���� ��������(NULL)�� �����մϴ�.' end from dba_profiles where resource_name = 'PASSWORD_VERIFY_FUNCTION' and limit = 'NULL';
>>"%TMP_SQL_1%" echo set heading on

REM -- [1.5] ����� �н����� ��� ���� (���ͺ�) --
>>"%TMP_SQL_1%" echo prompt
>>"%TMP_SQL_1%" echo prompt ### [1.5] ����� �н����� ��� ���� (���ͺ�) ###
>>"%TMP_SQL_1%" echo prompt [�Ǵ� ����]
>>"%TMP_SQL_1%" echo prompt  - ��ȣ: �����ϱ� ���� �н�����(���� �ܾ�, ���ӵ� ���� ��) ����� �����ϰ� �ֱ������� �����ϴ� ���
>>"%TMP_SQL_1%" echo prompt  - ���: ����� �н����忡 ���� ��� ���� ��å�� ���� ���
>>"%TMP_SQL_1%" echo prompt
>>"%TMP_SQL_1%" echo prompt [���� ���]
>>"%TMP_SQL_1%" echo prompt  - ����ڿ��� �Ʒ� ������ �����ϰ� Ȯ���մϴ�.
>>"%TMP_SQL_1%" echo prompt    1) ������� �����ϰų� ������ �н�����, ������ �ִ� �ܾ� ���� �����ϴ� ��å�� �ֽ��ϱ�?
>>"%TMP_SQL_1%" echo prompt    2) �ֱ������� ����� �н����带 ����ϴ� ������ �ִ��� �����ϰ� ��ġ�մϱ�?
>>"%TMP_SQL_1%" echo prompt
>>"%TMP_SQL_1%" echo prompt [���� ���]
>>"%TMP_SQL_1%" echo prompt ���� Ȯ�� �ʿ�: ����� ���ͺ並 ���� ����� �н����� ���� ��å�� Ȯ���ؾ� �մϴ�.

REM --- �ڡڡ� �߿�: SQL ��ũ��Ʈ�� ���⼭ �����ϴ� �ڡڡ� ---
>>"%TMP_SQL_1%" echo spool off
>>"%TMP_SQL_1%" echo exit

REM --- SQL ��ũ��Ʈ ���� ---
echo [INFO] Auditing Chapter 1 (1.1 ~ 1.5)...
if defined ORA_CONN ( sqlplus -s "%ORA_CONN%" @"%TMP_SQL_1%" ) else ( sqlplus -s / as sysdba @"%TMP_SQL_1%" )


REM --- �ڡڡ� �߿�: [1.6] OS ������ SQL ���� �� ��ġ ���Ͽ��� ���� ���� �ڡڡ� ---
echo [INFO] Auditing Chapter 1 (1.6)...
(
    echo.
    echo ### [1.6] OS DBA �׷� ��� Ȯ�� ###
    echo [�Ǵ� ����]
    echo  - ��ȣ: ���ʿ��� ������ ORA_DBA �׷쿡 �������� �ʴ� ���
    echo  - ���: ���ʿ��� ������ ORA_DBA �׷쿡 �����ϴ� ���
    echo.
    echo [OS Command] 
    echo net localgroup "ORA_DBA"
) >> "%REPORT_FILE_1%"

net localgroup "ORA_DBA" >> "%REPORT_FILE_1%" 2>nul

(
    echo.
    echo [���� ���]
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
    >>"%REPORT_FILE_1%" echo ���� Ȯ�� �ʿ�: ���ʿ��� ������ ORA_DBA �׷쿡 �����մϴ�. (���: !VULN_MEMBERS!)
) else (
    >>"%REPORT_FILE_1%" echo ��ȣ: ORA_DBA �׷쿡 ���ʿ��� ������ �������� �ʽ��ϴ�. (Administrator, oracle, NT AUTHORITY\SYSTEM ����)
)


REM ====== ���� �� �Ϸ� �޽��� ======
del "%TMP_SQL_1%" >nul 2>nul
echo.
echo [OK] Oracle security chapter 1 report created.
echo   - Folder: "%OUTDIR%"
echo   - Report File: "security_report_chapter_1.txt"


echo.
endlocal