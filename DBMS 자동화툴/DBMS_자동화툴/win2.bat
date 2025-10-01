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
set "REPORT_FILE_2=%CD%\%OUTDIR%\security_report_chapter_2.txt"

REM ====== �ӽ� SQL ���� ��� ���� ======
set "TMP_SQL_2=%TEMP%\ora_ch2_%RANDOM%.sql"

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
REM ====== [2.8] �׸� ������ ���� ���� ������ �̸� �˻� (������ �κ�) ======
REM =================================================================
REM 1. �⺻ ���� ����� '���'���� ����
set "AUTH_RESULT=���: �Ķ���Ͱ� �������� �ʾ� �⺻��(NTS)���� ������ �� �ֽ��ϴ�."

REM 2. sqlnet.ora ������ �����ϴ��� Ȯ�� �� ���� �˻�
if exist "!FOUND_TNS_ADMIN_PATH!\sqlnet.ora" (
    set "AUTH_LINE="
    for /f "tokens=*" %%a in ('type "!FOUND_TNS_ADMIN_PATH!\sqlnet.ora" 2^>nul ^| findstr /I "SQLNET.AUTHENTICATION_SERVICES"') do (
        set "AUTH_LINE=%%a"
    )

    REM 3. ã�Ƴ� ����(����)�� ������ �������� ���� ��� �Ǵ�
    if defined AUTH_LINE (
        echo !AUTH_LINE! | findstr /I /C:"(NONE)" >nul
        if !errorlevel! equ 0 (
            set "AUTH_RESULT=��ȣ: OS ����(NTS)�� �ƴ� �����ͺ��̽� ����(NONE)�� ����մϴ�."
        ) else (
            echo !AUTH_LINE! | findstr /I /C:"(NTS)" >nul
            if !errorlevel! equ 0 (
                set "AUTH_RESULT=���: OS ����(NTS)�� ����ϵ��� �����Ǿ� �ֽ��ϴ�."
            )
        )
    )
)


REM =================================================================
REM ====== 2��. ���� ���� ���� SQL ���� ======
REM =================================================================
> "%TMP_SQL_2%" echo set echo off feedback off verify off pages 999 trimspool on
>>"%TMP_SQL_2%" echo set linesize 120
>>"%TMP_SQL_2%" echo whenever sqlerror continue
>>"%TMP_SQL_2%" echo spool "%REPORT_FILE_2%"
>>"%TMP_SQL_2%" echo prompt [2��. ���� ����] Oracle DB ���� ���� �ڵ� ���� ����
>>"%TMP_SQL_2%" echo prompt =================================================================

REM -- [2.1] ���� �� � �ý��� �и� ��� (���ͺ�) --
>>"%TMP_SQL_2%" echo prompt
>>"%TMP_SQL_2%" echo prompt ### [2.1] ���� �� � �ý��� �и� ��� (���ͺ�) ###
>>"%TMP_SQL_2%" echo prompt [�Ǵ� ����]
>>"%TMP_SQL_2%" echo prompt  - ��ȣ: ����, ����, � ȯ���� DB�� ������ �Ǵ� �������� �и��Ǿ� ��Ǵ� ���
>>"%TMP_SQL_2%" echo prompt  - ���: ���� DB�� � DB�� �и����� �ʰ�, ������ �������� ���� ������ ���
>>"%TMP_SQL_2%" echo prompt
>>"%TMP_SQL_2%" echo prompt [���� ���]
>>"%TMP_SQL_2%" echo prompt  - ����ڿ��� �Ʒ� ������ �����ϰ� Ȯ���մϴ�.
>>"%TMP_SQL_2%" echo prompt    1) ����, ����, � ȯ���� �����ͺ��̽��� �и��Ǿ� �ֽ��ϱ�?
>>"%TMP_SQL_2%" echo prompt    2) �����ڰ� � DB�� ���� ������ �� �ֽ��ϱ�? ���� ��å�� ��� �˴ϱ�?
>>"%TMP_SQL_2%" echo prompt
>>"%TMP_SQL_2%" echo prompt [���� ���]
>>"%TMP_SQL_2%" echo prompt ���� Ȯ�� �ʿ�: ����� ���ͺ並 ���� �ý��� �и� ��å�� Ȯ���ؾ� �մϴ�.

REM -- [2.2] Public�� ���� ���� ���� --
>>"%TMP_SQL_2%" echo prompt
>>"%TMP_SQL_2%" echo prompt ### [2.2] Public �ѿ� ���� ���� ���� ###
>>"%TMP_SQL_2%" echo prompt [�Ǵ� ����]
>>"%TMP_SQL_2%" echo prompt  - ��ȣ: Public �ѿ� ���ʿ��� ����(EXECUTE) �Ǵ� ����(UPDATE, DELETE ��) ������ ���� ���
>>"%TMP_SQL_2%" echo prompt  - ���: Public �ѿ� �����ϰų� ���ʿ��� ������ �ο��� ���
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
>>"%TMP_SQL_2%" echo prompt [���� ���]
>>"%TMP_SQL_2%" echo set heading off
>>"%TMP_SQL_2%" echo select case when count(*)=0 then '��ȣ: PUBLIC �ѿ� ������ ����/���� ������ �����ϴ�.' else '���� Ȯ�� �ʿ�: PUBLIC �ѿ� ������ ����/���� ������ ������ �� �ֽ��ϴ�. ������ �ʿ��մϴ�.' end from dba_tab_privs where grantee='PUBLIC' and privilege in ('EXECUTE', 'UPDATE', 'INSERT', 'DELETE', 'ALTER', 'DEBUG', 'FLASHBACK', 'MERGE VIEW') and owner not in ('SYS','CTXSYS','MDSYS','ODM','OLAPSYS','TSMSYS','ORDPLUGINS','ORDSYS','SYSTEM','WKSYS','WMSYS','XDB','LBACSYS','PERFSTAT','SYSMAN','DMSYS','EXFSYS','WK_TEST','IMP_FULL_DATABASE','FLOWS_030000','MGMT_VIEW');
>>"%TMP_SQL_2%" echo set heading on

REM -- [2.3] SYS.LINK$ ���̺� ���� ���� --
>>"%TMP_SQL_2%" echo prompt
>>"%TMP_SQL_2%" echo prompt ### [2.3] SYS.LINK$ ���̺� ���� ���� ###
>>"%TMP_SQL_2%" echo prompt [�Ǵ� ����]
>>"%TMP_SQL_2%" echo prompt  - ��ȣ: DBA ������ ���� ������ SYS.LINK$ ���̺� ���� ������ ���� ���
>>"%TMP_SQL_2%" echo prompt  - ���: DBA ������ ���� ������ SYS.LINK$ ���̺� ���� ������ �ο��� ���
>>"%TMP_SQL_2%" echo prompt
>>"%TMP_SQL_2%" echo prompt [SQL Command]
>>"%TMP_SQL_2%" echo prompt   select grantee, privilege from dba_tab_privs where owner='SYS' and table_name='LINK$' and grantee not in ('SYS','SYSTEM','DBA') order by grantee, privilege;
>>"%TMP_SQL_2%" echo col grantee format a30
>>"%TMP_SQL_2%" echo col privilege format a20
>>"%TMP_SQL_2%" echo select grantee, privilege from dba_tab_privs where owner='SYS' and table_name='LINK$' and grantee not in ('SYS','SYSTEM','DBA') order by grantee, privilege;
>>"%TMP_SQL_2%" echo clear columns
>>"%TMP_SQL_2%" echo prompt
>>"%TMP_SQL_2%" echo prompt [���� ���]
>>"%TMP_SQL_2%" echo set heading off
>>"%TMP_SQL_2%" echo select case when count(*)=0 then '��ȣ: ���ʿ��� ������ ������ �����ϴ�.' else '���: �Ʒ� ������ ���ʿ��� ������ �����մϴ�.' end from dba_tab_privs where owner='SYS' and table_name='LINK$' and grantee not in ('SYS','SYSTEM','DBA');
>>"%TMP_SQL_2%" echo set heading on

REM -- [2.4] SYSDBA ���� ���� --
>>"%TMP_SQL_2%" echo prompt
>>"%TMP_SQL_2%" echo prompt ### [2.4] SYSDBA ���� ���� ###
>>"%TMP_SQL_2%" echo prompt [�Ǵ� ����]
>>"%TMP_SQL_2%" echo prompt  - ��ȣ: SYS ������ ������ �ٸ� ������ SYSDBA ������ ���� ���
>>"%TMP_SQL_2%" echo prompt  - ���: SYS ���� �ܿ� SYSDBA ������ ���� ������ �����ϴ� ���
>>"%TMP_SQL_2%" echo prompt
>>"%TMP_SQL_2%" echo prompt [SQL Command]
>>"%TMP_SQL_2%" echo prompt   select username,sysdba,sysoper from v$pwfile_users where username not in (select grantee from dba_role_privs where granted_role='DBA' and username ^^!='INTERNAL' and sysdba='TRUE');
>>"%TMP_SQL_2%" echo col username format a30
>>"%TMP_SQL_2%" echo select username,sysdba,sysoper from v$pwfile_users where username not in (select grantee from dba_role_privs where granted_role='DBA' and username ^^!='INTERNAL' and sysdba='TRUE');
>>"%TMP_SQL_2%" echo clear columns
>>"%TMP_SQL_2%" echo prompt
>>"%TMP_SQL_2%" echo prompt [���� ���]
>>"%TMP_SQL_2%" echo set heading off
>>"%TMP_SQL_2%" echo select case when count(*) = 0 then '��ȣ: SYS �� SYSDBA ���� ������ �����ϴ�.' else '���: SYS �ܿ� SYSDBA ������ ���� ������ �����մϴ�.' end AS "���� ���" from v$pwfile_users where username not in (select grantee from dba_role_privs where granted_role='DBA' and username ^^!='INTERNAL' and sysdba='TRUE');
>>"%TMP_SQL_2%" echo set heading on

REM -- [2.5] DBA ���� ���� --
>>"%TMP_SQL_2%" echo prompt
>>"%TMP_SQL_2%" echo prompt ### [2.5] DBA ���� ���� ###
>>"%TMP_SQL_2%" echo prompt [�Ǵ� ����]
>>"%TMP_SQL_2%" echo prompt  - ��ȣ: SYS, SYSTEM �ܿ� DBA ���� ���� ���ʿ��� ������ ���� ���
>>"%TMP_SQL_2%" echo prompt  - ���: SYS, SYSTEM �ܿ� DBA ���� ���� ������ �����ϴ� ���
>>"%TMP_SQL_2%" echo prompt
>>"%TMP_SQL_2%" echo prompt [SQL Command]
>>"%TMP_SQL_2%" echo prompt   select grantee from dba_role_privs where granted_role='DBA' and grantee not in ('SYS','SYSTEM','WKSYS','CTXSYS','CSTA','SYSMAN'); 
>>"%TMP_SQL_2%" echo col grantee format a30
>>"%TMP_SQL_2%" echo select grantee from dba_role_privs where granted_role='DBA' and grantee not in ('SYS','SYSTEM','WKSYS','CTXSYS','CSTA','SYSMAN'); 
>>"%TMP_SQL_2%" echo clear columns
>>"%TMP_SQL_2%" echo prompt
>>"%TMP_SQL_2%" echo prompt [���� ���]
>>"%TMP_SQL_2%" echo set heading off
>>"%TMP_SQL_2%" echo select case when count(*) = 0 then '��ȣ: �⺻ ������ �� DBA ���� ���� ������ �����ϴ�.' else '���� Ȯ�� �ʿ�: �⺻ ������ �� DBA ���� ���� ������ �ִ��� Ȯ���ؾ� �մϴ�.' end AS "���� ���" from dba_role_privs where granted_role='DBA' and grantee not in ('SYS','SYSTEM','WKSYS','CTXSYS','CSTA','SYSMAN');
>>"%TMP_SQL_2%" echo set heading on

REM -- [2.6] with grant option ��� ���� --
>>"%TMP_SQL_2%" echo prompt
>>"%TMP_SQL_2%" echo prompt ### [2.6] with grant option ��� ���� ###
>>"%TMP_SQL_2%" echo prompt [�Ǵ� ����]
>>"%TMP_SQL_2%" echo prompt  - ��ȣ: with grant option�� ������ ����ڿ��� �ο��Ǿ� �ִ� ���  
>>"%TMP_SQL_2%" echo prompt  - ���: with grant option�� ������ ����ڿ��� �ο��Ǿ� ���� ���� ���
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
>>"%TMP_SQL_2%" echo prompt [���� ���]
>>"%TMP_SQL_2%" echo set heading off
>>"%TMP_SQL_2%" echo select case when count(*)=0 then '��ȣ: WITH GRANT OPTION ������ �����ϰ� �����ǰ� �ֽ��ϴ�.' else '���: DBA ������ ���� ����ڿ��� WITH GRANT OPTION�� �ο��� ������ �ֽ��ϴ�.' end from dba_tab_privs where grantable='YES' and grantee not in (select distinct owner from dba_objects) and grantee not in (select grantee from dba_role_privs where granted_role='DBA');
>>"%TMP_SQL_2%" echo set heading on


REM -- [2.7] with admin option ��� ���� --
>>"%TMP_SQL_2%" echo prompt
>>"%TMP_SQL_2%" echo prompt ### [2.7] with admin option ��� ���� ###
>>"%TMP_SQL_2%" echo prompt
>>"%TMP_SQL_2%" echo prompt [�Ǵ� ����]
>>"%TMP_SQL_2%" echo prompt  - ��ȣ: with admin option�� ������ ����ڿ��� �ο��Ǿ� �ִ� ���  
>>"%TMP_SQL_2%" echo prompt  - ���: with admin option�� ������ ����ڿ��� �ο��Ǿ� ���� ���� ���
>>"%TMP_SQL_2%" echo prompt
>>"%TMP_SQL_2%" echo prompt [SQL Command]
>>"%TMP_SQL_2%" echo prompt   select grantee,privilege from dba_sys_privs where grantee not in ('SYS','SYSTEM','AQ_ADMINISTRATOR_ROLE','DBA','MDSYS','LBACSYS','SCHEDULER_ADMIN',' MSYS') and admin_option='YES' and grantee not in (select grantee from dba_role_privs where granted_role='DBA');
>>"%TMP_SQL_2%" echo col grantee format a20
>>"%TMP_SQL_2%" echo col privilege format a30
>>"%TMP_SQL_2%" echo select grantee,privilege from dba_sys_privs where grantee not in ('SYS','SYSTEM','AQ_ADMINISTRATOR_ROLE','DBA','MDSYS','LBACSYS','SCHEDULER_ADMIN',' MSYS') and admin_option='YES' and grantee not in (select grantee from dba_role_privs where granted_role='DBA'); 
>>"%TMP_SQL_2%" echo clear columns
>>"%TMP_SQL_2%" echo prompt
>>"%TMP_SQL_2%" echo prompt [���� ���]
>>"%TMP_SQL_2%" echo set heading off
>>"%TMP_SQL_2%" echo select case when count(*)=0 then '��ȣ: WITH ADMIN OPTION ������ �����ϰ� �����ǰ� �ֽ��ϴ�.' else '���� Ȯ�� �ʿ�: ���ʿ��� ����ڿ��� WITH ADMIN OPTION�� �ο��� �ý��� ������ �ֽ��ϴ�.' end from dba_sys_privs where grantee not in ('SYS','SYSTEM','AQ_ADMINISTRATOR_ROLE','DBA','MDSYS','LBACSYS','SCHEDULER_ADMIN',' MSYS') and admin_option='YES' and grantee not in (select grantee from dba_role_privs where granted_role='DBA');
>>"%TMP_SQL_2%" echo set heading on

REM -- [2.8] SYS ���� ���� ��� ���� (sqlnet.ora ���� Ȯ��)--
>>"%TMP_SQL_2%" echo prompt
>>"%TMP_SQL_2%" echo prompt ### [2.8] SYS ���� ���� ��� ���� (SQLNET.AUTHENTICATION_SERVICES) ###
>>"%TMP_SQL_2%" echo prompt [�Ǵ� ����]
>>"%TMP_SQL_2%" echo prompt  - ��ȣ: sqlnet.ora ���Ͽ� SQLNET.AUTHENTICATION_SERVICES �Ķ���Ͱ� (NONE)���� ������ ���
>>"%TMP_SQL_2%" echo prompt  - ���: �ش� �Ķ���Ͱ� ���ų�, ���� (NTS)�� ������ ���
>>"%TMP_SQL_2%" echo prompt
>>"%TMP_SQL_2%" echo prompt [OS Command]
>>"%TMP_SQL_2%" echo prompt    host type "!FOUND_TNS_ADMIN_PATH!\sqlnet.ora" 2^>nul ^| findstr /I "SQLNET.AUTHENTICATION_SERVICES"

REM >>"%TMP_SQL_2%" echo host type "!FOUND_TNS_ADMIN_PATH!\sqlnet.ora" 2^>nul ^| findstr /I "SQLNET.AUTHENTICATION_SERVICES"
>>"%TMP_SQL_2%" echo host findstr /I "SQLNET.AUTHENTICATION_SERVICES" "!FOUND_TNS_ADMIN_PATH!\sqlnet.ora"

>>"%TMP_SQL_2%" echo prompt
>>"%TMP_SQL_2%" echo prompt [���� ���]
REM --- �̸� ������ ���� ��� ������ SQL ���Ͽ� ��� ---
>>"%TMP_SQL_2%" echo prompt !AUTH_RESULT!
>>"%TMP_SQL_2%" echo prompt


REM -- [2.9] CREATE ANY DIRECTORY ���� ���� --
>>"%TMP_SQL_2%" echo prompt
>>"%TMP_SQL_2%" echo prompt ### [2.9] CREATE ANY DIRECTORY ���� ���� ###
>>"%TMP_SQL_2%" echo prompt
>>"%TMP_SQL_2%" echo prompt [�Ǵ� ����]
>>"%TMP_SQL_2%" echo prompt  - ��ȣ: 'CREATE ANY DIRECTORY' ������ ���ʿ��� ������ �ο����� ���� ���
>>"%TMP_SQL_2%" echo prompt  - ���: 'CREATE ANY DIRECTORY' ������ ���ʿ��� ������ �ο��� ���
>>"%TMP_SQL_2%" echo prompt
>>"%TMP_SQL_2%" echo prompt [SQL Command]
>>"%TMP_SQL_2%" echo prompt    select grantee,privilege from dba_sys_privs where privilege='CREATE ANY DIRECTORY' and grantee not in('DBA','IMP_FULL_DATABASE','WKSYS','SYS','SYSDBA'); 
>>"%TMP_SQL_2%" echo col grantee format a20
>>"%TMP_SQL_2%" echo col privilege format a30
>>"%TMP_SQL_2%" echo select grantee,privilege from dba_sys_privs where privilege='CREATE ANY DIRECTORY' and grantee not in('DBA','IMP_FULL_DATABASE','WKSYS','SYS','SYSDBA'); 
>>"%TMP_SQL_2%" echo clear columns
>>"%TMP_SQL_2%" echo prompt
>>"%TMP_SQL_2%" echo prompt [���� ���]
>>"%TMP_SQL_2%" echo set heading off
>>"%TMP_SQL_2%" echo select case when count(*)=0 then '��ȣ: CREATE ANY DIRECTORY ������ �����ϰ� �����ǰ� �ֽ��ϴ�.' else '���: (���� Ȯ�� �ʿ�) ���ʿ��� ����ڿ��� CREATE ANY DIRECTORY ������ �ο��Ǿ����ϴ�.' end from dba_sys_privs where privilege='CREATE ANY DIRECTORY' and grantee not in('DBA','IMP_FULL_DATABASE','WKSYS','SYS','SYSDBA','SYSBACKUP');
>>"%TMP_SQL_2%" echo set heading on

>>"%TMP_SQL_2%" echo spool off
>>"%TMP_SQL_2%" echo exit;

echo [INFO] Chapter 2. Privilege Management Audit...
if defined ORA_CONN ( sqlplus -s "%ORA_CONN%" @"%TMP_SQL_2%" ) else ( sqlplus -s / as sysdba @"%TMP_SQL_2%" )
echo    - Report 2: "security_report_chapter_2.txt"

REM ====== ���� �� �Ϸ� �޽��� ======
del "%TMP_SQL_2%" >nul 2>nul

echo.
endlocal