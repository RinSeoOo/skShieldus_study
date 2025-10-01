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
set "REPORT_FILE_3=%CD%\%OUTDIR%\security_report_chapter_3.txt"

REM ====== �ӽ� SQL ���� ��� ���� ======
set "TMP_SQL_3=%TEMP%\ora_ch3_%RANDOM%.sql"

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
REM ====== [3.3] �׸� ������ ���� ���� ������ �̸� �˻� (������ ����) ======
REM =================================================================
set "ORACLE_VERSION="
set "MAJOR_VERSION="
set "LISTENER_SEC_RESULT="

REM --- �ڡڡ� ����: �ӽ� ������ ����� ������ ���� Ȯ�� ���� �ڡڡ�
set "TMP_VERSION_SQL=%TEMP%\ora_version_check_%RANDOM%.sql"
set "TMP_VERSION_OUT=%TEMP%\ora_version_out_%RANDOM%.txt"

REM --- 1. �ӽ� SQL ���� ���� ---
> "%TMP_VERSION_SQL%" echo set echo off feedback off verify off heading off pagesize 0 trimspool on;
>>"%TMP_VERSION_SQL%" echo select version from v$instance;
>>"%TMP_VERSION_SQL%" echo exit;

echo  - Oracle ���� ������ Ȯ���ϴ� ��...

REM --- 2. Oracle ���� ���� �������� (�ӽ� ���Ϸ� ���) ---
if defined ORA_CONN (
    sqlplus -s "!ORA_CONN!" @"%TMP_VERSION_SQL%" > "!TMP_VERSION_OUT!" 2>&1
) else (
    sqlplus -s / as sysdba @"%TMP_VERSION_SQL%" > "!TMP_VERSION_OUT!" 2>&1
)

REM --- 3. �ӽ� ���Ͽ��� ���� ���� �б� ---
if exist "!TMP_VERSION_OUT!" (
    for /f "usebackq delims=" %%v in ("!TMP_VERSION_OUT!") do (
        if not defined ORACLE_VERSION (
            set "ORACLE_VERSION=%%v"
        )
    )
)

REM --- 4. �ӽ� ���ϵ� ���� ---
del "%TMP_VERSION_SQL%" >nul 2>nul
del "!TMP_VERSION_OUT!" >nul 2>nul

REM --- 5. ������ ���� ��ȿ�� �˻� �� �б� ó�� ---
if not defined ORACLE_VERSION (
    echo  - [���] Oracle ���� ������ �������� ���߽��ϴ�.
    goto :ContinueListenerCheck
)

REM ���� �� Ư������ ����
set "ORACLE_VERSION=!ORACLE_VERSION: =!"
for /f "tokens=*" %%a in ("!ORACLE_VERSION!") do set "ORACLE_VERSION=%%a"

REM Oracle/TNS ���� �޽��� Ȯ��
echo "!ORACLE_VERSION!" | findstr /I "ORA-" >nul
if !errorlevel! equ 0 (
    echo  - [���] Oracle ���� ����: !ORACLE_VERSION!
    goto :ContinueListenerCheck
)

echo "!ORACLE_VERSION!" | findstr /I "TNS-" >nul
if !errorlevel! equ 0 (
    echo  - [���] TNS ���� ����: !ORACLE_VERSION!
    goto :ContinueListenerCheck
)

REM SP2- �� �ٸ� ���� �޽��� Ȯ��
echo "!ORACLE_VERSION!" | findstr /I "SP2-\|ERROR\|ORA-\|TNS-" >nul
if !errorlevel! equ 0 (
    echo  - [���] SQL*Plus ����: !ORACLE_VERSION!
    goto :ContinueListenerCheck
)

REM --- 6. �������� ���� ���� ó�� ---
echo  - Ȯ�ε� Oracle ����:!ORACLE_VERSION!

REM �ֿ� ���� ��ȣ ���� (ù ��° ����)
for /f "tokens=1 delims=." %%a in ("!ORACLE_VERSION!") do set "MAJOR_VERSION=%%a"

if not defined MAJOR_VERSION (
    echo  - [���] ���� ��ȣ�� ������ �� �����ϴ�.
    goto :ContinueListenerCheck
)

REM �������� Ȯ�� �� 12 �̻� ���� üũ
set /a "VERSION_NUM=!MAJOR_VERSION!" 2>nul

if !VERSION_NUM! GEQ 12 (
    echo  - Oracle 12c �̻� ������ Ȯ�εǾ����ϴ�.
    set "LISTENER_SEC_RESULT=��ȣ: Oracle 12.1 �̻� ������ Local OS ������ ����ϹǷ� ���� ������ �ʼ��� �ƴմϴ�."
    goto :EndListenerCheck
)

echo  - Oracle 12c �̸� �����Դϴ�. Listener ���� ������ Ȯ���մϴ�.

:ContinueListenerCheck
REM --- 7. ������ 12 �̸��̰ų� Ȯ�� ���� �� Listener ���� ���� �˻� ---
set "LISTENER_SEC_RESULT=���: Listener �н����尡 �����Ǿ� ���� �ʽ��ϴ�. (12.1 �̸� ������ �ش�)"
set "PASSWORD_SET="
set "ADMIN_RESTRICTIONS_SET="

if exist "!FOUND_TNS_ADMIN_PATH!\listener.ora" (
    echo  - listener.ora ������ Ȯ���ϴ� ��...
    
    REM Listener ���� ���� Ȯ��
    lsnrctl status > "%TEMP%\lsnrctl_status.txt" 2>nul
    findstr /C:"Services Summary..." "%TEMP%\lsnrctl_status.txt" >nul
    if !errorlevel! equ 0 (
        REM listener.ora ���Ͽ��� ���� ���� Ȯ��
        for /f "usebackq tokens=*" %%L in ("!FOUND_TNS_ADMIN_PATH!\listener.ora") do (
            echo "%%L" | findstr /R /I /C:"^ *PASSWORDS_" >nul
            if !errorlevel! equ 0 ( 
                set "PASSWORD_SET=YES"
                echo  - PASSWORDS_ ���� �߰�
            )
            echo "%%L" | findstr /R /I /C:"^ *ADMIN_RESTRICTIONS_.*= *ON" >nul
            if !errorlevel! equ 0 ( 
                set "ADMIN_RESTRICTIONS_SET=YES"
                echo  - ADMIN_RESTRICTIONS ���� �߰�
            )
        )
        
        if defined PASSWORD_SET if defined ADMIN_RESTRICTIONS_SET (
            set "LISTENER_SEC_RESULT=��ȣ: Listener �н����� �� ���� ������ �����Ǿ� �ֽ��ϴ�."
        )
    ) else (
        set "LISTENER_SEC_RESULT=�ش� ����: Ȱ��ȭ�� Listener�� �����ϴ�."
    )
    del "%TEMP%\lsnrctl_status.txt" >nul 2>nul
) else (
    echo  - [���] listener.ora ������ ã�� �� �����ϴ�: !FOUND_TNS_ADMIN_PATH!\listener.ora
    set "LISTENER_SEC_RESULT=���: listener.ora ������ ã�� �� �����ϴ�."
)

:EndListenerCheck
echo  - Listener ���� �˻� �Ϸ�: !LISTENER_SEC_RESULT!

REM =================================================================
REM ====== [3.4] �׸� ������ ���� ���� ������ �̸� �˻� ======
REM =================================================================
set "IP_CONTROL_RESULT=���: IP ������ �����Ǿ� ���� �ʽ��ϴ�."
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
        set "IP_CONTROL_RESULT=��ȣ: IP ������ �����Ǿ� �ֽ��ϴ�."
    )
)

REM =================================================================
REM ====== 3��. ���� ���� ���� SQL ���� ======
REM =================================================================
> "%TMP_SQL_3%" echo set echo off feedback off verify off pages 999 lines 200 trimspool on
>>"%TMP_SQL_3%" echo whenever sqlerror continue
>>"%TMP_SQL_3%" echo spool "%REPORT_FILE_3%"
>>"%TMP_SQL_3%" echo prompt [3��. ���� ����] Oracle DB ���� ���� �ڵ� ���� ����
>>"%TMP_SQL_3%" echo prompt =================================================================

REM -- [3.1] ��� ���� (���ͺ�) --
>>"%TMP_SQL_3%" echo prompt
>>"%TMP_SQL_3%" echo prompt ### [3.1] ��� ���� (���ͺ�) ###
>>"%TMP_SQL_3%" echo prompt
>>"%TMP_SQL_3%" echo prompt [�Ǵ� ����]
>>"%TMP_SQL_3%" echo prompt  - ��ȣ: ��� ��å�� ���� �ֱ������� ����� �����ϰ� �����ϰ� �����ϴ� ���
>>"%TMP_SQL_3%" echo prompt  - ���: �ֱ����� ��� ��å�� ���ų� ����� ������� �ʴ� ���
>>"%TMP_SQL_3%" echo prompt
>>"%TMP_SQL_3%" echo prompt [���� ���]
>>"%TMP_SQL_3%" echo prompt  - ����ڿ��� �Ʒ� ������ �����ϰ� Ȯ���մϴ�.
>>"%TMP_SQL_3%" echo prompt    1) DB ��� ��å�� �����Ǿ� ������, ���������� ����� �����ϰ� �ֽ��ϱ�? (��� �ֱ� Ȯ��)
>>"%TMP_SQL_3%" echo prompt    2) DB ���������� ���׷��̵� �۾� ������ ��ü ����� �����մϱ�?
>>"%TMP_SQL_3%" echo prompt    3) ��� �����ʹ� ������ ������ ���� ������ ������ ��ҿ� �����˴ϱ�?
>>"%TMP_SQL_3%" echo prompt
>>"%TMP_SQL_3%" echo prompt [���� ���]
>>"%TMP_SQL_3%" echo prompt ���� Ȯ�� �ʿ�: ����� ���ͺ並 ���� ��� ��å �� ���� ���θ� Ȯ���ؾ� �մϴ�.

REM -- [3.2] PL/SQL Package�� PUBLIC Role ������� ���� --
>>"%TMP_SQL_3%" echo prompt
>>"%TMP_SQL_3%" echo prompt ### [3.2] PL/SQL Package�� Public Role ���� ###
>>"%TMP_SQL_3%" echo prompt
>>"%TMP_SQL_3%" echo prompt [�Ǵ� ����]
>>"%TMP_SQL_3%" echo prompt  - ��ȣ: PL/SQL package�� ���� ������ �����Ǿ� �ִ� ���
>>"%TMP_SQL_3%" echo prompt  - ���: PL/SQL package�� ���� ������ �����Ǿ� ���� ���� ���
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
>>"%TMP_SQL_3%" echo prompt [���� ���]
>>"%TMP_SQL_3%" echo.
>>"%TMP_SQL_3%" echo set heading off
>>"%TMP_SQL_3%" echo select case when count(*) ^> 0 then '���� Ȯ�� �ʿ�: PUBLIC �ѿ� ������ ��Ű�� ���� ������ �ο��Ǿ� �ֽ��ϴ�.' else '��ȣ: PUBLIC �ѿ� �ο��� ������ ��Ű�� ���� ������ �����ϴ�.' end from dba_tab_privs where grantee='PUBLIC' and privilege='EXECUTE' and table_name in ('UTL_SMTP','UTL_TCP','UTL_HTTP','UTL_FILE','DBMS_RANDOM','DBMS_LOB','DBMS_SQL','DBMS_JOB','DBMS_BACKUP_RESTORE','DBMS_OBFUSCATION_TOOLKIT','UTL_INADDR');
>>"%TMP_SQL_3%" echo set heading on
>>"%TMP_SQL_3%" echo.

REM -- [3.3] Listener ���� ���� ���� (listener.ora ���� Ȯ��) --
>>"%TMP_SQL_3%" echo prompt
>>"%TMP_SQL_3%" echo prompt ### [3.3] Listener ���� ���� ���� ###
>>"%TMP_SQL_3%" echo prompt [�Ǵ� ����]
>>"%TMP_SQL_3%" echo prompt  - ��ȣ: Listener ������ �н����� ������ �Ǿ� �ִ� ���
>>"%TMP_SQL_3%" echo prompt  - ���: Listener ������ �н����� ������ �Ǿ� ���� ���� ���
>>"%TMP_SQL_3%" echo prompt  (�� Oracle 12.1 Version ���� Listener �н����� ��� ������)
>>"%TMP_SQL_3%" echo prompt
>>"%TMP_SQL_3%" echo prompt [OS Command]
>>"%TMP_SQL_3%" echo prompt   1. Listener ���� Ȯ��:
>>"%TMP_SQL_3%" echo prompt     C:\^> lsnrctl status
>>"%TMP_SQL_3%" echo prompt
>>"%TMP_SQL_3%" echo prompt   2. ���� ���� Ȯ��:
>>"%TMP_SQL_3%" echo prompt     host findstr /I /C:"PASSWORDS_" /C:"ADMIN_RESTRICTIONS_" "!FOUND_TNS_ADMIN_PATH!\listener.ora"
>>"%TMP_SQL_3%" echo host findstr /I /C:"PASSWORDS_" /C:"ADMIN_RESTRICTIONS_" "!FOUND_TNS_ADMIN_PATH!\listener.ora"
>>"%TMP_SQL_3%" echo prompt
>>"%TMP_SQL_3%" echo prompt [���� ���]
>>"%TMP_SQL_3%" echo prompt !LISTENER_SEC_RESULT!
>>"%TMP_SQL_3%" echo prompt

REM -- [3.4] DB ���� IP ���� (sqlnet.ora ���� Ȯ��) --
>>"%TMP_SQL_3%" echo prompt
>>"%TMP_SQL_3%" echo prompt ### [3.4] DB ���� IP ���� ###
>>"%TMP_SQL_3%" echo prompt [�Ǵ� ����]
>>"%TMP_SQL_3%" echo prompt  - ��ȣ: IP ������ �����Ǿ� �ִ� ���
>>"%TMP_SQL_3%" echo prompt  - ���: IP ������ �����Ǿ� ���� ���� ���
>>"%TMP_SQL_3%" echo prompt
>>"%TMP_SQL_3%" echo prompt [���� ���]
>>"%TMP_SQL_3%" echo prompt   $ORACLE_HOME/network/admin/sqlnet.ora ���Ͽ� �Ʒ� ������ �߰� �Ǵ� �����մϴ�.
>>"%TMP_SQL_3%" echo prompt   TCP.VALIDNODE_CHECKING = YES
>>"%TMP_SQL_3%" echo prompt   TCP.INVITED_NODES = (����� IP1, ����� IP2, ...)
>>"%TMP_SQL_3%" echo prompt
>>"%TMP_SQL_3%" echo prompt [OS Command]
>>"%TMP_SQL_3%" echo prompt     host findstr /I "NODES" "!FOUND_TNS_ADMIN_PATH!\sqlnet.ora"
>>"%TMP_SQL_3%" echo host findstr /I "NODES" "!FOUND_TNS_ADMIN_PATH!\sqlnet.ora"
>>"%TMP_SQL_3%" echo prompt
>>"%TMP_SQL_3%" echo prompt [���� ���]
>>"%TMP_SQL_3%" echo prompt !IP_CONTROL_RESULT!
>>"%TMP_SQL_3%" echo prompt

REM -- [3.5] �α� ���� �ֱ�(��å ���� �� ���ͺ� �ʿ�) --
>>"%TMP_SQL_3%" echo prompt
>>"%TMP_SQL_3%" echo prompt ### [3.5] �α� ���� �ֱ� ###
>>"%TMP_SQL_3%" echo prompt
>>"%TMP_SQL_3%" echo prompt [�Ǵ� ����]
>>"%TMP_SQL_3%" echo prompt - ��ȣ: �ֱ������� �α� ����, ���, �����ǰ� �ִ� ���
>>"%TMP_SQL_3%" echo prompt - ���: �α� ����, ���, �������� �ʴ� ���
>>"%TMP_SQL_3%" echo prompt
>>"%TMP_SQL_3%" echo prompt [���� ���]
>>"%TMP_SQL_3%" echo prompt   - ����ڿ��� �Ʒ� ������ �����ϰ� Ȯ���մϴ�.
>>"%TMP_SQL_3%" echo prompt     1) '������Ÿ��̿����� �� ������ȣ����ѹ���', '����������ȣ��', 'ȸ����' � ���� �ּ� �Ⱓ �̻� �����ϰ� �ֽ��ϱ�?
>>"%TMP_SQL_3%" echo prompt     2) ���� ����� �������� ���� �ʵ��� ������ �������� ���� ��ġ�� �����ϰ� �������� ����� �����ϰ� �ֽ��ϱ�?
>>"%TMP_SQL_3%" echo prompt
>>"%TMP_SQL_3%" echo prompt [���� ���]
>>"%TMP_SQL_3%" echo prompt ���� Ȯ�� �ʿ�: ����� ���ͺ並 ���� �α� ���� �ֱ⸦ Ȯ���ؾ� �մϴ�.

REM -- [3.6] ���� IDLE_TIMEOUT ���� --
>>"%TMP_SQL_3%" echo prompt
>>"%TMP_SQL_3%" echo prompt ### [3.6] ���� IDLE_TIMEOUT ���� (IDLE_TIME) ###
>>"%TMP_SQL_3%" echo prompt
>>"%TMP_SQL_3%" echo prompt [�Ǵ� ����]
>>"%TMP_SQL_3%" echo prompt - ��ȣ: IDLE_TIMEOUT�� 5�� ���Ϸ� �����Ǿ� �ִ� ���
>>"%TMP_SQL_3%" echo prompt - ���: IDLE_TIMEOUT�� 5�� �ʰ��� �����Ǿ� �ִ� ���
>>"%TMP_SQL_3%" echo prompt [SQL Command]
>>"%TMP_SQL_3%" echo prompt   select profile,resource_name,limit from dba_profiles where resource_name = 'IDLE_TIME';
>>"%TMP_SQL_3%" echo col profile format a20
>>"%TMP_SQL_3%" echo col resource_name format a15
>>"%TMP_SQL_3%" echo col limit format a10
>>"%TMP_SQL_3%" echo select profile, resource_name, limit from dba_profiles where resource_name = 'IDLE_TIME';
>>"%TMP_SQL_3%" echo prompt
>>"%TMP_SQL_3%" echo prompt [���� ���]
>>"%TMP_SQL_3%" echo set heading off
>>"%TMP_SQL_3%" echo select case when count(*) ^>0 then '��ȣ: ��� ���������� ���� IDLE_TIMEOUT�� 5�� ���Ϸ� �����Ǿ����ϴ�.' else '���: ���� IDLE_TIMEOUT�� 5���� �ʰ��ϰų� ������ ���� ���������� �����մϴ�.' end from (select limit from dba_profiles where resource_name = 'IDLE_TIME') where limit in ('UNLIMITED', 'DEFAULT') or (regexp_like(limit, '^[0-9]+$') and to_number(limit) ^> 5);
>>"%TMP_SQL_3%" echo set heading on

>>"%TMP_SQL_3%" echo spool off
>>"%TMP_SQL_3%" echo exit

echo [INFO] Chapter 3. Configuration Management Audit...
if defined ORA_CONN ( sqlplus -s "%ORA_CONN%" @"%TMP_SQL_3%" ) else ( sqlplus -s / as sysdba @"%TMP_SQL_3%" )
echo    - Report 3: "security_report_chapter_3.txt"


REM ====== ���� �� �Ϸ� �޽��� ======
del "%TMP_SQL_3%" >nul 2>nul

echo.
endlocal