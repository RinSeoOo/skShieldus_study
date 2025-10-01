@echo off
setlocal enableextensions enabledelayedexpansion

REM ==================== �ܼ�/���ڵ� ���� ====================
REM chcp 65001 >nul
REM set NLS_LANG=AMERICAN_AMERICA.AL32UTF8
chcp 949 >nul
set NLS_LANG=KOREAN_KOREA.KO16MSWIN949
REM set NLS_LANG=AMERICAN_AMERICA.AL32UTF8
REM �ʿ� �� chcp 949 / NLS_LANG=KOREAN_KOREA.KO16MSWIN949 ���

REM ==================== ����� �Է�/���� ���� ====================
REM OS ������ �� �Ǹ� ORA_CONN�� ä���ּ��� (��: system/Passw0rd@//127.0.0.1:1521/ORCLPDB1)
REM set ORA_CONN=system/ChangeMe1!@//127.0.0.1:1521/XEPDB1
set "ORA_CONN=c##test/1234@//10.0.8.8:1521/XE"

REM ---- (�߿�) Oracle Ȩ/�ν��Ͻ� �⺻�� ���� ----
if not defined ORACLE_HOME set "ORACLE_HOME=C:\app\Administrator\product\21c\dbhomeXE"
if not defined ORACLE_SID  set "ORACLE_SID=XE"
set "PATH=%ORACLE_HOME%\bin;%PATH%"

REM sqlplus�� 5.1 ���˿� �ʼ��� �ƴ�����, ���� ���� ����
where sqlplus >nul 2>nul || (
  echo [ERROR] sqlplus.exe not found in PATH. Install Oracle Client or add to PATH.
  REM ��� �����ص� ����������, ���� ������ ���� ������ �˸��� ����
  REM �ʿ� �� exit /b 1 �ּ� ����
  REM exit /b 1
)

set "REPORT_FILE_5=%CD%\%OUTDIR%\security_report_chapter_5.txt"

REM ======================================================================
REM ==================== 5��. ���� ��ġ ���� (���� 5.1) ====================
REM  OPatch lsinventory ����. �ϵ��ڵ� ��� ��� + ��� �ڵ� ����
REM ======================================================================
set "ORA_HOME_HC=C:\app\Administrator\product\21c\dbhomeXE"
set "OPATCH=%ORA_HOME_HC%\OPatch\opatch.bat"
if not exist "%OPATCH%" set "OPATCH=%ORA_HOME_HC%\OPatch\opatch.cmd"
if not exist "%OPATCH%" set "OPATCH=%ORA_HOME_HC%\OPatch\opatch"

set "TMP_OPATCH=%TEMP%\opatch_%RANDOM%.txt"

> "%REPORT_FILE_5%"  echo [5. ���� ��ġ] (���� '3-1. ���� ���' ��Ʈ 5.1)
>>"%REPORT_FILE_5%" echo =================================================================
>>"%REPORT_FILE_5%" echo ### [5.1] ���� ��ġ ���� ��Ȳ ^(OPatch lsinventory^)
>>"%REPORT_FILE_5%" echo [�Ǵ� ����]
>>"%REPORT_FILE_5%" echo   - ��ȣ: � ��å ������ �ֽ� RU/CPU ����
>>"%REPORT_FILE_5%" echo   - ���: ������/������ �Ǵ� OPatch ����/����� �̷� Ȯ�� �Ұ�
>>"%REPORT_FILE_5%" echo.

echo [INFO] Chapter 5. Security Patch...

if exist "%OPATCH%" (
  >>"%REPORT_FILE_5%" echo [Command]
  >>"%REPORT_FILE_5%" echo   "%OPATCH%" lsinventory -oh "%ORA_HOME_HC%"
  "%OPATCH%" lsinventory -oh "%ORA_HOME_HC%" > "%TMP_OPATCH%" 2>&1

  >>"%REPORT_FILE_5%" echo.
  >>"%REPORT_FILE_5%" echo [���� ���]
  type "%TMP_OPATCH%" >> "%REPORT_FILE_5%"

  rem --- �ڵ� ���� ---
  set "EXITCODE=%ERRORLEVEL%"
  set "PATCHCOUNT="
  for /f %%N in ('findstr /R /I /C:"Patch [0-9][0-9][0-9]" "%TMP_OPATCH%" ^| find /c /v ""') do set "PATCHCOUNT=%%N"

  set "NOINT="
  findstr /I /C:"no interim" "%TMP_OPATCH%" >nul && set "NOINT=1"
  findstr /I /C:"There are no Interim patches installed" "%TMP_OPATCH%" >nul && set "NOINT=1"
  REM (����) �ѱ�/��Ķ ���� ���� Ű���� �߰�
  findstr /I /C:"Interim ��ġ�� ��" "%TMP_OPATCH%" >nul && set "NOINT=1"

  >>"%REPORT_FILE_5%" echo.
  >>"%REPORT_FILE_5%" echo [���� ���]
  if not "!EXITCODE!"=="0" (
    >>"%REPORT_FILE_5%" echo ��� - OPatch ���� ������ ��ġ �̷� Ȯ�� �Ұ�^(EXITCODE=!EXITCODE!^).
  ) else if "!PATCHCOUNT!"=="0" (
    >>"%REPORT_FILE_5%" echo ��� - ����� ��ġ�� Ȯ�ε��� ���� ^(Interim 0��^).
  ) else if defined NOINT (
    >>"%REPORT_FILE_5%" echo ��� - ^"There are no Interim patches installed^" ���� Ȯ�ε�.
  ) else (
    >>"%REPORT_FILE_5%" echo ���� - ���� ��ġ !PATCHCOUNT!�� Ȯ��. �ֽ� RU/CPU ���δ� � ��å�� ���� �ʿ�.
  )
) else (
  >>"%REPORT_FILE_5%" echo [ERROR] OPatch not found at "%ORA_HOME_HC%\OPatch"
  >>"%REPORT_FILE_5%" echo [���� ���]
  >>"%REPORT_FILE_5%" echo ��� - OPatch ���� ����� ��ġ �̷� Ȯ�� �Ұ�.
)

del "%TMP_OPATCH%" >nul 2>nul

echo.
echo [OK] Oracle security report created (5.1 only).
echo    - Folder: "%OUTDIR%"
echo    - Report 5: "security_report_chapter_5.txt"

endlocal
