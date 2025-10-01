@echo off
setlocal enableextensions enabledelayedexpansion

REM ==================== 콘솔/인코딩 설정 ====================
chcp 65001 >nul
set NLS_LANG=AMERICAN_AMERICA.AL32UTF8
REM 필요 시 chcp 949 / NLS_LANG=KOREAN_KOREA.KO16MSWIN949 사용

REM ==================== 사용자 입력/사전 조건 ====================
REM OS 인증이 안 되면 ORA_CONN을 채워주세요 (예: system/Passw0rd@//127.0.0.1:1521/ORCLPDB1)
REM set ORA_CONN=system/ChangeMe1!@//127.0.0.1:1521/ORCLPDB1
set "ORA_CONN=c##test/1234@//10.0.8.8:1521/XE"

where sqlplus >nul 2>nul || (
  echo [ERROR] sqlplus.exe not found in PATH. Install Oracle Client or add to PATH.
  exit /b 1
)


set "REPORT_FILE_6=%CD%\%OUTDIR%\security_report_chapter_6.txt"
set "TMP_SQL_6=%TEMP%\ora_ch6_%RANDOM%.sql"

REM ======================================================================
REM ============ 6장. 보안 감사 설정 (엑셀 6.1 ~ 6.2, SQL 실행) ============
REM  SQL 리포트에 “Command(실제 쿼리)”와 “판단 기준/결과/결론” 모두 출력
REM ======================================================================
> "%TMP_SQL_6%" echo set echo off feedback off verify off pages 1000 lines 200 trimspool on
>>"%TMP_SQL_6%" echo set define off
>>"%TMP_SQL_6%" echo whenever sqlerror continue
>>"%TMP_SQL_6%" echo spool "%REPORT_FILE_6%"
>>"%TMP_SQL_6%" echo prompt [6. 보안 감사 설정] (엑셀 '3-1. 진단 결과' 시트 6.1 ~ 6.2)
>>"%TMP_SQL_6%" echo prompt =================================================================

REM -- 6.1 SYS 감사 수행 설정 (AUDIT_SYS_OPERATIONS) --
>>"%TMP_SQL_6%" echo prompt.
>>"%TMP_SQL_6%" echo prompt ### [6.1] SYS 감사 수행 설정 (AUDIT_SYS_OPERATIONS) ###
>>"%TMP_SQL_6%" echo prompt [판단 기준]
>>"%TMP_SQL_6%" echo prompt  - 양호: AUDIT_SYS_OPERATIONS=TRUE
>>"%TMP_SQL_6%" echo prompt  - 취약: FALSE
>>"%TMP_SQL_6%" echo prompt [Command]
>>"%TMP_SQL_6%" echo prompt   select name, value from v^$parameter where name='audit_sys_operations';
>>"%TMP_SQL_6%" echo col name format a30
>>"%TMP_SQL_6%" echo col value format a20
>>"%TMP_SQL_6%" echo select name, value from v^$parameter where name='audit_sys_operations';
>>"%TMP_SQL_6%" echo prompt [진단 결론]
>>"%TMP_SQL_6%" echo set heading off
>>"%TMP_SQL_6%" echo select case when upper(value)='TRUE' then '양호: SYS 감사 수행이 활성화되어 있습니다.' else '취약: SYS 감사 수행이 비활성화되어 있습니다.' end from v^$parameter where name='audit_sys_operations';
>>"%TMP_SQL_6%" echo set heading on

REM -- 6.2 Audit Trail 기록 설정 (AUDIT_TRAIL) --
>>"%TMP_SQL_6%" echo prompt.
>>"%TMP_SQL_6%" echo prompt ### [6.2] Audit Trail 기록 설정 (AUDIT_TRAIL) ###
>>"%TMP_SQL_6%" echo prompt [판단 기준]
>>"%TMP_SQL_6%" echo prompt  - 양호: DB / DB,EXTENDED / OS / XML / XML,EXTENDED
>>"%TMP_SQL_6%" echo prompt  - 취약: NONE
>>"%TMP_SQL_6%" echo prompt [Command]
>>"%TMP_SQL_6%" echo prompt   select name, value from v^$parameter where name='audit_trail';
>>"%TMP_SQL_6%" echo col name format a25
>>"%TMP_SQL_6%" echo col value format a30
>>"%TMP_SQL_6%" echo select name, value from v^$parameter where name='audit_trail';
>>"%TMP_SQL_6%" echo prompt [진단 결론]
>>"%TMP_SQL_6%" echo set heading off
>>"%TMP_SQL_6%" echo select case when upper(value) in ('DB','DB,EXTENDED','OS','XML','XML,EXTENDED') then '양호: 감사가 활성화되어 있습니다.' when upper(value)='NONE' then '취약: 감사가 비활성화되어 있습니다.' else '정보: 알 수 없는 설정값입니다.' end from v^$parameter where name='audit_trail';
>>"%TMP_SQL_6%" echo set heading on

>>"%TMP_SQL_6%" echo spool off
>>"%TMP_SQL_6%" echo exit;

REM ===================== 실행 =====================
echo [INFO] Chapter 6. Audit Settings (6.1 ~ 6.2)...
if defined ORA_CONN (
  sqlplus -s "%ORA_CONN%" @"%TMP_SQL_6%"
) else (
  sqlplus -s / as sysdba @"%TMP_SQL_6%"
)

REM ===================== 정리 =====================
del "%TMP_SQL_6%" >nul 2>nul

echo.
echo [OK] Oracle audit report created (6.1 ~ 6.2 only).
echo    - Folder: "%OUTDIR%"
echo    - Report : "security_report_chapter_6.txt"
endlocal
