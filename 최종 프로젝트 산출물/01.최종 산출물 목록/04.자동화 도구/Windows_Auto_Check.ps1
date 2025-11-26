<#
.SYNOPSIS
   Windows Server 취약점 진단 스크립트 - 1.1 ~ 9.1 
.DESCRIPTION
   - Windows Server 2012부터 Windows Server 2022까지, OS 및 PowerShell 버전(PS 2.0~이상)을 감지
   - secedit /export로 추출된 보안정책(cfg) 파싱, LGPO.exe(사용 가능 시) 이용한 로컬 GPO 내보내기,
     WMI/CIM, 레지스트리, 서비스 상태 등을 다각도로 활용하여 정확도를 높입니다.
   - 레거시 환경에서는 WMI 대신 cmd /c 방식(fallback)으로 net user, net localgroup, net share 등을 호출하고,
     Modern 환경에서는 최신 모듈(Get-CimInstance, Get-SmbShare, ScheduledTasks 모듈 등)을 사용합니다.
   - 이 스크립트는 항목별로 “양호/취약/검토/N/A”를 내도록 하며, 환경에 따라 자동 검증이 불가능하면 “검토” 또는 “수동확인” 처리합니다.
   - 최종 결과는 텍스트 파일과 JSON 파일(동일 경로)에 저장됩니다.

.NOTES
   작성일   : 2025-09-05
   수정일   : 2025-09-05
   참고자료 제작자   : 보안기술팀 윤지환 책임
   제작자: 클라우드보안 과정 25기 취약점 진단 팀 가하늘
   주요정보통신기반시설 기술적 취약점 분석 평가 가이드(2021) 기반인 코드를 SK 쉴더스 2022 보안 가이드라인 OS 진단 windows2019 가이트 항목에 맞춰 수정하고 새로운 항목들을 추가했습니다.
   테스트 OS : Windows Server 2012 이상(PS 3.0+ Modern) ~ 2022
   실행 시  : 관리자 권한 PowerShell 콘솔에서 실행
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypas
#>

# -------------------------------
# (A) 초기 설정 및 공통 함수
# -------------------------------

# ShowResult 함수: 결과 출력 (Write-Log 호출)
function ShowResult {
    param(
        [string]$CheckName,
        [string]$Result
    )
    # 1) JsonOutput에 기록
    $global:JsonOutput[$CheckName].result = $Result

    # 2) (기존 기능) JSON 파일 경로 계산
    $global:JsonFile = [IO.Path]::ChangeExtension($global:ResultFile, 'json')
}

# 1) 보안 정책(secedit /export) 및 LGPO.exe 활용 준비
function Initialize-SecurityExport {
    param([string]$osCategory)

    $global:SecPolContent = $null
    $global:LGPOExists    = $false

    Write-Host "[INFO] secedit /export로 보안 정책 파일 내보내기 시도..."
    $tempFile = "$env:TEMP\secedit_export.cfg"
    try {
        if (Test-Path $tempFile) {
            Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
        }
        secedit /export /cfg $tempFile /quiet
        if (Test-Path $tempFile) {
            $global:SecPolContent = Get-Content $tempFile -ErrorAction SilentlyContinue
            Write-Host "[INFO] secedit_export.cfg 내보내기 및 로드 성공."
        }
    }
    catch {
        Write-Host "[WARN] secedit /export 실패: $($_.Exception.Message)"
    }
    finally {
        if (Test-Path $tempFile) {
            Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
        }
    }

    # LGPO.exe 존재 여부 (Modern 환경에서만 확인)
    $lgpoPath = "C:\Windows\System32\LGPO.exe"
    if ((Test-Path $lgpoPath) -and ($osCategory -eq "Modern")) {
        $global:LGPOExists = $true
        Write-Host "[INFO] LGPO.exe 도구 감지됨 → 필요 시 로컬 GPO 내보내기 활용 가능"
    }
    else {
        Write-Host "[INFO] LGPO.exe 미존재 혹은 Legacy 환경 → Skip"
    }
}

# 2) PowerShell 버전 감지 (PSVersionTable.PSVersion 없으면 PS 2.0 가정)
function Get-PowerShellVersion {
    if ($PSVersionTable -and $PSVersionTable.PSVersion) {
        return $PSVersionTable.PSVersion
    }
    else {
        return [version]"2.0"
    }
}

# 3) OS+PS 버전에 따라 Legacy/Modern 결정
function Get-OSVersionCategory {
    try {
        $psVer = Get-PowerShellVersion
        if ($psVer.Major -lt 3) {
            return "Legacy"
        }
        $os = Get-WmiObject Win32_OperatingSystem -ErrorAction Stop
        $version = [version]$os.Version
        if ($version.Major -lt 6 -or ($version.Major -eq 6 -and $version.Minor -le 1)) {
            return "Legacy"
        }
        else {
            return "Modern"
        }
    }
    catch {
        Write-Host "[WARN] OS 버전 감지 실패: $($_.Exception.Message). Legacy로 가정."
        return "Legacy"
    }
}

# 4) 결과 파일 이름 생성 
function Get-ResultFileName {
    # 타임스탬프
    $nowStr       = (Get-Date).ToString('yyMMdd_HHmm')
    # 호스트명 (자동 변수 $host 대신)
    $computerName = $env:COMPUTERNAME
    # IPv4 (루프백·APIPA 제외)
    $ip = Get-NetIPAddress -AddressFamily IPv4 |
          Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.)' } |
          Select-Object -First 1 -ExpandProperty IPAddress

    # 결과 폴더 준비
    $resultFolder = Join-Path $PSScriptRoot 'Results'
    if (-not (Test-Path $resultFolder)) {
        New-Item -Path $resultFolder -ItemType Directory -Force | Out-Null
    }

    # 파일명 조합 (ip_hostname_yyMMdd_HHmm.txt)
    $fileName = "{0}_{1}_{2}.txt" -f $ip, $computerName, $nowStr
    return Join-Path $resultFolder $fileName
}



# 파싱 헬퍼: secedit /export로 생성된 cfg 파일 파싱
function Parse-SeceditPolicy {
    if ($null -eq $global:SecPolContent -or $global:SecPolContent.Count -eq 0) {
        Write-Host "[WARN] global:SecPolContent가 비어 있음 → null 반환"
        return $null
    }
    $policyTable = @{}
    foreach ($line in $global:SecPolContent) {
        $trimLine = $line.Trim()
        if ($trimLine -match '^\[.*\]$' -or [string]::IsNullOrWhiteSpace($trimLine)) { continue }
        if ($trimLine -match '^\s*(\S+)\s*=\s*(.+)$') {
            $key = $matches[1]
            $val = ($matches[2].Trim()) -replace ",", ""
            $policyTable[$key] = $val
        }
    }
    Write-Host "[DEBUG] 파싱된 보안 정책 키: $($policyTable.Keys -join ', ')"
    return $policyTable
}

# 전역 결과 해시테이블 (1.1 ~ 9.1)
$global:WResult = @{}
# Json 출력용 해시테이블 (진단 순서를 유지하기 위해 ordered 사용)
$global:JsonOutput = [ordered]@{}
# 메타 정보 생성
$meta = [ordered]@{}
$meta["ip"]       = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.)' } | Select-Object -First 1 -ExpandProperty IPAddress)
$meta["hostname"] = $env:COMPUTERNAME
$meta["os"]       = (Get-WmiObject Win32_OperatingSystem).Caption
$meta["date"]     = (Get-Date -Format 'yyyy-MM-dd')
$meta["time"]     = (Get-Date -Format 'HH:mm:ss')

# JsonOutput에 meta 삽입
$global:JsonOutput["meta"] = $meta

$global:CurrentCheckId = $null

# 로그 기록 함수 (콘솔 + 결과 파일)
function Write-Log {
    param([string]$text)
    if (-not [string]::IsNullOrWhiteSpace($text)) {
        $trim = $text.TrimStart()
        if ($global:DisableInfoPrefix) {
            if ($trim -match '^\[INFO\]\s*') {
                $text = $trim -replace '^\[INFO\]\s*', ''
            }
        }
        elseif (-not ($trim -match '^\[') -and -not ($trim -match '^=+')) {
            $text = "[INFO] $text"
        }
    }
    Write-Host $text
    $text | Out-File -FilePath $global:ResultFile -Append -Encoding UTF8
}

# section helpers
function Start-Check {
    param([string]$Id, [string]$Title)
    $global:CurrentCheckId = $Id
    $global:JsonOutput[$Id] = [ordered]@{
        list   = $Id
        item   = $Title
        info   = @()
        result = $null
    }
    Write-Log "`n===========[$Id] $Title ==========="
    $global:DisableInfoPrefix = $true
}

function End-Check {
    $global:DisableInfoPrefix = $false
    $global:CurrentCheckId = $null
}

function Write-Info2 {
    param([string]$text)
    if ($global:CurrentCheckId) {
        $global:JsonOutput[$global:CurrentCheckId].info += $text
    }
}

function Log-And-Record {
    param([string]$msg)
    Write-Log $msg
    Write-Info2 $msg
}

# (추가) LGPO.exe를 통한 로컬 GPO 내보내기
function Export-LGPO {
    param([switch]$Force)
    $lgpoPath = "C:\Windows\System32\LGPO.exe"
    if ((-not (Test-Path $lgpoPath)) -or ($global:osCategory -ne "Modern" -and -not $Force)) {
        Write-Host "[INFO] LGPO.exe 없음 또는 Legacy 환경 → Skip"
        return $null
    }
    $exportTemp = Join-Path $env:TEMP "LGPOExport"
    if (Test-Path $exportTemp) { Remove-Item $exportTemp -Recurse -Force -ErrorAction SilentlyContinue }
    Write-Host "[INFO] LGPO.exe /b 옵션으로 로컬 GPO 내보내기 시도..."
    try {
        & $lgpoPath /b $exportTemp | Out-Null
        if (Test-Path $exportTemp) {
            Write-Host "[INFO] 로컬 GPO 정책 내보내기 성공: $exportTemp"
            return $exportTemp
        }
    }
    catch {
        Write-Host "[WARN] LGPO.exe 실행 오류: $($_.Exception.Message)"
    }
    return $null
}

# OS 버전에 따른 명령어 호출 함수들 (net accounts, net share, net user, net localgroup)
function Get-NetAccountsOutput {
    param([string]$osCategory)
    if ($osCategory -eq "Legacy") { return cmd /c "net accounts" 2>&1 | Out-String }
    else { return net accounts | Out-String }
}
function Get-NetShareOutput {
    param([string]$osCategory)
    if ($osCategory -eq "Legacy") { return cmd /c "net share" 2>&1 | Out-String }
    else { return net share | Out-String }
}
function Get-NetUserOutput {
    param([string]$osCategory, [string]$User)
    if ($osCategory -eq "Legacy") { return cmd /c "net user $User" 2>&1 | Out-String }
    else { return net user $User 2>&1 | Out-String }
}
function Get-NetUserListOutput {
    param([string]$osCategory)
    if ($osCategory -eq "Legacy") { return cmd /c "net user" 2>&1 | Out-String }
    else { return net user | Out-String }
}
function Get-NetLocalGroupOutput {
    param([string]$osCategory, [string]$Group)
    if ($osCategory -eq "Legacy") { return cmd /c "net localgroup $Group" 2>&1 | Out-String }
    else { return net localgroup $Group 2>&1 | Out-String }
}

# 지정된 레지스트리 값 안전하게 반환
function Get-RegValue {
    param([string]$regPath, [string]$prop, [string]$osCategory)
    try {
        $item = Get-ItemProperty -Path $regPath -ErrorAction Stop
        if ($item.PSObject.Properties.Name -contains $prop) { return $item.$prop }
        else {
            Write-Log "경고: '${prop}' 속성이 $regPath 에 존재하지 않습니다."
            return $null
        }
    }
    catch {
        throw "Get-RegValue 오류: $($_.Exception.Message)"
    }
}

# -------------------------------
# (B) 진단 함수 (1.1 ~ 9.1)
# -------------------------------

# CHK_1-1: (W-01 + W-02 + W-03) 통합 판정
# 양호 조건(ALL):
#  1) Administrator 기본 이름 미사용(= 이름 변경되었거나 계정 없음)
#  2) Guest 계정 비활성화(또는 없음)
#  3) 불필요 계정 없음(표준 계정만 존재)
function CHK_1-1 {
    param(
        [ValidateSet('Legacy','Modern','DomainController')]
        [string]$osCategory = 'Modern'
    )

    Start-Check "CHK_1-1" "계정 보안(Administrator 이름 변경 + Guest 비활성 + 불필요 계정 無) [통합]"

    # ---------------------------
    # 1) Administrator 기본 이름 사용 여부
    # ---------------------------
    $adminStatus = '검토'
    try {
        if ($osCategory -eq 'Legacy') {
            $adminAccount = Get-WmiObject Win32_UserAccount -Filter "LocalAccount=True and Name='Administrator'" -ErrorAction Stop
        } else {
            $adminAccount = Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True and Name='Administrator'" -ErrorAction Stop
        }
        Log-And-Record "참고: Administrator 조회 결과 존재여부 = " + ([bool]$adminAccount)

        if ($adminAccount) {
            # 기본 이름 그대로 있음 → 실패
            Log-And-Record "Administrator 기본 계정명이 그대로 존재 → FAIL"
            $adminStatus = '취약'
        } else {
            # 기본 이름이 아님(= 변경됐거나 계정 없음) → 통과
            Log-And-Record "Administrator 기본 계정명이 아님(변경/삭제) → PASS"
            $adminStatus = '양호'
        }
    } catch {
        Log-And-Record "오류: Administrator 조회 실패 → 검토 (${($_.Exception.Message)})"
        $adminStatus = '검토'
    }

    # ---------------------------
    # 2) Guest 계정 비활성화 여부
    # ---------------------------
    $guestStatus = '검토'
    $guestInfo = Get-NetUserOutput -osCategory $osCategory -User 'guest'
    Log-And-Record "참고: net user guest 출력:`n$guestInfo"

    if (-not $guestInfo) {
        Log-And-Record "Guest 계정이 존재하지 않음 → PASS"
        $guestStatus = '양호'
    }
    elseif ($guestInfo -imatch "((활성\s+계정)|(Account\s+active))\s*:?\s*(예|Yes)") {
        Log-And-Record "Guest 계정이 활성화됨 → FAIL"
        $guestStatus = '취약'
    }
    elseif ($guestInfo -imatch "((활성\s+계정)|(Account\s+active))\s*:?\s*(아니요|No)") {
        Log-And-Record "Guest 계정이 비활성화됨 → PASS"
        $guestStatus = '양호'
    }
    else {
        Log-And-Record "Guest 상태 판단 불가 → 검토"
        $guestStatus = '검토'
    }

    # ---------------------------
    # 3) 불필요 계정 존재 여부
    #    - 표준 계정 화이트리스트만 남기고 나머지 있으면 FAIL
    # ---------------------------
    $unnecStatus = '검토'
    $rawUsers = Get-NetUserListOutput -osCategory $osCategory
    Log-And-Record "참고: net user 전체 출력:`n$rawUsers"

    try {
        $lines = $rawUsers -split "`r?`n" | ForEach-Object { $_.Trim() } |
         Where-Object { $_ -and ($_ -notmatch "^(명령|[-]+|사용자 이름|\\.+에 대한 사용자 계정)") }

        $accountList = ($lines -join ' ') -split '\s+' | Where-Object { $_ }

        # 표준 계정(로컬)
        $stdList = @('Administrator','Guest','DefaultAccount','WDAGUtilityAccount', 'infra-db', 'secu-db')

        # 도메인 컨트롤러의 krbtgt 등은 로컬 net user에 보통 안 나오지만, 방어적으로 추가
        if ($osCategory -eq 'DomainController') {
            $stdList += 'krbtgt'
        }

        $nonStd = $accountList | Where-Object { $stdList -notcontains $_ }
        Log-And-Record "표준 외 계정: $($nonStd -join ', ')"

        if ($nonStd -and $nonStd.Count -gt 0) {
            Log-And-Record "불필요(또는 검토 필요) 계정 존재 → FAIL"
            $unnecStatus = '취약'
        } else {
            Log-And-Record "표준 계정만 존재 → PASS"
            $unnecStatus = '양호'
        }
    } catch {
        Log-And-Record "오류: 계정 목록 파싱 실패 → 검토 (${($_.Exception.Message)})"
        $unnecStatus = '검토'
    }

    # ---------------------------
    # 최종 통합 판정
    # ---------------------------
    $statuses = @(
        @{ Name='Administrator 이름 변경'; Value=$adminStatus },
        @{ Name='Guest 비활성화';        Value=$guestStatus },
        @{ Name='불필요 계정 없음';      Value=$unnecStatus }
    )

    $hasFail  = $statuses.Value -contains '취약'
    $hasHold  = ($statuses.Value -contains '검토') -and -not $hasFail
    $allPass  = ($statuses.Value | Where-Object { $_ -ne '양호' }).Count -eq 0

    if ($hasFail) {
        $global:WResult['CHK_1-1'] = '취약'
    } elseif ($allPass) {
        $global:WResult['CHK_1-1'] = '양호'
    } else {
        # FAIL은 없지만 하나라도 판단불가면 검토
        $global:WResult['CHK_1-1'] = '검토'
    }

    # 요약 로그
    $summary = ($statuses | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ' / '
    Log-And-Record "통합 요약: $summary"
    Log-And-Record "최종 판정(CHK_1-1) = $($global:WResult["CHK_1-1"])"

    End-Check
    ShowResult "CHK_1-1" $global:WResult["CHK_1-1"]
}

# CHK_1-2: (W-04 + W-47) 통합 판정
# 양호(ALL)
#  1) W-04 잠금 임계값(Lockout threshold) = 1~5회
#  2) W-47 잠금 기간(Lockout duration)     = 60분 이상
# 취약: 둘 중 하나라도 위반
# 검토: FAIL은 없지만 하나라도 판단 불가
function CHK_1-2 {
    param(
        [ValidateSet('Legacy','Modern','DomainController')]
        [string]$osCategory = 'Modern'
    )

    Start-Check "CHK_1-2" "계정 잠금 임계값(실패 횟수) + 잠금 기간(분) [통합]"

    # net accounts 한 번만 호출해서 두 값 모두 파싱
    $netAccounts = Get-NetAccountsOutput -osCategory $osCategory
    Log-And-Record "참고: net accounts 출력:`n$netAccounts"
    $lines = $netAccounts -split "`r?`n"

    # ---------------------------
    # (W-04) Lockout threshold (회수)
    # ---------------------------
    # (W-04) Lockout threshold (회수)
    $w04 = '검토'
    $lockLine = ($lines | Where-Object { $_ -match "(?i)(Lockout\s*threshold|잠금\s*임계값)" }) -join " "
    if ([string]::IsNullOrWhiteSpace($lockLine)) {
        Log-And-Record "잠금 임계값 정보 없음 → 검토"
        $w04 = '검토'
    } else {
        if ($lockLine -match "(?i)(?:Lockout\s*threshold|잠금\s*임계값)[^0-9]*(\d+)") {
            $threshold = [int]$Matches[1]
            if ($threshold -ge 1 -and $threshold -le 5) {
                Log-And-Record "[INFO] 잠금 임계값: $threshold 회 (권고 1~5회) → PASS"
                $w04 = '양호'
            } else {
                Log-And-Record "[INFO] 잠금 임계값: $threshold 회 (권고 1~5회) → FAIL"
                $w04 = '취약'
            }
        } elseif ($lockLine -match "(?i)(never|아님|없음|무제한)") {
            Log-And-Record "[INFO] 잠금 임계값 미설정(Never) → FAIL"
            $w04 = '취약'
        } else {
            Log-And-Record "잠금 임계값 파싱 실패 → 검토"
            $w04 = '검토'
        }
    }

    # ---------------------------
    # (W-47) Lockout duration (분)
    # ---------------------------
    $w47 = '검토'
    $durLine = ($lines | Where-Object { $_ -match "(?i)(Lockout\s*duration|잠금\s*기간)" }) -join " "
    if ([string]::IsNullOrWhiteSpace($durLine)) {
        Log-And-Record "잠금 기간 정보 없음 → 검토"
        $w47 = '검토'
    } else {
        if ($durLine -match "(?i)(?:Lockout\s*duration|잠금\s*기간)(?:\s*\(분\))?[^0-9]*(\d+)") {
            $duration = [int]$Matches[1]
            Log-And-Record "[INFO] 잠금 기간: $duration 분 (권고 ≥30분)"
            if ($duration -ge 30) {
                $w47 = '양호'
            } else {
                $w47 = '취약'
            }
        } elseif ($durLine -match "(?i)(never|아님|없음|무제한)") {
            Log-And-Record "[INFO] 잠금 기간 미설정(Never) → FAIL"
            $w47 = '취약'
        } else {
            Log-And-Record "잠금 기간 파싱 실패 → 검토"
            $w47 = '검토'
        }
    }

    # ---------------------------
    # (W-47b) Reset account lockout counter after (분)
    #  - 가이드: ≥ 30분이면 양호
    #  - UI/로캘별 표기 다양 → 다중 패턴 + secedit 보조
    # ---------------------------
    $w47b = '검토'

    # 공백 변동(탭/여러 칸) 대비해서 라인 정규화
    $normLines = $lines | ForEach-Object { ($_ -replace '\s+', ' ').Trim() }

    # 여러 후보 라벨을 OR로 처리
    $resetLine = ($normLines | Where-Object {
        $_ -match '(?i)(
            Reset\s+account\s+lockout\s+counter\s+after     # 영문
            |원래대로\s*설정                                 # 번역 1
            |잠금\s*관찰\s*창                                # 번역 2 (실사용 예: "잠금 관찰 창 (분)")
            |다음\s*시간\s*후\s*계정\s*잠금\s*수를\s*원래대로\s*설정 # 번역 3(정식 표현)
        )'
    }) -join ' '

    if ([string]::IsNullOrWhiteSpace($resetLine)) {
        Log-And-Record "원래대로 설정(Reset counter) 정보 없음 → [보조: secedit] 시도"
        # 보조: secedit /export 로컬 보안정책(INF)의 ResetLockoutCount(분) 확인
        try {
            $policy = $null
            try { $policy = Parse-SeceditPolicy } catch {}
            if ($policy -and $policy.ContainsKey('ResetLockoutCount')) {
                $resetMins = [int]$policy['ResetLockoutCount']
                Log-And-Record "[INFO] [secedit] ResetLockoutCount=$resetMins 분 (권고 ≥30분)"
                if ($resetMins -ge 30) { $w47b = '양호' } else { $w47b = '취약' }
            } else {
                $w47b = '검토'
            }
        } catch {
            Log-And-Record "[WARN] secedit 보조 실패: $($_.Exception.Message)"
            $w47b = '검토'
        }
    }
    else {
        Log-And-Record "[DEBUG] Reset 매칭 라인: $resetLine"
        if ($resetLine -match '(?i)(\d+)\s*(minutes?|mins?|분)') {
            $resetMins = [int]$Matches[1]
            Log-And-Record "[INFO] 원래대로 설정(Reset counter): $resetMins 분 (권고 ≥30분)"
            if ($resetMins -ge 30) { $w47b = '양호' } else { $w47b = '취약' }
        }
        elseif ($resetLine -match '(?i)(never|아님|없음|무제한)') {
            Log-And-Record "[INFO] 원래대로 설정 미설정(Never) → 취약"
            $w47b = '취약'
        }
        else {
            Log-And-Record "원래대로 설정(Reset counter) 파싱 실패 → 검토"
            $w47b = '검토'
        }
    }

    # ---------------------------
    # 최종 통합 판정
    # ---------------------------
    $statuses = @(
        @{ Name='잠금 임계값(1~5회)'; Value=$w04 },
        @{ Name='잠금 기간(≥30분)';  Value=$w47 },
        @{ Name='원래대로 설정(≥30분)'; Value=$w47b }
    )

    $hasFail = $statuses.Value -contains '취약'
    $allPass = ($statuses.Value | Where-Object { $_ -ne '양호' }).Count -eq 0

    if ($hasFail) {
        $global:WResult['CHK_1-2'] = '취약'
    } elseif ($allPass) {
        $global:WResult['CHK_1-2'] = '양호'
    } else {
        $global:WResult['CHK_1-2'] = '검토'
    }

    $summary = ($statuses | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ' / '
    Log-And-Record "통합 요약: $summary"
    Log-And-Record "최종 판정(CHK_1-2) = $($global:WResult['CHK_1-2'])"

    End-Check
    ShowResult 'CHK_1-2' $global:WResult['CHK_1-2']
}

# CHK_1-3: 암호 정책 설정 W-05, W-49, W-50, W-51, W-55, W-80)
function CHK_1-3 {
    param(
        [ValidateSet('Legacy','Modern','DomainController')]
        [string]$osCategory = 'Modern'
    )

    Start-Check "CHK_1-3" "암호 정책 설정 [W-05,49,50,51,55,80]"

    # 공통: 로컬 보안 정책 파싱(여러 항목에 재사용)
    $policy = $null
    try {
        $policy = Parse-SeceditPolicy
        if (-not $policy) { Log-And-Record "[WARN] 보안 정책 파싱 실패(Null)"; }
    } catch {
        Log-And-Record "[WARN] 보안 정책 파싱 예외: $($_.Exception.Message)"
    }

    # ---------------------------
    # W-05: ClearTextPassword = 0
    # ---------------------------
    $w05 = '검토'
    if ($policy -and $policy.ContainsKey('ClearTextPassword')) {
        $val = [int]$policy['ClearTextPassword']
        Log-And-Record "[INFO] ClearTextPassword: $val (권고: 0)"
        if ($val -eq 0) { $w05 = '양호' } else { $w05 = '취약' }
    } elseif ($policy) {
        Log-And-Record "[WARN] ClearTextPassword 항목 없음 → 검토"
        $w05 = '검토'
    } else {
        $w05 = '검토'
    }

    # ---------------------------
    # W-49: MinimumPasswordLength ≥ 8
    # ---------------------------
    $w49 = '검토'
    if ($policy -and $policy.ContainsKey('MinimumPasswordLength')) {
        $val = [int]$policy['MinimumPasswordLength']
        Log-And-Record "[INFO] MinimumPasswordLength: $val (권고: ≥8)"
        if ($val -ge 8) { $w49 = '양호' } else { $w49 = '취약' }
    } elseif ($policy) {
        Log-And-Record "[WARN] MinimumPasswordLength 항목 없음 → 검토"
        $w49 = '검토'
    } else {
        $w49 = '검토'
    }

    # ---------------------------
    # Complexity: PasswordComplexity = 1 (사용)
    # ---------------------------
    $wComplex = '검토'
    $complexVal = $null

    # 도메인 기본 정책 우선
    $domainJoined = $false
    try {
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        $domainJoined = $cs.PartOfDomain
    } catch {}

    if ($domainJoined) {
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
            $pwd = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop
            $complexVal = [bool]$pwd.ComplexityEnabled
            Log-And-Record "[INFO] [Domain] ComplexityEnabled=$complexVal (권고: 사용)"
        } catch {
            Log-And-Record "[WARN] 도메인 복잡도 조회 실패 → 로컬 정책 보조"
        }
    }

    # 로컬(보조): secedit /export 파싱
    if ($null -eq $complexVal -and $policy -and $policy.ContainsKey('PasswordComplexity')) {
        try {
            $complexVal = ([int]$policy['PasswordComplexity'] -eq 1)
            Log-And-Record "[INFO] [Local] PasswordComplexity=" + ($(if($complexVal){'1'}else{'0'})) + " (권고: 1)"
        } catch {}
    }

    if ($null -eq $complexVal) {
        Log-And-Record "복잡도 설정 파악 불가 → 검토"
        $wComplex = '검토'
    } else {
        $wComplex = ($(if ($complexVal){'양호'} else {'취약'}))
    }

    # ---------------------------
    # W-50: MaximumPasswordAge ≤ 60, -1 금지
    # ---------------------------
    $w50 = '검토'
    if ($policy -and $policy.ContainsKey('MaximumPasswordAge')) {
        try {
            $val = [int]$policy['MaximumPasswordAge']
            Log-And-Record "[INFO] MaximumPasswordAge: $val 일 (권고: ≤60, -1 금지)"
            if ($val -eq -1) {
                $w50 = '취약'
            } elseif ($val -le 60) {
                $w50 = '양호'
            } else {
                $w50 = '취약'
            }
        } catch {
            Log-And-Record "[WARN] MaximumPasswordAge 변환 오류 → 검토"
            $w50 = '검토'
        }
    } elseif ($policy) {
        Log-And-Record "[WARN] MaximumPasswordAge 항목 없음 → 검토"
        $w50 = '검토'
    } else {
        $w50 = '검토'
    }

    # ---------------------------
    # W-51: MinimumPasswordAge ≥ 7
    # ---------------------------
    $w51 = '검토'
    if ($policy -and $policy.ContainsKey('MinimumPasswordAge')) {
        try {
            $val = [int]$policy['MinimumPasswordAge']
            Log-And-Record "[INFO] MinimumPasswordAge: $val 일 (권고: ≥7)"
            if ($val -ge 7) { $w51 = '양호' } else { $w51 = '취약' }
        } catch {
            Log-And-Record "[WARN] MinimumPasswordAge 변환 오류 → 검토"
            $w51 = '검토'
        }
    } elseif ($policy) {
        Log-And-Record "[WARN] MinimumPasswordAge 항목 없음 → 검토"
        $w51 = '검토'
    } else {
        $w51 = '검토'
    }

    # ---------------------------
    # W-55: PasswordHistorySize ≥ 12
    # ---------------------------
    $w55 = '검토'
    if ($policy -and $policy.ContainsKey('PasswordHistorySize')) {
        $val = [int]$policy['PasswordHistorySize']
        Log-And-Record "[INFO] PasswordHistorySize: $val (권고: ≥12)"
        if ($val -ge 12) { $w55 = '양호' } else { $w55 = '취약' }
    } elseif ($policy) {
        Log-And-Record "[WARN] PasswordHistorySize 항목 없음 → 검토"
        $w55 = '검토'
    } else {
        $w55 = '검토'
    }

    # ---------------------------
    # W-80: 컴퓨터 계정 암호 최대 사용 기간
    #   - 도메인: MaxPasswordAge 정확히 60일
    #   - 워크그룹: MaximumPasswordAge=60 AND DisableMachineAccountPasswordChange=0
    # ---------------------------
    $w80 = '검토'
    $domainJoined = $false
    try {
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        $domainJoined = $cs.PartOfDomain

        # PS 5.1 호환: 삼항연산자 대신 변수로 처리
        $domainState = '워크그룹'
        if ($domainJoined) { $domainState = '도메인' }
        Log-And-Record "[INFO] 도메인 가입 상태: $domainState"
    } catch {
        Log-And-Record "[WARN] 도메인 가입 여부 조회 실패: $($_.Exception.Message)"
    }

    if ($domainJoined) {
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
            $pwdPolicy = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop
            $maxPwdAgeDays = (-$pwdPolicy.MaxPasswordAge).Days
            Log-And-Record "[INFO] 도메인 MaxPasswordAge: $maxPwdAgeDays 일 (요건: 60일)"
            if ($maxPwdAgeDays -eq 60) { $w80 = '양호' } else { $w80 = '취약' }
        } catch {
            Log-And-Record "[WARN] 도메인 암호 정책 조회 오류: $($_.Exception.Message) → 검토"
            $w80 = '검토'
        }
    } else {
        if ($policy) {
            $ok = $false
            $reason = @()

            if ($policy.ContainsKey('MaximumPasswordAge')) {
                $maxAge = [int]$policy['MaximumPasswordAge']
                Log-And-Record "[INFO] 로컬 MaximumPasswordAge: $maxAge (요건: 90)"
                if ($maxAge -eq 60) { $ok = $true } else { $reason += 'MaximumPasswordAge≠60' }
            } else {
                $reason += 'MaximumPasswordAge 미설정'
            }

            $disableChange = 0
            if ($policy.ContainsKey('DisableMachineAccountPasswordChange')) {
                $disableChange = [int]$policy['DisableMachineAccountPasswordChange']
                Log-And-Record "[INFO] DisableMachineAccountPasswordChange: $disableChange (요건: 0)"
                if ($disableChange -ne 0) { $ok = $false; $reason += 'DisableMachineAccountPasswordChange≠0' }
            } else {
                $reason += 'DisableMachineAccountPasswordChange 미설정'
                $ok = $false
            }

            if ($ok -and $disableChange -eq 0) { $w80 = '양호' }
            elseif ($reason.Count -gt 0) { $w80 = '취약' }
            else { $w80 = '검토' }
        } else {
            $w80 = '검토'
        }
    }

    # ---------------------------
    # 최종 통합 판정
    # ---------------------------
    $statuses = @(
        @{ Name='Complexity=On';      Value=$wComplex },
        @{ Name='ClearTextPassword=0'; Value=$w05 },
        @{ Name='MinLen≥8';            Value=$w49 },
        @{ Name='MaxAge≤60 & not -1';  Value=$w50 },
        @{ Name='MinAge≥7';            Value=$w51 },
        @{ Name='History≥12';          Value=$w55 }
    )
    # 요약에만 W-80 추가(판정에는 영향 X)
    Log-And-Record ("[참고] MachinePwdPolicy(W-80) = {0}" -f $w80)

    $hasFail = $false
    foreach ($s in $statuses) { if ($s.Value -eq '취약') { $hasFail = $true; break } }

    $allPass = $true
    foreach ($s in $statuses) { if ($s.Value -ne '양호') { $allPass = $false; break } }

    if ($hasFail) {
        $global:WResult['CHK_1-3'] = '취약'
    } elseif ($allPass) {
        $global:WResult['CHK_1-3'] = '양호'
    } else {
        $global:WResult['CHK_1-3'] = '검토'
    }

    $summaryParts = @()
    foreach ($s in $statuses) { $summaryParts += ("{0}={1}" -f $s.Name, $s.Value) }
    $summary = ($summaryParts -join ' / ')
    Log-And-Record "통합 요약: $summary"
    Log-And-Record "최종 판정(CHK_1-3) = $($global:WResult['CHK_1-3'])"

    End-Check
    ShowResult 'CHK_1-3' $global:WResult['CHK_1-3']
}

# ---------- CHK_1-4: 취약한 패스워드 점검 (통합본) ----------
# 가이드 요약: 복잡도=ON 이고 최소 길이 ≥ 8 이면 양호.
# 참고(로그만 남김): NoLMHash=1, LimitBlankPasswordUse=1 권고.
function CHK_1-4 {
    param([string]$osCategory)

    Start-Check "CHK_1-4" "취약한 패스워드 점검(가이드: 계정과 유사하지 않은 8자 이상의 영문/숫자/특수문자 조합)"

    $result = "검토"

    # 0) 도메인 가입 여부
    $domainJoined = $false
    try {
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        $domainJoined = $cs.PartOfDomain
        Log-And-Record "[INFO] 도메인 가입: " + ($(if ($domainJoined) {'도메인'} else {'워크그룹'}))
    } catch {
        Log-And-Record "[WARN] 도메인 여부 조회 실패: $($_.Exception.Message)"
    }

    # 공통: 로컬 secedit 정책(보조용)
    $policy = $null
    try { $policy = Parse-SeceditPolicy } catch {}

    # 1) 복잡도(Complexity) + 2) 최소 길이(MinLength)
    $complex = $null   # True/False/Null
    $minLen  = $null   # int/Null

    # (우선) 도메인 기본 정책
    if ($domainJoined) {
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
            $pwd   = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop
            $complex = [bool]$pwd.ComplexityEnabled
            $minLen  = [int]$pwd.MinPasswordLength
            Log-And-Record "[INFO] [Domain] ComplexityEnabled=$complex, MinPasswordLength=$minLen (가이드: 복잡도=사용 AND 길이≥8)"
        } catch {
            Log-And-Record "[WARN] 도메인 암호정책 조회 실패: $($_.Exception.Message) → 로컬 정책으로 보조"
        }
    }

    # (보조) 로컬 정책(secedit /export)
    if (($null -eq $complex) -or ($null -eq $minLen)) {
        if ($policy) {
            if ($policy.ContainsKey("PasswordComplexity")) {
                try { $complex = ([int]$policy["PasswordComplexity"] -eq 1) } catch {}
                if ($null -ne $complex) { Log-And-Record "[INFO] [Local] PasswordComplexity=" + ($(if ($complex){'1(사용)'} else {'0(사용 안 함)'})) }
            } else {
                Log-And-Record "[WARN] [Local] PasswordComplexity 항목 없음"
            }

            if ($policy.ContainsKey("MinimumPasswordLength")) {
                try { $minLen = [int]$policy["MinimumPasswordLength"] } catch {}
                if ($null -ne $minLen) { Log-And-Record "[INFO] [Local] MinimumPasswordLength=$minLen" }
            } else {
                Log-And-Record "[WARN] [Local] MinimumPasswordLength 항목 없음"
            }
        } else {
            Log-And-Record "[WARN] secedit 정책을 읽지 못함"
        }
    }

    # 3) 참고(로그용 권고): LM 해시 저장 금지 / 빈 비밀번호 제한
    try {
        $noLM = Get-ItemPropertyValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'NoLMHash' -ErrorAction SilentlyContinue
        if ($null -ne $noLM) {
            if ($noLM -eq 1) { Log-And-Record "[INFO] 권고: NoLMHash=1 (OK)" }
            else { Log-And-Record "[WARN] 권고: NoLMHash=$noLM (권고값 1)" }
        } else { Log-And-Record "[WARN] 권고 확인 불가: NoLMHash 없음" }
    } catch { Log-And-Record "[WARN] NoLMHash 확인 실패: $($_.Exception.Message)" }

    try {
        $limitBlank = Get-ItemPropertyValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LimitBlankPasswordUse' -ErrorAction SilentlyContinue
        if ($null -ne $limitBlank) {
            if ($limitBlank -eq 1) { Log-And-Record "[INFO] 권고: LimitBlankPasswordUse=1 (OK)" }
            else { Log-And-Record "[WARN] 권고: LimitBlankPasswordUse=$limitBlank (권고값 1)" }
        } else { Log-And-Record "[WARN] 권고 확인 불가: LimitBlankPasswordUse 없음" }
    } catch { Log-And-Record "[WARN] LimitBlankPasswordUse 확인 실패: $($_.Exception.Message)" }

    # 최종 판정 (가이드 1.4에 맞춤)
    # - 양호: 복잡도=사용 AND 최소 길이 ≥ 8
    #   * 복잡도=사용은 계정명/표시명과 유사한 문자열 포함을 제한하므로
    #     '계정과 유사하지 않은' 조건을 대리 충족.
    # - 취약: 위 조건 불만족
    # - 검토: 정책값 확보 불가
    if ($null -ne $complex -and $null -ne $minLen) {
        if ($complex -and ($minLen -ge 8)) {
            $result = "양호"
        } else {
            $result = "취약"
        }
    } else {
        $result = "검토"
    }

    Log-And-Record "[NOTE] 본 항목은 정책 기반 자동판정이며, 실제 개별 비밀번호의 연속/반복/사전형 여부 등 세부 품질은 별도 점검이 필요할 수 있음."
    $global:WResult["CHK_1-4"] = $result
    End-Check
    ShowResult "CHK_1-4" $result
}

# ---------- CHK_1-5: 사용자 계정 컨트롤(UAC) 설정 ----------
function CHK_1-5 {
    param([string]$osCategory)

    Start-Check "CHK_1-5" "사용자 계정 컨트롤(UAC) 설정"

    $result = "검토"
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

    try {
        if (-not (Test-Path $regPath)) {
            Log-And-Record "[WARN] 레지스트리 경로 없음: $regPath"
            $global:WResult["CHK_1-5"] = "검토"
            End-Check
            ShowResult "CHK_1-5" "검토"
            return
        }

        $p = Get-ItemProperty -Path $regPath -ErrorAction Stop

        # 핵심 키
        $enableLUA = $null
        $consent   = $null
        $secure    = $null

        if ($p.PSObject.Properties.Name -contains 'EnableLUA')                 { $enableLUA = [int]$p.EnableLUA }
        if ($p.PSObject.Properties.Name -contains 'ConsentPromptBehaviorAdmin'){ $consent   = [int]$p.ConsentPromptBehaviorAdmin }
        if ($p.PSObject.Properties.Name -contains 'PromptOnSecureDesktop')     { $secure    = [int]$p.PromptOnSecureDesktop }

        Log-And-Record "[INFO] EnableLUA=$enableLUA (1=UAC 사용)"
        Log-And-Record "[INFO] ConsentPromptBehaviorAdmin=$consent (2=항상 알림, 5=기본값, 0=알림 안 함)"
        Log-And-Record "[INFO] PromptOnSecureDesktop=$secure (1=보안 데스크톱)"

        # ---- 판정 로직 (가이드 정합) ----
        # 1) UAC가 꺼져 있으면 즉시 취약
        if ($enableLUA -ne 1) {
            Log-And-Record "[FAIL] UAC 비활성화(EnableLUA≠1)"
            $result = "취약"
        }
        else {
            # 2) '기본값 이상'만 요구 → Consent ∈ {5(기본), 2(항상)}
            $okConsent = $false
            if ($null -ne $consent) {
                if ($consent -in 2,5) { $okConsent = $true }
                elseif ($consent -eq 0) { Log-And-Record "[FAIL] 관리자 알림 꺼짐(Consent=0)" }
            }

            # 3) 보안 데스크톱은 '권장'만 기록, 판정에는 미반영
            if ($okConsent) {
                $result = "양호"
            }
            elseif ($null -eq $consent) {
                Log-And-Record "[WARN] Consent 값을 읽지 못함 → 검토"
                $result = "검토"
            }
            else {
                $result = "취약"
            }
        }
    }
    catch {
        Log-And-Record "[WARN] CHK_1-5 점검 중 오류: $($_.Exception.Message)"
        $result = "검토"
    }

    $global:WResult["CHK_1-5"] = $result
    End-Check
    ShowResult "CHK_1-5" $result
}

# ---------- CHK_1-6: 익명 SID/이름 변환 허용 정책 (LSAAnonymousNameLookup) ----------
function CHK_1-6 {
    param([string]$osCategory)
    Start-Check "CHK_1-6" "익명 SID/이름 변환 허용 정책 (LSAAnonymousNameLookup)"
    $policy = Parse-SeceditPolicy
    if ($policy) {
        $val = $policy["LSAAnonymousNameLookup"]
        Log-And-Record "[INFO] LSAAnonymousNameLookup: $val (권고: 0)"
        if ([int]$val -eq 0) {
            $global:WResult["CHK_1-6"] = "양호"
        }
        else {
            $global:WResult["CHK_1-6"] = "취약"
        }
    }
    else {
        try {
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
            $val2 = (Get-ItemProperty $regPath -Name "LSAAnonymousNameLookup" -ErrorAction Stop).LSAAnonymousNameLookup
            Log-And-Record "[INFO] LSAAnonymousNameLookup (registry): $val2 (권고: 0)"
            if ([int]$val2 -eq 0) {
                $global:WResult["CHK_1-6"] = "양호"
            }
            else {
                $global:WResult["CHK_1-6"] = "취약"
            }
        }
        catch {
            Log-And-Record "[WARN] LSAAnonymousNameLookup 조회 오류 → 검토"
            $global:WResult["CHK_1-6"] = "검토"
        }
    }
    End-Check
    ShowResult "CHK_1-6" $global:WResult["CHK_1-6"]
}

# ---------- CHK_1-7: 콘솔 로그온 시 로컬 계정에서 빈 암호 사용 제한 정책 점검 ----------
function CHK_1-7 {
    param([string]$osCategory)
    Start-Check "CHK_1-7" "콘솔 로그온 시 로컬 계정에서 빈 암호 사용 제한 정책 점검"
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    $prop = "LimitBlankPasswordUse"
    try {
        $val = Get-RegValue -regPath $regPath -prop $prop -osCategory $osCategory
        Log-And-Record "[INFO] LimitBlankPasswordUse: $val (권고: 1)"
        if ([int]$val -eq 1) {
            $global:WResult["CHK_1-7"] = "양호"
        }
        else {
            $global:WResult["CHK_1-7"] = "취약"
        }
    }
    catch {
        Log-And-Record "[WARN] LimitBlankPasswordUse 조회 오류 → 검토"
        $global:WResult["CHK_1-7"] = "검토"
    }
    End-Check
    ShowResult "CHK_1-7" $global:WResult["CHK_1-7"]
}

# ---------- CHK_1-8: 관리자 그룹에 최소한의 사용자 포함 ----------
function CHK_1-8 {
    param([string]$osCategory)
    Start-Check "CHK_1-8" "관리자 그룹에 최소한의 사용자 포함"

    $groupOutput = Get-NetLocalGroupOutput -Group "Administrators" -osCategory $osCategory
    Log-And-Record "참고: Administrators 그룹 정보:"
    Log-And-Record $groupOutput

    $lines = $groupOutput -split "`r?\n" | ForEach-Object { $_.Trim() } |
             Where-Object {
                 $_ -and 
                 ($_ -notmatch "^(Members of|Alias for|명령을 잘 실행|[-]+|구성원|별칭|설명)") -and
                 ($_ -notmatch "^\*")
             }

    # 허용 계정 목록
    $allowed = @("Administrator", "Domain Admins", "원격 데스크톱 사용자", "infra-db", "secu-db", $env:USERNAME)

    # 허용 목록 외 계정
    $extra = $lines | Where-Object { $allowed -notcontains $_ }

    Log-And-Record "관리자 그룹 구성원: $($lines -join ', ')"
    Log-And-Record "허용 외 구성원: $($extra -join ', ')"

    # 단독 사용자 허용 로직
    if (($lines.Count -eq 1) -and ($lines[0] -eq $env:USERNAME)) {
        Log-And-Record "[INFO] 단독 관리자 계정이 현재 사용자 ($env:USERNAME) → 양호"
        $global:WResult["CHK_1-8"] = "양호"
    }
    elseif ($extra.Count -gt 0) {
        Log-And-Record "[INFO] 불필요 관리자 계정 존재: $($extra -join ', ') → 취약"
        $global:WResult["CHK_1-8"] = "취약"
    }
    else {
        Log-And-Record "[INFO] 추가 관리자 없음 또는 허용 목록만 존재 → 양호"
        $global:WResult["CHK_1-8"] = "양호"
    }

    End-Check
    ShowResult "CHK_1-8" $global:WResult["CHK_1-8"]
}

# ---------- CHK_2-1: CMD.EXE 파일 권한 설정 ----------
function CHK_2-1 {
    param([string]$osCategory)

    Start-Check "CHK_2-1" "CMD.EXE 파일 권한 설정"

    $result  = "검토"
    $cmdPath = "$env:windir\System32\cmd.exe"

    try {
        if (-not (Test-Path $cmdPath)) {
            Log-And-Record "[WARN] cmd.exe 경로 없음: $cmdPath"
            $global:WResult["CHK_2-1"] = "검토"
            End-Check
            ShowResult "CHK_2-1" "검토"
            return
        }

        # 0) IIS(W3SVC) 실행 여부
        $iisRunning = $false
        try {
            $svc = Get-Service W3SVC -ErrorAction SilentlyContinue
            if ($svc -and $svc.Status -eq 'Running') { $iisRunning = $true }
        } catch {}
        Log-And-Record "[INFO] IIS(W3SVC) 실행 여부: $iisRunning"

        # 1) ACL 조회 (소유자는 참고용만 — 가이드 판정에는 사용 안 함)
        $acl = Get-Acl $cmdPath
        Log-And-Record "[INFO] 소유자(참고): $($acl.Owner)"

        # 실행 권한 판정 함수 (Execute/ReadAndExecute/GenericExecute/Modify/FullControl을 실행 가능으로 간주)
        function Has-ExecRight {
            param([System.Security.AccessControl.FileSystemRights]$r)
            return (
                ($r -band [IO.FileSystemRights]::ExecuteFile)                  -or
                ($r -band [IO.FileSystemRights]::ReadAndExecute)               -or
                ($r -band [IO.FileSystemRights]::Synchronize -and $r -band [IO.FileSystemRights]::ReadAndExecute) -or
                ($r -band [IO.FileSystemRights]::GenericExecute)               -or
                ($r -band [IO.FileSystemRights]::Modify)                       -or
                ($r -band [IO.FileSystemRights]::FullControl)
            )
        }

        # 가이드가 허용하는 실행 주체(정확한 이름 매칭, 도메인/BUILTIN 접두는 허용)
        $allowedExecExact = @(
            'Administrators',              # BUILTIN\Administrators 등
            'SYSTEM',                      # NT AUTHORITY\SYSTEM
            'TrustedInstaller'             # NT SERVICE\TrustedInstaller
        )
        function Is-AllowedExecIdentity {
            param([string]$id)
            $nameOnly = ($id -split '\\')[-1]
            return ($allowedExecExact -contains $nameOnly)
        }

        # 2) IIS가 꺼져 있으면 → 가이드에 따라 즉시 양호
        if (-not $iisRunning) {
            Log-And-Record "[OK] IIS 미실행 → 가이드 기준에 따라 양호"
            $result = "양호"
        }
        else {
            # 3) IIS 실행 중: 실행 권한 보유 주체 수집
            $execAllowedOthers = @()
            foreach ($ace in $acl.Access) {
                if ($ace.AccessControlType -ne "Allow") { continue }
                $id  = $ace.IdentityReference.Value
                $rts = $ace.FileSystemRights

                if (Has-ExecRight $rts) {
                    if (-not (Is-AllowedExecIdentity $id)) {
                        $execAllowedOthers += "$id($rts)"
                    }
                }
            }

            if ($execAllowedOthers.Count -gt 0) {
                Log-And-Record "[FAIL] IIS 실행 중이며, 허용 외 주체가 cmd.exe 실행 권한 보유: $($execAllowedOthers -join ', ')"
                $result = "취약"
            } else {
                Log-And-Record "[OK] IIS 실행 중이며, 실행 권한 주체가 Administrators/SYSTEM/TrustedInstaller로만 제한됨"
                $result = "양호"
            }
        }
    }
    catch {
        Log-And-Record "[WARN] CHK_2-1 점검 중 오류: $($_.Exception.Message)"
        $result = "검토"
    }

    $global:WResult["CHK_2-1"] = $result
    End-Check
    ShowResult "CHK_2-1" $result
}

# ---------- CHK_2-2: 사용자 홈 디렉터리 접근 제한 ----------

function CHK_2-2 {
    param([string]$osCategory)

    Start-Check "CHK_2-2" "사용자 홈 디렉터리 접근 제한"
    $usersPath = "C:\Users"

    if (-not (Test-Path $usersPath)) {
        Log-And-Record "[WARN] $usersPath 경로 미존재 → 검토"
        $global:WResult["CHK_2-2"] = "검토"
        End-Check
        ShowResult "CHK_2-2" $global:WResult["CHK_2-2"]
        return
    }

    # 올바른 형식 사용
    function Has-FullControl {
        param([System.Security.AccessControl.FileSystemRights]$r)
        return (($r -band [System.Security.AccessControl.FileSystemRights]::FullControl) -ne 0)
    }

    # Everyone/Users 매칭(이름/로캘/SID 모두 대응)
    function Is-Everyone {
        param([string]$id)
        $trim = $id.Trim()
        $short = ($trim -split '\\')[-1]
        return (
            $short -ieq 'Everyone' -or
            $short -eq '모든 사용자' -or  # 일부 로캘
            $trim  -match '^S-1-1-0$'    # Everyone SID
        )
    }
    function Is-UsersGroup {
        param([string]$id)
        $trim = $id.Trim()
        $short = ($trim -split '\\')[-1]
        return (
            $short -ieq 'Users' -or
            $short -eq '사용자' -or        # 일부 로캘
            $trim  -match '^S-1-5-32-545$' # Users(Local) SID
        )
    }

    $dirs = Get-ChildItem $usersPath -Directory -ErrorAction SilentlyContinue
    $violations = @()

    foreach ($dir in $dirs) {
        try {
            $acl = Get-Acl $dir.FullName
            $badAces = @()

            foreach ($ace in $acl.Access) {
                if ($ace.AccessControlType -ne "Allow") { continue }

                $id  = $ace.IdentityReference.Value
                $rts = $ace.FileSystemRights

                if (Has-FullControl $rts) {
                    if (Is-Everyone $id -or Is-UsersGroup $id) {
                        $badAces += ('{0}: {1}' -f $id, $rts)
                    }
                }
            }

            if ($badAces.Count -gt 0) {
                Log-And-Record ("[FAIL] '{0}'에서 Users:F 또는 Everyone:F 발견 → {1}" -f $dir.FullName, ($badAces -join '; '))
                $violations += $dir.FullName
            } else {
                Log-And-Record ("[OK] '{0}'에 Users:F / Everyone:F 없음" -f $dir.FullName)
            }
        }
        catch {
            Log-And-Record ("[WARN] '{0}' ACL 조회 오류: {1} → 검토" -f $dir.FullName, $_.Exception.Message)
            $violations += "<검토:$($dir.FullName)>"
        }
    }

    if ($violations.Count -eq 0) {
        $global:WResult["CHK_2-2"] = "양호"
    }
    else {
        $hasErr = ($violations | Where-Object { $_ -like '<검토:*>' }).Count -gt 0
        $hasBad = ($violations | Where-Object { $_ -notlike '<검토:*>' }).Count -gt 0
        if ($hasErr -and -not $hasBad) { $global:WResult["CHK_2-2"] = "검토" }
        else                            { $global:WResult["CHK_2-2"] = "취약" }
    }

    End-Check
    ShowResult "CHK_2-2" $global:WResult["CHK_2-2"]
}

# ---------- CHK_2-3: 공유 권한 및 기본 공유 설정 [가이드 정합] ----------
function CHK_2-3 {
    param([string]$osCategory)

    Start-Check "CHK_2-3" "공유 권한 및 기본 공유 설정 [통합]"

    # 공통 헬퍼 ---------------------------------------------------------
    function Get-AutoShareServerValue {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
        try {
            $v = (Get-ItemProperty -Path $regPath -Name "AutoShareServer" -ErrorAction SilentlyContinue).AutoShareServer
            return $v  # null 또는 0/1
        } catch { return $null }
    }

    # “암호 보호 공유” 판정(로컬 정책 표기 차이를 흡수: 둘 중 하나로 감지)
    # - Windows 계열에서 일반적으로 다음 중 하나로 표현됨:
    #   * HKLM\...\Lsa\UserAuthenticatedSharing = 1  → ON
    #   * HKLM\...\Lsa\ForceGuest = 0                → ON (게스트 강제 미사용)
    function Get-PasswordProtectedSharingOn {
        $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        try {
            $uas = (Get-ItemProperty -Path $lsaPath -Name "UserAuthenticatedSharing" -ErrorAction SilentlyContinue).UserAuthenticatedSharing
        } catch { $uas = $null }
        try {
            $fg = (Get-ItemProperty -Path $lsaPath -Name "ForceGuest" -ErrorAction SilentlyContinue).ForceGuest
        } catch { $fg = $null }

        # 판단 로직: UAS=1 이거나, ForceGuest=0 이면 ON 으로 간주
        if (($uas -ne $null -and [int]$uas -eq 1) -or ($fg -ne $null -and [int]$fg -eq 0)) { return $true }
        if (($uas -ne $null -and [int]$uas -eq 0) -or ($fg -ne $null -and [int]$fg -eq 1)) { return $false }
        return $null   # 판단 불가
    }

    # Everyone 존재 여부를 공유별로 확인 (Modern: SMB cmdlet / Legacy: WMI DACL)
    function Test-AnyShareHasEveryone {
        param([string]$osCategory)

        # Modern: Get-SmbShare/Access 사용
        if ($osCategory -ne "Legacy") {
            $shares = Get-SmbShare -ErrorAction SilentlyContinue
            if (-not $shares) { return $null }  # 판단 불가
            foreach ($s in $shares) {
                # 모든 공유 대상 (관리/기본/일반 가리지 않고 체크)
                $acc = Get-SmbShareAccess -Name $s.Name -ErrorAction SilentlyContinue
                if (-not $acc) { continue }
                if ($acc | Where-Object { $_.AccountName -ieq "Everyone" }) { return $true }
            }
            return $false
        }

        # Legacy: Win32_LogicalShareSecuritySetting DACL 조회
        try {
            $wmi = Get-WmiObject -Class Win32_LogicalShareSecuritySetting -ErrorAction Stop
            foreach ($ss in $wmi) {
                $sd = $ss.GetSecurityDescriptor()
                if ($sd -and $sd.Descriptor -and $sd.Descriptor.DACL) {
                    foreach ($ace in $sd.Descriptor.DACL) {
                        $trustee = $ace.Trustee
                        $name = $null
                        if ($trustee) {
                            if ($trustee.Name) { $name = $trustee.Name }
                            elseif ($trustee.SIDString -and $trustee.SIDString -eq 'S-1-1-0') { $name = 'Everyone' }
                        }
                        if ($name -and $name -ieq 'Everyone') { return $true }
                    }
                }
            }
            return $false
        } catch {
            Log-And-Record "[WARN] Legacy WMI 보안 설명자 조회 실패: $($_.Exception.Message)"
            return $null
        }
    }

    function Get-DriveSharesPresent {
        # 드라이브 기본 공유(C$, D$ ...) 존재 여부 반환 (null=판단불가)
        if ($osCategory -ne "Legacy") {
            $shares = Get-SmbShare -ErrorAction SilentlyContinue
            if (-not $shares) { return $null }
            $driveShares = $shares | Where-Object { $_.Name -match '^[A-Z]\$$' }
            return ($driveShares.Count -gt 0)
        } else {
            $text = Get-NetShareOutput -osCategory $osCategory
            if (-not $text) { return $null }
            return ($text -match "(?m)^\s*[A-Z]\$\s*$")
        }
    }

    # --------------------------- (A) Everyone 존재 여부 ---------------------------
    $hasEveryone = Test-AnyShareHasEveryone -osCategory $osCategory
    if ($hasEveryone -eq $true) { Log-And-Record "[FAIL] 공유 접근 권한에 Everyone 존재" }
    elseif ($hasEveryone -eq $false) { Log-And-Record "[OK] 모든 공유에서 Everyone 미존재" }
    else { Log-And-Record "[WARN] 공유 ACL에서 Everyone 존재 여부 판단 불가 → 검토" }

    # --------------------------- (B) 기본 드라이브 공유 존재 여부 -------------------
    $driveSharesPresent = Get-DriveSharesPresent
    if ($driveSharesPresent -eq $true) { Log-And-Record "[INFO] 기본 드라이브 공유(C$, D$ 등) 존재" }
    elseif ($driveSharesPresent -eq $false) { Log-And-Record "[INFO] 기본 드라이브 공유 없음" }
    else { Log-And-Record "[WARN] 기본 공유 존재 여부 판단 불가 → 검토" }

    # --------------------------- (C) AutoShareServer ------------------------------
    $autoShare = Get-AutoShareServerValue
    if ($autoShare -eq $null) {
        Log-And-Record "[WARN] 레지스트리 AutoShareServer 값을 읽지 못함(미설정일 수 있음)"
    } else {
        Log-And-Record "[INFO] AutoShareServer=$autoShare (요건: 0)"
    }

    # --------------------------- (D) 암호 보호 공유 -------------------------------
    $ppsOn = Get-PasswordProtectedSharingOn
    if ($ppsOn -eq $true) { Log-And-Record "[OK] 암호 보호 공유 = 설정(ON)" }
    elseif ($ppsOn -eq $false) { Log-And-Record "[FAIL] 암호 보호 공유 = 해제(OFF)" }
    else { Log-And-Record "[WARN] 암호 보호 공유 설정값 판단 불가 → 검토" }

    # --------------------------- (E) 판정 로직 (가이드 정합) -----------------------
    # 취약 우선 조건: Everyone 존재 OR 암호 보호 공유 OFF
    if ($hasEveryone -eq $true -or $ppsOn -eq $false) {
        $global:WResult['CHK_2-3'] = '취약'
    }
    else {
        # 양호 조건: (기본 공유 없음 OR Everyone 없음) AND AutoShareServer=0 AND 암호 보호 공유 ON
        $cond1 = (($driveSharesPresent -eq $false) -or ($hasEveryone -eq $false))
        $cond2 = ($autoShare -eq $null -or [int]$autoShare -eq 0)  # 미설정은 0로 간주
        $cond3 = ($ppsOn -eq $true)

        if ($cond1 -and $cond2 -and $cond3) {
            $global:WResult['CHK_2-3'] = '양호'
        }
        else {
            $global:WResult['CHK_2-3'] = '검토'
        }
    }

    Log-And-Record ("[SUMMARY] Everyone={0} / DriveSharesPresent={1} / AutoShareServer={2} / PasswordProtectedSharing={3}" -f $hasEveryone, $driveSharesPresent, ($autoShare -as [string]), ($ppsOn -as [string]))

    End-Check
    ShowResult 'CHK_2-3' $global:WResult['CHK_2-3']
}

# ---------- CHK_2-4: SAM(Security Account Manager) 파일 권한 설정 (가이드 정합) ----------
function CHK_2-4 {
    param([string]$osCategory)
    Start-Check "CHK_2-4" "SAM(Security Account Manager) 파일 권한 설정"

    $samPath = "$env:SystemRoot\System32\config\SAM"
    $result = "검토"

    try {
        if (-not (Test-Path $samPath)) {
            Log-And-Record "[WARN] SAM 파일 경로가 존재하지 않음: $samPath"
            $global:WResult["CHK_2-4"] = "검토"
            End-Check; ShowResult "CHK_2-4" $global:WResult["CHK_2-4"]; return
        }

        $acl = Get-Acl -Path $samPath -ErrorAction Stop

        # 허용되는 주체(정확한 이름) — 가이드는 그룹 'Administrators', 'SYSTEM'만 허용
        $allowed = @('Administrators','SYSTEM')

        # FullControl 비트 확인
        function Has-FullControl([System.Security.AccessControl.FileSystemRights]$r) {
            return (($r -band [System.Security.AccessControl.FileSystemRights]::FullControl) -ne 0)
        }

        # 관측된 상태
        $seenFull = @{ 'Administrators' = $false; 'SYSTEM' = $false }
        $violOthers = @()   # 허용 외 주체가 권한을 가진 경우
        $violMissing = @()  # Admins/SYSTEM이 FullControl이 아닌 경우 또는 누락

        foreach ($ace in $acl.Access) {
            if ($ace.AccessControlType -ne 'Allow') { continue }

            $id  = $ace.IdentityReference.Value
            $who = ($id -split '\\')[-1]  # 접두어 제거 (BUILTIN\, NT AUTHORITY\ 등)

            if ($allowed -contains $who) {
                if (Has-FullControl $ace.FileSystemRights) {
                    $seenFull[$who] = $true
                }
                else {
                    $violMissing += ('{0}: {1}' -f $who, $ace.FileSystemRights)
                }
            }
            else {
                # 가이드는 '다른 그룹에 권한이 있으면 취약' (권한 수준 불문)
                $violOthers  += ('{0}: {1}' -f $id,  $ace.FileSystemRights)
            }
        }

        # 필수 항목 누락(Admins/SYSTEM FullControl) 체크
        foreach ($k in $seenFull.Keys) {
            if (-not $seenFull[$k]) { $violMissing += "$k:FullControl 누락" }
        }

        if ($violOthers.Count -gt 0) {
            Log-And-Record "[FAIL] 허용 외 주체에 SAM 권한 존재: $($violOthers -join '; ')"
            $result = "취약"
        }
        elseif ($violMissing.Count -gt 0) {
            Log-And-Record "[FAIL] Administrators/SYSTEM의 FullControl 미충족: $($violMissing -join '; ')"
            $result = "취약"
        }
        else {
            Log-And-Record "[OK] SAM 권한이 Administrators, SYSTEM만이며 둘 다 FullControl"
            $result = "양호"
        }
    }
    catch {
        Log-And-Record "[ERROR] SAM ACL 조회 실패: $($_.Exception.Message)"
        $result = "검토"
    }

    $global:WResult["CHK_2-4"] = $result
    End-Check
    ShowResult "CHK_2-4" $result
}

# ---------- CHK_2-5: 파일 및 디렉토리 보호 (NTFS 여부 확인) ----------
function CHK_2-5 {
    param([string]$osCategory)
    Start-Check "CHK_2-5" "파일 및 디렉토리 보호"

    # Windows 2019 가이드: 해당 OS는 체크리스트에 포함하지 않음 → N/A 처리
    Log-And-Record "[INFO] 이 OS 버전에서는 NFS 항목이 평가 대상 아님(N/A)."
    $global:WResult["CHK_2-5"] = "N/A"
    End-Check
    ShowResult "CHK_2-5" $global:WResult["CHK_2-5"]
}

# ---------- CHK_3-1: 불필요한 서비스 제거 ----------
function CHK_3-1 {
    param([string]$osCategory)
    Start-Check "CHK_3-1" "불필요한 서비스 제거"

    # 조직 합의된(=불필요로 판단된) 블랙리스트
    $unwanted = @("RemoteRegistry", "Telnet", "Fax", "SNMP", "Messenger")

    $issue = $false

    foreach ($svcName in $unwanted) {
        try {
            # 서비스 객체
            $svc     = Get-Service -Name $svcName -ErrorAction Stop
            $svcInfo = Get-CimInstance -ClassName Win32_Service -Filter "Name='$svcName'" -ErrorAction Stop

            $status   = $svc.Status            # Running / Stopped
            $startup  = $svcInfo.StartMode     # Auto / Manual / Disabled

            # ★가이드 정합: 불필요 서비스는 반드시 Disabled여야 함
            if ($startup -ne 'Disabled') {
                Log-And-Record "[FAIL] 불필요 서비스 '$svcName' 시작유형=$startup, 상태=$status → Disabled 아님 → 취약"
                $issue = $true
            } else {
                Log-And-Record "[OK] '$svcName' Disabled (상태=$status) → 양호"
            }
        }
        catch {
            # 서비스가 아예 없거나 쿼리 불가(미설치 등) → 불필요 서비스 미사용으로 간주
            Log-And-Record "[INFO] '$svcName' 서비스 없음/미설치 → 양호"
        }
    }

    $global:WResult["CHK_3-1"] = if ($issue) { "취약" } else { "양호" }

    End-Check
    ShowResult "CHK_3-1" $global:WResult["CHK_3-1"]
}

# ---------- CHK_3-2: 터미널 서비스 암호화 수준 설정 ----------
function CHK_3-2 {
    param([string]$osCategory)
    Start-Check "CHK_3-2" "터미널 서비스 암호화 수준 설정"

    try {
        $termSvc = Get-Service -Name "TermService" -ErrorAction SilentlyContinue
    }
    catch {
        Log-And-Record "[WARN] TermService 조회 오류: $($_.Exception.Message) → 검토"
        $global:WResult["CHK_3-2"] = "검토"
        End-Check
    ShowResult "CHK_3-2" $global:WResult["CHK_3-2"]
        return
    }

    if (-not $termSvc) {
        Log-And-Record "[INFO] 터미널 서비스 미설치 → N/A"
        $global:WResult["CHK_3-2"] = "N/A"
        End-Check
    ShowResult "CHK_3-2" $global:WResult["CHK_3-2"]
        return
    }

    if ($termSvc.Status -ne "Running") {
        Log-And-Record "[INFO] 터미널 서비스 비실행 → 양호"
        $global:WResult["CHK_3-2"] = "양호"
        End-Check
    ShowResult "CHK_3-2" $global:WResult["CHK_3-2"]
        return
    }

    $regPath = "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
    $prop = "MinEncryptionLevel"

    try {
        $val = (Get-ItemProperty -Path $regPath -Name $prop -ErrorAction Stop).$prop
        Log-And-Record "[INFO] MinEncryptionLevel: $val (권고: 2 이상 - 중간 수준 이상)"
        if ([int]$val -ge 2) {
            $global:WResult["CHK_3-2"] = "양호"
        }
        else {
            $global:WResult["CHK_3-2"] = "취약"
        }
    }
    catch {
        Log-And-Record "[WARN] MinEncryptionLevel 조회 오류: $($_.Exception.Message) → 검토"
        $global:WResult["CHK_3-2"] = "검토"
    }

    End-Check
    ShowResult "CHK_3-2" $global:WResult["CHK_3-2"]
}

# ---------- CHK_3-3: NetBIOS 바인딩 서비스 보안 설정 ----------
function CHK_3-3 {
    param([string]$osCategory)
    Start-Check "CHK_3-3" "NetBIOS 바인딩 서비스 구동 점검" 
    try {
        if ($osCategory -eq "Legacy") {
            $nics = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True"
        }
        else {
            $nics = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True"
        }
        $allGood = $true
        foreach ($nic in $nics) {
            if ($nic.TcpipNetbiosOptions -ne 2) { $allGood = $false }
        }
        if ($allGood) {
            Log-And-Record "[INFO] 모든 NIC에서 NetBIOS over TCP/IP 비활성화 → 양호"
            $global:WResult["CHK_3-3"] = "양호"
        }
        else {
            Log-And-Record "[INFO] 하나 이상의 NIC에서 NetBIOS over TCP/IP 활성화 → 취약"
            $global:WResult["CHK_3-3"] = "취약"
        }
    }
    catch {
        Log-And-Record "[WARN] NetBIOS 검사 오류: $($_.Exception.Message) → 검토"
        $global:WResult["CHK_3-3"] = "검토"
    }
    End-Check
    ShowResult "CHK_3-3" $global:WResult["CHK_3-3"]
}

# ---------- CHK_3-4: 터미널 서비스 Time Out 설정 ----------
function CHK_3-4 {
    param([string]$osCategory)
    Start-Check "CHK_3-4" "터미널 서비스 Time Out 설정"

    try {
        $termSvc = Get-Service -Name "TermService" -ErrorAction SilentlyContinue
    } catch {
        Log-And-Record "[WARN] TermService 조회 오류: $($_.Exception.Message) → 검토"
        $global:WResult["CHK_3-4"] = "검토"
        End-Check; ShowResult "CHK_3-4" $global:WResult["CHK_3-4"]; return
    }

    if (-not $termSvc) {
        Log-And-Record "[INFO] 터미널 서비스 미설치 → N/A"
        $global:WResult["CHK_3-4"] = "N/A"
        End-Check; ShowResult "CHK_3-4" $global:WResult["CHK_3-4"]; return
    }

    if ($termSvc.Status -ne "Running") {
        Log-And-Record "[INFO] 터미널 서비스 비실행 → 양호"
        $global:WResult["CHK_3-4"] = "양호"
        End-Check; ShowResult "CHK_3-4" $global:WResult["CHK_3-4"]; return
    }

    # ---------------------------
    # MaxIdleTime 조회 (정책 키 우선 → RDP-Tcp 보조)
    # ---------------------------
    $polHKLM = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    $polHKCU = 'HKCU:\Software\Policies\Microsoft\Windows NT\Terminal Services'
    $rdpTcp  = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'

    function Get-IdleMs {
        param([nullable[int64]]$v)
        if ($null -eq $v) { return $null }
        # 보통 ms이지만 드물게 '분'으로 저장된 환경 방어
        if ($v -lt 1000) { return ($v * 60000) } else { return $v }
    }

    # HKCU 드라이브가 없을 수 있어 방어적으로 생성
    if (-not (Get-PSDrive HKCU -ErrorAction SilentlyContinue)) {
        try { New-PSDrive -Name HKCU -PSProvider Registry -Root HKEY_CURRENT_USER | Out-Null } catch {}
    }

    $valMs = $null
    try {
        if (Test-Path $polHKLM) {
            $raw = (Get-ItemProperty -Path $polHKLM -Name 'MaxIdleTime' -ErrorAction SilentlyContinue).MaxIdleTime
            $valMs = Get-IdleMs $raw
            if ($valMs -ne $null) { Log-And-Record "[INFO] 정책(HKLM) MaxIdleTime(ms)=$valMs" }
        }
        if ($null -eq $valMs -and (Test-Path $polHKCU)) {
            $raw = (Get-ItemProperty -Path $polHKCU -Name 'MaxIdleTime' -ErrorAction SilentlyContinue).MaxIdleTime
            $valMs = Get-IdleMs $raw
            if ($valMs -ne $null) { Log-And-Record "[INFO] 정책(HKCU) MaxIdleTime(ms)=$valMs" }
        }
        if ($null -eq $valMs -and (Test-Path $rdpTcp)) {
            $raw = (Get-ItemProperty -Path $rdpTcp -Name 'MaxIdleTime' -ErrorAction SilentlyContinue).MaxIdleTime
            $valMs = Get-IdleMs $raw
            if ($valMs -ne $null) { Log-And-Record "[INFO] RDP-Tcp MaxIdleTime(ms)=$valMs" }
        }
    } catch {
        Log-And-Record "[WARN] MaxIdleTime 조회 오류: $($_.Exception.Message)"
    }

    if ($null -ne $valMs) {
        $valMin = [math]::Round($valMs / 60000.0, 2)
        Log-And-Record "[INFO] 최종 적용값: ~$valMin 분 (가이드 ≤5분)"
        if ($valMs -eq 0) {
            Log-And-Record "[FAIL] 무제한(0) → 취약"
            $global:WResult['CHK_3-4'] = '취약'
        }
        elseif ($valMs -le 300000) {
            $global:WResult['CHK_3-4'] = '양호'     # 5분 이하
        }
        else {
            $global:WResult['CHK_3-4'] = '취약'     # 5분 초과
        }
    } else {
        Log-And-Record "[WARN] 값 미발견(서비스 실행 중) → 보수적으로 취약"
        $global:WResult['CHK_3-4'] = '취약'
    }

    End-Check
    ShowResult "CHK_3-4" $global:WResult["CHK_3-4"]
}

# ---------- CHK_4-1: Telnet 서비스 보안 설정 ----------
function CHK_4-1 {
    param([string]$osCategory)
    Start-Check "CHK_4-1" "Telnet 서비스 보안 설정"

    # Windows 2019 가이드: 해당 OS는 체크리스트에 포함하지 않음 → N/A 처리
    Log-And-Record "[INFO] 이 OS 버전에서는 Telnet 항목이 평가 대상 아님(N/A)."
    $global:WResult["CHK_4-1"] = "N/A"
    End-Check
    ShowResult "CHK_4-1" $global:WResult["CHK_4-1"]
}

# ---------- CHK_4-2: DNS 보안 설정 (W-29 + W-63) ----------
# 판정 규칙
#  - 하나라도 '취약' → 최종 '취약'
#  - 둘 다 '양호'    → 최종 '양호'
#  - 그 외           → 최종 '검토'
# ---------- CHK_4-2: DNS 보안 설정 (W-29 + W-63) ----------
function CHK_4-2 {
    param([string]$osCategory)

    Start-Check "CHK_4-2" "DNS Zone Transfer & 동적 업데이트 [통합]"

    $w29 = '검토'   # Zone Transfer
    $w63 = '검토'   # Dynamic Update

    # 0) DNS 서비스 상태
    $dnsRunning = $false
    try {
        $svc = Get-Service -Name 'DNS' -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq 'Running') { $dnsRunning = $true }
    } catch {
        Log-And-Record "[WARN] DNS 서비스 조회 오류: $($_.Exception.Message)"
    }
    Log-And-Record "[INFO] DNS 서비스 실행 여부: $dnsRunning"

    if (-not $dnsRunning) {
        Log-And-Record "[INFO] DNS 미실행 → 두 항목 모두 양호로 간주"
        $w29 = '양호'
        $w63 = '양호'
    }
    else {
        # (A) W-29: Zone Transfer 제한 (SecureSecondaries = 2) + 허용 서버 목록 존재 확인
        try {
            if (Get-Command Get-DnsServerPrimaryZone -ErrorAction SilentlyContinue) {
                $pzones = Get-DnsServerPrimaryZone -ErrorAction Stop
                if ($pzones) {
                    $bad = $false
                    foreach ($z in $pzones) {
                        $ss = $z.SecureSecondaries
                        $okSS = $false
                        if ($ss -is [int]) { if ($ss -eq 2) { $okSS = $true } }
                        else { if ($ss -match '(?i)(Secure|Specific|TransferToSecureServers)') { $okSS = $true } }

                        # 허용 서버 목록 존재 확인(환경별 속성 이름 방어적 확인)
                        $allowList = @()
                        foreach ($propName in 'SecondaryServers','NotifyServers','ZoneTransferServers','AllowedTransferServers') {
                            if ($z.PSObject.Properties.Name -contains $propName) {
                                $val = $z.$propName
                                if ($val) { $allowList += $val }
                            }
                        }

                        $okList = ($allowList.Count -gt 0)

                        Log-And-Record "[INFO] Zone=$($z.ZoneName) SecureSecondaries=$ss / AllowListCnt=$($allowList.Count)"

                        if (-not ($okSS -and $okList)) { $bad = $true }
                    }
                    if ($bad) { $w29 = '취약' } else { $w29 = '양호' }
                } else {
                    Log-And-Record "[WARN] 1차: Primary Zone 없음 → 레지스트리 보조 점검"
                    throw "NoPrimaryZone"
                }
            } else { throw "NoDnsCmdlets" }
        }
        catch {
            # [REG] 보조 점검: SecureSecondaries==2 + 허용 서버 값 존재(키/값의 존재로 보수판정)
            try {
                $zonesRoot = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DNS Server\Zones'
                $zoneKeys  = Get-ChildItem $zonesRoot -ErrorAction Stop
                if ($zoneKeys) {
                    $bad = $false
                    foreach ($k in $zoneKeys) {
                        $valSS = (Get-ItemProperty -Path $k.PSPath -Name 'SecureSecondaries' -ErrorAction SilentlyContinue).SecureSecondaries
                        # 허용 서버 힌트가 되는 값/하위키 존재 유무(환경별 키명이 다를 수 있어 포괄 확인)
                        $hasList = $false
                        foreach ($nm in 'AllowTransfer','NameServers','ZoneTransfers','SecondaryServers','NotifyServers') {
                            if (Get-ItemProperty -Path $k.PSPath -Name $nm -ErrorAction SilentlyContinue) { $hasList = $true; break }
                            if (Test-Path (Join-Path $k.PSPath $nm)) { $hasList = $true; break }
                        }
                        Log-And-Record "[INFO] [REG] Zone=$($k.PSChildName) SecureSecondaries=$valSS / AllowListHint=$hasList"
                        if ($valSS -ne 2 -or -not $hasList) { $bad = $true }
                    }
                    if ($bad) { $w29 = '취약' } else { $w29 = '양호' }
                } else {
                    Log-And-Record "[WARN] [REG] Zone 키 없음 → 검토"
                    $w29 = '검토'
                }
            } catch {
                Log-And-Record "[WARN] Zone Transfer 보조 점검 실패: $($_.Exception.Message) → 검토"
                $w29 = '검토'
            }
        }

        # (B) W-63: 동적 업데이트 금지 (DynamicUpdate=0)  ← 참고용(최종 판정에는 미반영)
        try {
            if (Get-Command Get-DnsServerZone -ErrorAction SilentlyContinue) {
                $zones = Get-DnsServerZone -ErrorAction Stop
                if ($zones) {
                    $hasDyn = $false  # 0(None)=양호, 1/2 허용=취약(참고)
                    foreach ($z in $zones) {
                        $du = $z.DynamicUpdate
                        Log-And-Record "[INFO] Zone=$($z.ZoneName) DynamicUpdate=$du"
                        if ($du -eq 1 -or $du -eq 2) { $hasDyn = $true }
                    }
                    if ($hasDyn) { $w63 = '취약' } else { $w63 = '양호' }
                } else {
                    Log-And-Record "[WARN] 1차: Zone 없음 → dnscmd 보조 점검"
                    throw "NoZone"
                }
            }
            else {
                throw "NoDnsCmdlets"
            }
        }
        catch {
            try {
                $dnscmd = "$env:windir\System32\dnscmd.exe"
                if (Test-Path $dnscmd) {
                    $res = & $dnscmd /EnumZones 2>&1 | Out-String
                    if ($res -match '(?i)(Allow\s*Update|dynamic\s*update)') {
                        Log-And-Record "[INFO] dnscmd: 동적 업데이트 관련 문자열 발견"
                        $w63 = '취약'
                    } else {
                        Log-And-Record "[INFO] dnscmd: 동적 업데이트 관련 설정 미발견"
                        $w63 = '양호'
                    }
                } else {
                    Log-And-Record "[WARN] dnscmd.exe 미존재 → 검토"
                    $w63 = '검토'
                }
            }
            catch {
                Log-And-Record "[WARN] 동적 업데이트 보조 점검 실패: $($_.Exception.Message) → 검토"
                $w63 = '검토'
            }
        }
    }

    # (C) 최종 통합 판정 — ★W-29만 반영★
    Log-And-Record "[SUMMARY] W-29(ZoneTransfer)=$w29 / W-63(DynamicUpdate)=$w63"

    if ($w29 -eq '취약') {
        $global:WResult['CHK_4-2'] = '취약'
    }
    elseif ($w29 -eq '양호') {
        $global:WResult['CHK_4-2'] = '양호'
    }
    else {
        $global:WResult['CHK_4-2'] = '검토'
    }

    End-Check
    ShowResult 'CHK_4-2' $global:WResult['CHK_4-2']
}

# ---------- CHK_4-3: SNMP(Simple Network Management Protocol) 서비스 보안 설정 (W-60 + W-61 + W-62) ----------
# 판정 규칙
#  - 하나라도 '취약' → 최종 '취약'
#  - 모두   '양호'   → 최종 '양호'
#  - 그 외(확인 불가 등) → 최종 '검토'
function CHK_4-3 {
    param([string]$osCategory)

    Start-Check "CHK_4-3" "SNMP(Simple Network Management Protocol) 서비스 보안 설정"

    $w60 = '검토'   # SNMP 서비스 구동 여부
    $w61 = '검토'   # 커뮤니티 'public'/'private' 존재 여부
    $w62 = '검토'   # PermittedManagers 설정 여부

    # (0) SNMP 서비스 상태
    $snmpSvc = Get-Service -Name "SNMP" -ErrorAction SilentlyContinue
    if (-not $snmpSvc) {
        Log-And-Record "[INFO] SNMP 미설치 → W-60=양호, W-61=양호, W-62=양호"
        $w60 = '양호'; $w61 = '양호'; $w62 = '양호'
    } elseif ($snmpSvc.Status -eq "Running") {
        Log-And-Record "[INFO] SNMP 실행 중 → 세부 보안설정 점검"
        $w60 = '양호'
    } else {
        Log-And-Record "[INFO] SNMP 설치(중지 상태) → 사용 안 함으로 간주"
        $w60 = '양호'; $w61 = '양호'; $w62 = '양호'
    }

    # 실행 중일 때만 세부 점검
    if ($snmpSvc -and $snmpSvc.Status -eq "Running") {

        # (1) W-61: 커뮤니티 'public' / 'private' 금지
        try {
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities"
            if (Test-Path $regPath) {
                $props = (Get-ItemProperty $regPath).PSObject.Properties |
                         Where-Object { $_.Name -notin 'PSPath','PSParentPath','PSChildName','PSDrive','PSProvider' }
                $foundBad = $false
                foreach ($p in $props) {
                    if ($p.Name -match '^(?i:public|private)$') { $foundBad = $true; break }
                }
                if ($foundBad) { $w61 = '취약'; Log-And-Record "[FAIL] 커뮤니티에 'public/private' 발견" }
                else           { $w61 = '양호'; Log-And-Record "[OK] 위험 커뮤니티 미발견" }
            } else {
                $w61 = '양호'; Log-And-Record "[OK] ValidCommunities 키 없음(커뮤니티 미설정)"
            }
        } catch {
            $w61 = '검토'; Log-And-Record "[WARN] W-61 점검 오류: $($_.Exception.Message)"
        }

        # (2) W-62: PermittedManagers 설정 권장(최소 1개)
        try {
            $pmPath = "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers"
            $managersOk = $false
            if (Test-Path $pmPath) {
                $cnt = (Get-ChildItem $pmPath -ErrorAction SilentlyContinue | Measure-Object).Count
                $managersOk = ($cnt -ge 1)
            }
            if ($managersOk) { $w62 = '양호'; Log-And-Record "[OK] PermittedManagers 설정 수락: ≥1" }
            else             { $w62 = '취약'; Log-And-Record "[FAIL] PermittedManagers 미설정 또는 비어 있음" }
        } catch {
            $w62 = '검토'; Log-And-Record "[WARN] W-62 점검 오류: $($_.Exception.Message)"
        }
    }

    # (3) 최종 판정
    Log-And-Record "[SUMMARY] W-60=$w60 / W-61=$w61 / W-62=$w62"
    if ($w60 -eq '취약' -or $w61 -eq '취약' -or $w62 -eq '취약') { $global:WResult['CHK_4-3'] = '취약' }
    elseif ($w60 -eq '양호' -and $w61 -eq '양호' -and $w62 -eq '양호') { $global:WResult['CHK_4-3'] = '양호' }
    else { $global:WResult['CHK_4-3'] = '검토' }

    End-Check
    ShowResult 'CHK_4-3' $global:WResult['CHK_4-3']
}

# ---------- CHK_5-1: 원격 로그파일 접근 진단 ----------
function CHK_5-1 {
    param([string]$osCategory)
    Start-Check "CHK_5-1" "원격 로그파일 접근 진단"

    $logDir = "$env:SystemRoot\System32\config"
    try {
        if (-not (Test-Path $logDir)) {
            Log-And-Record "[WARN] 로그 디렉토리 경로 없음: $logDir → 검토"
            $global:WResult["CHK_5-1"] = "검토"
            End-Check
            ShowResult "CHK_5-1" $global:WResult["CHK_5-1"]
            return
        }

        $acl = Get-Acl $logDir

        # 가이드 정합: '존재 여부'만 판단 (권한 수준 불문)
        # 로켈에 따라 이름이 다를 수 있음 → 포괄 매칭
        $hasEveryone = $false
        $hasUsers    = $false

        foreach ($ace in $acl.Access) {
            $id = $ace.IdentityReference.Value

            # Everyone (영문/국문/도메인형식 모두 포괄)
            if ($id -match '^(?:.*\\)?Everyone$' -or $id -match '모두') { $hasEveryone = $true }

            # Users (BUILTIN\Users 포함)
            if ($id -match '^(?:BUILTIN\\)?Users$' -or $id -match '사용자') { $hasUsers = $true }
        }

        if ($hasEveryone -or $hasUsers) {
            Log-And-Record "[FAIL] ACL에 Users/Everyone 존재 → 취약 (권한 수준과 무관)"
            $global:WResult["CHK_5-1"] = "취약"
        } else {
            Log-And-Record "[OK] ACL에 Users/Everyone 없음 → 양호"
            $global:WResult["CHK_5-1"] = "양호"
        }
    }
    catch {
        Log-And-Record "[WARN] ACL 조회 오류: $($_.Exception.Message) → 검토"
        $global:WResult["CHK_5-1"] = "검토"
    }

    End-Check
    ShowResult "CHK_5-1" $global:WResult["CHK_5-1"]
}

# ---------- CHK_5-2: 화면보호기 설정 ----------
function CHK_5-2 {
    param([string]$osCategory)
    Start-Check "CHK_5-2" "화면보호기 설정"

    # 가이드: 사용(1) + 암호(1) + 대기 300초(정확히 5분)
    $REQ_ACTIVE = 1
    $REQ_SECURE = 1
    $REQ_TIMEOUT = 300

    # 1) GPO(컴퓨터 정책) 먼저
    $policyPathHKLM = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop"
    $gpoActive = $null; $gpoSecure = $null; $gpoTimeout = $null
    if (Test-Path $policyPathHKLM) {
        try {
            $gpo = Get-ItemProperty -Path $policyPathHKLM -ErrorAction Stop
            if ($gpo.PSObject.Properties.Name -contains "ScreenSaveActive")    { $gpoActive  = [int]$gpo.ScreenSaveActive }
            if ($gpo.PSObject.Properties.Name -contains "ScreenSaverIsSecure") { $gpoSecure  = [int]$gpo.ScreenSaverIsSecure }
            if ($gpo.PSObject.Properties.Name -contains "ScreenSaveTimeOut")   { $gpoTimeout = [int]$gpo.ScreenSaveTimeOut }
        } catch { Log-And-Record "[WARN] GPO(컴퓨터) 읽기 오류: $($_.Exception.Message)" }

        if (($gpoActive -eq $REQ_ACTIVE) -and ($gpoSecure -eq $REQ_SECURE) -and ($gpoTimeout -eq $REQ_TIMEOUT)) {
            Log-And-Record "[INFO] GPO(컴퓨터)로 사용/암호/300초 → 양호"
            $global:WResult["CHK_5-2"] = "양호"
            End-Check; ShowResult "CHK_5-2" $global:WResult["CHK_5-2"]; return
        } elseif ($gpoActive -or $gpoSecure -or $gpoTimeout) {
            Log-And-Record "[FAIL] GPO(컴퓨터) 일부 불일치 (요건: Active=1, Secure=1, Timeout=300) → 취약"
            $global:WResult["CHK_5-2"] = "취약"
            End-Check; ShowResult "CHK_5-2" $global:WResult["CHK_5-2"]; return
        }
    }

    # 2) HKU가 비어 있으면: 사용자 하이브 직접 로드해서 점검 (ProfileList 기반)
    function Test-UserDesktopOK($rootPath) {
        # $rootPath 예: HKU:\_AUDIT_S-1-5-21-...\Control Panel\Desktop
        try {
            if (-not (Test-Path $rootPath)) { return $false }
            $p = Get-ItemProperty -Path $rootPath -ErrorAction Stop
            $active  = 0; $secure = 0; $timeout = -1
            if ($p.PSObject.Properties.Name -contains "ScreenSaveActive")    { $active  = [int]$p.ScreenSaveActive }
            if ($p.PSObject.Properties.Name -contains "ScreenSaverIsSecure") { $secure  = [int]$p.ScreenSaverIsSecure }
            if ($p.PSObject.Properties.Name -contains "ScreenSaveTimeOut")   { $timeout = [int]$p.ScreenSaveTimeOut }
            return (($active -eq $REQ_ACTIVE) -and ($secure -eq $REQ_SECURE) -and ($timeout -eq $REQ_TIMEOUT))
        } catch { return $false }
    }

    function Test-HKCUDesktopOK() {
        try {
            $p = Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -ErrorAction Stop
            $a=[int]$p.ScreenSaveActive; $s=[int]$p.ScreenSaverIsSecure; $t=[int]$p.ScreenSaveTimeOut
            return (($a -eq $REQ_ACTIVE) -and ($s -eq $REQ_SECURE) -and ($t -eq $REQ_TIMEOUT))
        } catch { return $false }
    }

    # HKU에 이미 로드된 SID들
    if (-not (Get-PSDrive -Name HKU -ErrorAction SilentlyContinue)) {
        New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
    }
    $loadedSIDs = @(Get-ChildItem HKU:\ | Where-Object { $_.Name -match '^S-1-5' }) |
                   Where-Object { $_.Name -notmatch '^(S-1-5-18|S-1-5-19|S-1-5-20)$' }

    $compliant = 0; $noncompliant = 0

    if ($loadedSIDs.Count -gt 0) {
        foreach ($sid in $loadedSIDs) {
            $deskPath = Join-Path $sid.PSPath 'Control Panel\Desktop'
            if (Test-UserDesktopOK $deskPath) { $compliant++ } else { $noncompliant++ }
        }
    } else {
        Log-And-Record "[WARN] HKU 내 사용자 SID 없음 → 프로필 하이브 로드 방식으로 점검"

        # 프로필 목록에서 SID/경로 가져오기
        $profRoot = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
        $profKeys = Get-ChildItem $profRoot -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^S-1-5' }
        foreach ($k in $profKeys) {
            try {
                $sid = $k.PSChildName
                $img = (Get-ItemProperty -Path $k.PSPath -Name 'ProfileImagePath' -ErrorAction Stop).ProfileImagePath
                if (-not $img) { continue }
                $ntuser = Join-Path $img 'NTUSER.DAT'
                if (-not (Test-Path $ntuser)) { continue }

                $mountName = "_AUDIT_$($sid)"
                $mountKey  = "HKU\$mountName"
                # 로드
                $loadRes = & reg.exe load $mountKey $ntuser 2>&1
                if ($LASTEXITCODE -ne 0) {
                    Log-And-Record "[WARN] 하이브 로드 실패: $sid ($img) → 건너뜀"
                    continue
                }

                # 점검
                $deskPath = "HKU:\$mountName\Control Panel\Desktop"
                if (Test-UserDesktopOK $deskPath) { $compliant++ } else { $noncompliant++ }

                # 언로드
                & reg.exe unload $mountKey | Out-Null
            } catch {
                Log-And-Record "[WARN] 프로필 점검 오류: $($_.Exception.Message)"
            }
        }

        # 그래도 아무도 못 봤다면 마지막으로 HKCU라도 확인
        if ($compliant -eq 0 -and $noncompliant -eq 0) {
            if (Test-HKCUDesktopOK) { $compliant++ } else { $noncompliant++ }
        }
    }

    # 3) 최종 판정
    if ($compliant -eq 0 -and $noncompliant -gt 0) {
        $global:WResult["CHK_5-2"] = "취약"
    } elseif ($noncompliant -eq 0 -and $compliant -gt 0) {
        $global:WResult["CHK_5-2"] = "양호"
    } else {
        Log-And-Record "[INFO] 일부만 충족: 양호=$compliant, 미양호=$noncompliant → 검토"
        $global:WResult["CHK_5-2"] = "검토"
    }

    End-Check
    ShowResult "CHK_5-2" $global:WResult["CHK_5-2"]
}

# ---------- CHK_5-3: 이벤트 뷰어 설정 ----------
function CHK_5-3 {
    param([string]$osCategory)
    Start-Check "CHK_5-3" "이벤트 뷰어 설정"

    # 가이드 대상 로그 3종
    $targets = @("Application","Security","System")

    # wevtutil 출력 파싱 함수
    function Get-LogStatus($logName) {
        try {
            $out = wevtutil gl $logName 2>&1
            $maxBytes = $null; $ret = $null

            foreach ($line in $out) {
                if ($line -match "maxSize:\s*(\d+)")      { $maxBytes = [int]$matches[1] }
                elseif ($line -match "retention:\s*(\w+)") { $ret = $matches[1].Trim().ToLower() }
            }

            if ($null -eq $maxBytes -or [string]::IsNullOrWhiteSpace($ret)) {
                return @{ ok=$false; reason="파싱실패"; kb=0; retention=$ret }
            }

            $kb = [math]::Round($maxBytes / 1024)
            # 가이드: 최대 크기 >= 10240KB AND '필요 시 덮어쓰기' (= retention:false)
            $ok = ($kb -ge 10240) -and ($ret -eq "false")
            return @{ ok=$ok; reason="kb=$kb, retention=$ret"; kb=$kb; retention=$ret }
        }
        catch {
            return @{ ok=$false; reason="조회오류:$($_.Exception.Message)"; kb=0; retention=$null }
        }
    }

    $allOk = $true
    $anyError = $false
    foreach ($name in $targets) {
        $st = Get-LogStatus $name
        Log-And-Record ('[INFO] {0}: {1}' -f $name, $st.reason)
        if ($st.reason -like "파싱실패*" -or $st.reason -like "조회오류*") { $anyError = $true }
        if (-not $st.ok) { $allOk = $false }
    }

    if ($anyError) {
        $global:WResult["CHK_5-3"] = "검토"
    }
    elseif ($allOk) {
        $global:WResult["CHK_5-3"] = "양호"
    }
    else {
        $global:WResult["CHK_5-3"] = "취약"
    }

    End-Check
    ShowResult "CHK_5-3" $global:WResult["CHK_5-3"]
}

# ---------- CHK_5-4: 로그인 시 경고 메시지 표시 설정 (legalnoticecaption/text) ----------
function CHK_5-4 {
    param([string]$osCategory)
    Start-Check "CHK_5-4" "로그인 시 경고 메시지 표시 설정 (legalnoticecaption/text)"

    # 후보 경로 (일반/정책, 32/64 뷰 포함)
    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\System', # 방어적
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' # 일부 환경에서 사용
    )

    function Get-NoticeFrom-Path($p) {
        try {
            if (Test-Path $p) {
                $o = Get-ItemProperty -Path $p -ErrorAction Stop
                $cap  = $null; $txt = $null
                if ($o.PSObject.Properties.Name -contains 'legalnoticecaption') { $cap = [string]$o.legalnoticecaption }
                if ($o.PSObject.Properties.Name -contains 'legalnoticetext')    { $txt = [string]$o.legalnoticetext }
                # 공백/개행만 있는 값은 미설정으로 간주
                if ($cap) { $cap = $cap.Trim() }
                if ($txt) { $txt = $txt.Trim() }
                return [pscustomobject]@{ Path=$p; Caption=$cap; Text=$txt }
            }
        } catch { }
        return $null
    }

    # 우선 레지스트리에서 찾기
    $found = $null
    foreach ($p in $paths) {
        $r = Get-NoticeFrom-Path $p
        if ($r -and ($r.Caption -and $r.Caption -ne '') -and ($r.Text -and $r.Text -ne '')) {
            $found = $r; break
        }
    }

    # 보조: secedit /export 로 실제 적용값 파싱 (정책 적용은 여기에도 반영됨)
    if (-not $found) {
        try {
            $tmp = Join-Path $env:TEMP "secpol_chk_5_4.inf"
            secedit /export /cfg $tmp /quiet | Out-Null
            $cap = (Select-String -Path $tmp -Pattern 'legalnoticecaption\s*=' -SimpleMatch -ErrorAction SilentlyContinue |
                    ForEach-Object { ($_ -split '=',2)[1].Trim() }) | Select-Object -First 1
            $txt = (Select-String -Path $tmp -Pattern 'legalnoticetext\s*=' -SimpleMatch -ErrorAction SilentlyContinue |
                    ForEach-Object { ($_ -split '=',2)[1].Trim() }) | Select-Object -First 1
            if (Test-Path $tmp) { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }

            if ($cap) { $cap = $cap.Trim() }
            if ($txt) { $txt = $txt.Trim() }

            if ($cap -and $cap -ne '' -and $txt -and $txt -ne '') {
                $found = [pscustomobject]@{ Path='[secedit export]'; Caption=$cap; Text=$txt }
            }
        } catch { }
    }

    if ($found) {
        Log-And-Record ("[INFO] 발견 경로: {0}" -f $found.Path)
        Log-And-Record ("[INFO] legalnoticecaption: '{0}'" -f $found.Caption)
        Log-And-Record ("[INFO] legalnoticetext: '{0}'" -f $found.Text)
        $global:WResult["CHK_5-4"] = "양호"
    } else {
        # 마지막으로 실제 기본 경로에서 읽은 원시 값도 로깅
        try {
            $p = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            $o = Get-ItemProperty -Path $p -ErrorAction SilentlyContinue
            if ($o) {
                Log-And-Record ("[INFO] raw legalnoticecaption: '{0}'" -f ([string]$o.legalnoticecaption))
                Log-And-Record ("[INFO] raw legalnoticetext: '{0}'" -f ([string]$o.legalnoticetext))
            }
        } catch { }
        $global:WResult["CHK_5-4"] = "취약"
    }

    End-Check
    ShowResult "CHK_5-4" $global:WResult["CHK_5-4"]
}

# ---------- CHK_5-5: 마지막 로그온 사용자 계정 숨김 ----------
function CHK_5-5 {
    param([string]$osCategory)
    Start-Check "CHK_5-5" "마지막 로그온 사용자 계정 숨김"
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $prop = "DontDisplayLastUserName"
    try {
        if ($osCategory -eq "Legacy") {
            $res = cmd /c "reg query `"${regPath}`" /v ${prop}" 2>&1
            if ($res -match "${prop}\s+REG_DWORD\s+0x([0-9a-fA-F]+)") {
                $val = [convert]::ToInt32($matches[1],16)
            }
            else {
                throw "값 미발견"
            }
        }
        else {
            $val = (Get-ItemProperty -Path $regPath -Name $prop -ErrorAction Stop).${prop}
        }
        Log-And-Record "[INFO] DontDisplayLastUserName: $val (권고: 1)"
        if ([int]$val -eq 1) {
            $global:WResult["CHK_5-5"] = "양호"
        }
        else {
            $global:WResult["CHK_5-5"] = "취약"
        }
    }
    catch {
        Log-And-Record "[WARN] DontDisplayLastUserName 조회 오류: $($_.Exception.Message) → 검토"
        $global:WResult["CHK_5-5"] = "검토"
    }
    End-Check
    ShowResult "CHK_5-5" $global:WResult["CHK_5-5"]
}

# ---------- CHK_5-6: 로그온 하지 않은 사용자 시스템 종료 방지 ----------
function CHK_5-6 {
    param([string]$osCategory)
    Start-Check "CHK_5-6" "로그온 하지 않은 사용자 시스템 종료 방지"

    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $prop = "shutdownwithoutlogon"

    try {
        # 레지스트리에서 shutdownwithoutlogon 값 조회
        $val = (Get-ItemProperty -Path $regPath -Name $prop -ErrorAction Stop).$prop
        Log-And-Record "[INFO] shutdownwithoutlogon 값: $val (0 = 사용 안 함 = 양호, 1 = 사용 = 취약)"

        if ($val -eq 0) {
            Log-And-Record "[INFO] 로그온 없이 시스템 종료 허용되지 않음 → 양호"
            $global:WResult["CHK_5-6"] = "양호"
        }
        elseif ($val -eq 1) {
            Log-And-Record "[WARN] 로그온 없이 시스템 종료 허용됨 → 취약"
            $global:WResult["CHK_5-6"] = "취약"
        }
        else {
            Log-And-Record "[WARN] shutdownwithoutlogon 값이 비정상 → 검토"
            $global:WResult["CHK_5-6"] = "검토"
        }
    }
    catch {
        Log-And-Record "[WARN] shutdownwithoutlogon 값 조회 실패 또는 키 없음 → 검토"
        $global:WResult["CHK_5-6"] = "검토"
    }

    End-Check
    ShowResult "CHK_5-6" $global:WResult["CHK_5-6"]
}

# ---------- CHK_5-7: 로그/감사 설정 통합 (W-34 + W-69) ----------
function CHK_5-7 {
    param([string]$osCategory)

    Start-Check "CHK_5-7" "로그 보존 설정 + 감사 정책 설정 [통합]"

    $w34 = '검토'  # 로그 보존(보안 로그) 설정
    $w69 = '검토'  # 감사 정책 설정

    # ---------------------------
    # (A) W-34: 보안 로그 보존/크기
    #   - wevtutil gl security
    #   - maxSize ≥ 20480000 AND retention = true 이면 양호
    # ---------------------------
    try {
        $secLog = wevtutil gl security | Out-String
        Log-And-Record "[INFO] wevtutil gl security 출력:"
        Log-And-Record $secLog

        $maxSize   = $null
        $retention = $null

        if ($secLog -match "(?i)maxSize:\s*(\d+)") { $maxSize = [int]$Matches[1] }
        if ($secLog -match "(?i)retention:\s*(\w+)") { $retention = $Matches[1].ToLower() }

        Log-And-Record "[INFO] 보안 로그: maxSize=$maxSize, retention=$retention (요건: maxSize≥20480000 & retention=true)"

        if ($null -ne $maxSize -and $null -ne $retention) {
            if (($maxSize -ge 20480000) -and ($retention -eq "false")) {
                $w34 = '양호'
            } else {
                $w34 = '취약'
            }
        } else {
            $w34 = '검토'
        }
    }
    catch {
        Log-And-Record "[WARN] 보안 로그 조회 오류: $($_.Exception.Message) → 검토"
        $w34 = '검토'
    }

    # ---------------------------
    # (B) W-69: 감사 정책 설정 여부
    #   - auditpol /get /category:* 결과에 Success 또는 Failure가 하나라도 있으면 양호
    # ---------------------------
    try {
        $required = @(
            "Object Access",          # 개체 액세스
            "Account Management",     # 계정 관리
            "Account Logon",          # 계정 로그온 이벤트
            "Privilege Use",          # 권한 사용
            "Logon/Logoff"            # 로그온/로그오프
        )

        $audit = auditpol /get /category:* 2>&1 | Out-String

        $regexOptions = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor
                        [System.Text.RegularExpressions.RegexOptions]::Multiline

        $allOk = $true
        foreach ($cat in $required) {
            # 카테고리 블록 추출 후 Success/Failure 포함 여부 검사
            $pattern = "(?s)$([regex]::Escape($cat)).*?(?=^\S|\z)"
            $m = [regex]::Match($audit, $pattern, $regexOptions)
            if (-not $m.Success -or ($m.Value -notmatch '(?i)Success|성공') -and ($m.Value -notmatch '(?i)Failure|실패')) {
                Log-And-Record "[FAIL] 감사 카테고리 미설정: $cat"
                $allOk = $false
            } else {
                Log-And-Record "[OK] 감사 카테고리 설정: $cat (Success/Failure 감지)"
            }
        }

        # ▶ PowerShell 5.1 호환: 삼항연산자 대신 if/else
        if ($allOk) { $w69 = '양호' } else { $w69 = '취약' }
    }
    catch {
        Log-And-Record "[WARN] 감사 정책 조회 실패: $($_.Exception.Message) → 검토"
        $w69 = '검토'
    }

    # ---------------------------
    # (C) 최종 통합 판정
    # ---------------------------
    Log-And-Record "[SUMMARY] W-34=$w34 / W-69=$w69"

    if ($w34 -eq '취약' -or $w69 -eq '취약') {
        $global:WResult['CHK_5-7'] = '취약'
    }
    elseif ($w34 -eq '양호' -and $w69 -eq '양호') {
        $global:WResult['CHK_5-7'] = '양호'
    }
    else {
        $global:WResult['CHK_5-7'] = '검토'
    }

    End-Check
    ShowResult 'CHK_5-7' $global:WResult['CHK_5-7']
}

# ---------- CHK_5-8: 가상 메모리 페이지 파일 삭제 설정 ----------
# 기준: HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\ClearPageFileAtShutdown
#  - 1(사용)  → 양호
#  - 0 또는 없음 → 취약
function CHK_5-8 {
    param([string]$osCategory)

    Start-Check "CHK_5-8" "가상 메모리 페이지 파일(Pagefile) 종료 시 삭제 설정"

    $result = "검토"
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
    $name    = "ClearPageFileAtShutdown"

    try {
        if (-not (Test-Path $regPath)) {
            Log-And-Record "[WARN] 레지스트리 경로 없음: $regPath"
            # 경로가 없으면 정책이 적용되지 않은 것으로 보고 취약 처리
            $result = "취약"
        }
        else {
            $val = $null
            try {
                $val = Get-ItemPropertyValue -Path $regPath -Name $name -ErrorAction Stop
            } catch {
                Log-And-Record "[INFO] 레지스트리 값 '$name' 미존재(기본값=사용 안 함)"
            }

            if ($null -ne $val) {
                Log-And-Record "[INFO] $name=$val (요건: 1)"
                if ([int]$val -eq 1) { $result = "양호" } else { $result = "취약" }
            }
            else {
                Log-And-Record "[FAIL] $name 값이 없음 → 취약"
                $result = "취약"
            }
        }
    }
    catch {
        Log-And-Record "[WARN] CHK_5-8 점검 중 오류: $($_.Exception.Message)"
        $result = "검토"
    }

    # 참고 로그: 변경 후 재부팅 필요
    Log-And-Record "[NOTE] 이 설정은 변경 시 재부팅 후 적용됨"

    $global:WResult["CHK_5-8"] = $result
    End-Check
    ShowResult "CHK_5-8" $result
}

# ---------- CHK_5-9: LAN Manager 인증 수준 (LMCompatibilityLevel) ----------
function CHK_5-9 {
    param([string]$osCategory)
    Start-Check "CHK_5-9" "LAN Manager 인증 수준 (LmCompatibilityLevel)"

    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    $keyName = "LmCompatibilityLevel"
    $result = ""

    # 1. Test-Path로 키 존재 여부 먼저 확인
    if (-not (Test-Path $regPath)) {
        Log-And-Record "[WARN] LSA 레지스트리 키 없음 → 정책 미설정 상태"
        $result = "취약"
    }
    else {
        try {
            # 2. PowerShell 방식으로 값 조회 시도
            $lmValue = Get-ItemPropertyValue -Path $regPath -Name $keyName -ErrorAction Stop
            Log-And-Record "[INFO] LmCompatibilityLevel 값: $lmValue"

            if ($lmValue -ge 3) {
                $result = "양호"
            }
            else {
                $result = "취약"
            }
        }
        catch {
            Log-And-Record "[WARN] LmCompatibilityLevel 값 없음 → 정책 미설정 상태"
            $result = "취약"
        }
    }

    # 3. Reg Query로도 보조 검증 (권한 이슈 보완용)
    $cmd = "reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v LmCompatibilityLevel"
    $output = cmd.exe /c $cmd
    if ($LASTEXITCODE -eq 0) {
        Log-And-Record "[INFO] reg query 결과: 존재함 → 추가 확인 완료"
    }
    else {
        Log-And-Record "[WARN] reg query 결과: 값 없음 → 정책 미설정 상태"
        if ($result -eq "양호") {
            Log-And-Record "[INFO] PowerShell에서는 값 존재했으나 reg query에서는 미탐지 → 보완 확인 필요"
        }
    }

    Log-And-Record "CHK_5-9 : $result"
    $global:WResult["CHK_5-9"] = $result
    ShowResult "CHK_5-9" $global:WResult["CHK_5-9"]
}

# ---------- CHK_5-10: Everyone 사용 권한을 익명 사용자에게 적용 안함 (EveryoneIncludesAnonymous) ----------
function CHK_5-10 {
    param([string]$osCategory)
    Start-Check "CHK_5-10" "Everyone 사용 권한을 익명 사용자에게 적용 안함 (EveryoneIncludesAnonymous)"

    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    $prop = "EveryoneIncludesAnonymous"

    try {
        $val = Get-ItemPropertyValue -Path $regPath -Name $prop -ErrorAction Stop
        Log-And-Record "[INFO] EveryoneIncludesAnonymous: $val (권고: 0)"

        if ([int]$val -eq 0) {
            $global:WResult["CHK_5-10"] = "양호"
        }
        else {
            $global:WResult["CHK_5-10"] = "취약"
        }
    }
    catch {
        Log-And-Record "[WARN] EveryoneIncludesAnonymous 조회 오류: $($_.Exception.Message) → 검토"
        $global:WResult["CHK_5-10"] = "검토"
    }

    End-Check
    ShowResult "CHK_5-10" $global:WResult["CHK_5-10"]
}

# ---------- CHK_5-11: 이동식 미디어 포맷 및 꺼내기 admin만 허용 ----------
function CHK_5-11 {
    param([string]$osCategory)
    Start-Check "CHK_5-11" "이동식 미디어 포맷 및 꺼내기 admin만 허용"
    if ($osCategory -eq "Modern") {
        $tempFile = "$env:TEMP\secpol_export.cfg"
        try {
            secedit /export /cfg $tempFile /quiet
            if (Test-Path $tempFile) {
                $cont = Get-Content $tempFile -ErrorAction SilentlyContinue | Out-String
                if ($cont -match "RemovableMediaEjectPolicy\s*=\s*(\d+)") {
                    $val = [int]$matches[1]
                    Log-And-Record "[INFO] RemovableMediaEjectPolicy: $val (권고: Administrators)"
                    if ($val -eq 1) {
                        $global:WResult["CHK_5-11"] = "양호"
                    }
                    else {
                        $global:WResult["CHK_5-11"] = "취약"
                    }
                }
                else {
                    Log-And-Record "[INFO] RemovableMediaEjectPolicy 항목 미존재 → 기본값(Administrators) 적용"
                    $global:WResult["CHK_5-11"] = "양호"
                }
                Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
            }
            else {
                Log-And-Record "[WARN] secpol_export.cfg 생성 실패 → 검토"
                $global:WResult["CHK_5-11"] = "검토"
            }
        }
        catch {
            Log-And-Record "[WARN] secedit export 오류: $($_.Exception.Message) → 검토"
            $global:WResult["CHK_5-11"] = "검토"
        }
    }
    else {
        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings"
        $prop = "PreventNonAdministrators"
        try {
            $val = Get-RegValue -regPath $regPath -prop $prop -osCategory $osCategory
            Log-And-Record "[INFO] Registry ${prop}: $val (권고: 1)"
            if ([int]$val -eq 1) {
                $global:WResult["CHK_5-11"] = "양호"
            }
            else {
                $global:WResult["CHK_5-11"] = "취약"
            }
        }
        catch {
            Log-And-Record "[WARN] Registry 조회 오류: $($_.Exception.Message) → 검토"
            $global:WResult["CHK_5-11"] = "검토"
        }
    }
    End-Check
    ShowResult "CHK_5-11" $global:WResult["CHK_5-11"]
}

# ---------- CHK_5-12: 세션 연결 전 유휴시간 설정 (정밀 진단: GPO + 레지스트리) ----------
function CHK_5-12 {
    param([string]$osCategory)
    Start-Check "CHK_5-12" "세션 연결 전 유휴시간 설정 (정밀 진단)"

    $lanmanPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"

    # ① 로그온 시간 만료 시 연결 끊기(가이드 필수)
    #    Local Security Policy: "Microsoft 네트워크 서버: 로그온 시간이 만료되면 클라이언트 연결 끊기"
    #    Registry: EnableForcedLogoff (DWORD) == 1
    $forcedLogoff = $null
    try {
        if (Test-Path $lanmanPath) {
            $forcedLogoff = (Get-ItemProperty -Path $lanmanPath -Name "EnableForcedLogoff" -ErrorAction SilentlyContinue).EnableForcedLogoff
            if ($null -ne $forcedLogoff) { $forcedLogoff = [int]$forcedLogoff }
            Log-And-Record "[INFO] EnableForcedLogoff: $forcedLogoff (요건: 1)"
        }
    } catch {
        Log-And-Record "[WARN] EnableForcedLogoff 조회 오류: $($_.Exception.Message)"
    }

    # ② 유휴시간(autodisconnect) 15분
    $autodisconnect = $null
    try {
        $autodisconnect = (Get-ItemProperty -Path $lanmanPath -Name "autodisconnect" -ErrorAction SilentlyContinue).autodisconnect
        if ($null -ne $autodisconnect) { $autodisconnect = [int]$autodisconnect }
        Log-And-Record "[INFO] autodisconnect: $autodisconnect (분, 요건: 15)"
    } catch {
        Log-And-Record "[WARN] autodisconnect 조회 오류: $($_.Exception.Message)"
    }

    # 판정: 두 가지 모두 충족해야 양호 (가이드 기준)
    if ($forcedLogoff -eq 1 -and $autodisconnect -ge 15) {
        $global:WResult["CHK_5-12"] = "양호"
    }
    elseif ($forcedLogoff -eq $null -or $autodisconnect -eq $null) {
        $global:WResult["CHK_5-12"] = "검토"
    }
    else {
        # -1(무제한) 또는 0~14분 이하는 모두 취약
        $global:WResult["CHK_5-12"] = "취약"
    }

    End-Check
    ShowResult "CHK_5-12" $global:WResult["CHK_5-12"]
}

# ---------- CHK_5-13: 예약된 작업 의심스런 명령어나 파일 점검 ----------
function CHK_5-13 {
    param([string]$osCategory)
    Start-Check "CHK_5-13" "예약된 작업 의심스런 명령어나 파일 점검(점검 유무 기준)"

    $enumerated = $false
    $suspicious = @()

    try {
        $tasks = Get-ScheduledTask -ErrorAction Stop
        $enumerated = $true

        foreach ($task in $tasks) {
            # 1) Microsoft 기본 예약 작업 제외
            if ($task.TaskPath -like "\Microsoft\*") { continue }

            # 2) 화이트리스트(조직 합의 항목) 예: AWS EC2 기본 작업 등
            $wl = @("Amazon Ec2 Launch*","Amazon EC2 Launch*")
            $fullName = ($task.TaskPath + $task.TaskName)
            if ($wl | Where-Object { $fullName -like $_ }) { continue }

            # 3) 실행 명령 점검(의심 패턴은 '경고' 로그만 남김)
            $actions = ($task.Actions | Where-Object { $_.Execute })
            foreach ($action in $actions) {
                $exe = ($action.Execute | ToLower)
                if ($exe -match "powershell|cmd|wscript|cscript|rundll32|bitsadmin") {
                    $suspicious += [PSCustomObject]@{
                        TaskName = $task.TaskName
                        Path     = $task.TaskPath
                        Command  = $exe
                    }
                }
            }
        }
    }
    catch {
        Log-And-Record "[WARN] 예약 작업 조회 실패: $($_.Exception.Message)"
    }

    if ($enumerated) {
        # 가이드 기준: '점검 수행' 자체가 양호
        if ($suspicious.Count -gt 0) {
            Log-And-Record "[경고] 의심 작업 발견 개수: $($suspicious.Count)"
            $suspicious | ForEach-Object {
                Log-And-Record ("[SUSPECT] {0}{1} -> {2}" -f $_.Path, $_.TaskName, $_.Command)
            }
        } else {
            Log-And-Record "[INFO] 의심 명령 포함 사용자 예약 작업 미발견"
        }
        $global:WResult["CHK_5-13"] = "양호"
    }
    else {
        # 점검 자체를 못했으므로 '취약'
        $global:WResult["CHK_5-13"] = "취약"
    }

    End-Check
    ShowResult "CHK_5-13" $global:WResult["CHK_5-13"]
}

# ---------- CHK_5-14: 원격 시스템 종료 권한 설정  ----------
# ---------- CHK_5-14: 원격 시스템 종료 권한 설정 (가이드 정합) ----------
function CHK_5-14 {
    Start-Check "CHK_5-14" "원격 시스템 종료 권한 설정"

    $exportPath = "$env:TEMP\w40_export.inf"
    try {
        # 1) 로컬 보안 정책 export
        secedit /export /cfg $exportPath /quiet

        # 2) SeRemoteShutdownPrivilege 라인 추출
        $shutdownLine = Select-String -Path $exportPath -Pattern "^SeRemoteShutdownPrivilege\s*=" |
                        ForEach-Object { ($_ -split "=",2)[1].Trim() }

        if (-not $shutdownLine) {
            Log-And-Record "[WARN] SeRemoteShutdownPrivilege 항목 없음 → 검토"
            $global:WResult["CHK_5-14"] = "검토"
            End-Check; ShowResult "CHK_5-14" $global:WResult["CHK_5-14"]; return
        }

        # 3) 주체 목록 파싱
        $principals = $shutdownLine -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ }

        # 4) 표기 정규화 함수 (SID/로컬라이즈드/NetBIOS 모두 'Administrators'로 통일)
        function Normalize-Principal([string]$p) {
            if ($p -match '^\*?S-1-5-32-544$') { return 'Administrators' }   # Builtin Admins SID
            if ($p -ieq 'Administrators') { return 'Administrators' }
            if ($p -ieq 'BUILTIN\Administrators') { return 'Administrators' }
            return $p
        }

        $norm = $principals | ForEach-Object { Normalize-Principal $_ }

        # 5) 진단 로직 (가이드: Administrators "만" 존재해야 양호)
        if ($norm.Count -eq 0) {
            Log-And-Record "[FAIL] 권한에 아무 주체도 없음(Administrators만 존재 조건 불충족) → 취약"
            $global:WResult["CHK_5-14"] = "취약"
        }
        else {
            $unauthorized = $norm | Where-Object { $_ -ne 'Administrators' }
            if ($unauthorized.Count -eq 0) {
                Log-And-Record "[OK] 'Administrators'만 존재 → 양호"
                $global:WResult["CHK_5-14"] = "양호"
            } else {
                Log-And-Record "[FAIL] Administrators 외 주체 존재: $($unauthorized -join ', ') → 취약"
                $global:WResult["CHK_5-14"] = "취약"
            }
        }
    }
    catch {
        Log-And-Record "[WARN] 점검 중 오류: $($_.Exception.Message) → 검토"
        $global:WResult["CHK_5-14"] = "검토"
    }
    finally {
        if (Test-Path $exportPath) { Remove-Item $exportPath -Force }
    }

    End-Check
    ShowResult "CHK_5-14" $global:WResult["CHK_5-14"]
}

# ---------- CHK_5-15: 보안 감사를 로그 할 수 없는 경우 즉시 시스템 종료 방지 ----------
# ---------- CHK_5-15: 보안 감사를 로그할 수 없는 경우 즉시 시스템 종료 방지 ----------
# 가이드 기준
#  - 양호: 정책이 "사용 안 함" → CrashOnAuditFail = 0
#  - 취약: 정책이 "사용"     → CrashOnAuditFail = 1
function CHK_5-15 {
    param([string]$osCategory)
    Start-Check "CHK_5-15" "보안 감사를 로그할 수 없는 경우 즉시 시스템 종료 방지"

    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    $prop    = "CrashOnAuditFail"
    $val     = $null

    # 1) 레지스트리 우선 확인
    try {
        if (Test-Path $regPath) {
            $tmp = Get-ItemProperty -Path $regPath -Name $prop -ErrorAction SilentlyContinue
            if ($tmp -and ($tmp.PSObject.Properties.Name -contains $prop)) {
                $val = [int]$tmp.$prop
                Log-And-Record "[INFO] (REG) CrashOnAuditFail = $val"
            } else {
                Log-And-Record "[INFO] (REG) CrashOnAuditFail 값 부재"
            }
        } else {
            Log-And-Record "[WARN] LSA 레지스트리 경로 없음: $regPath"
        }
    } catch {
        Log-And-Record "[WARN] 레지스트리 조회 오류: $($_.Exception.Message)"
    }

    # 2) 보조: secedit /export 결과에서 키 탐색(환경에 따라 정책이 cfg에만 있을 수 있음)
    if ($null -eq $val) {
        try {
            $pol = Parse-SeceditPolicy
            if ($pol -and $pol.ContainsKey($prop)) {
                $val = [int]$pol[$prop]
                Log-And-Record "[INFO] (SECEDIT) CrashOnAuditFail = $val"
            } else {
                Log-And-Record "[INFO] (SECEDIT) CrashOnAuditFail 항목 없음"
            }
        } catch {
            Log-And-Record "[WARN] secedit 정책 파싱 실패: $($_.Exception.Message)"
        }
    }

    # 3) 최종 판정 (가이드 정합)
    if ($val -eq 0) {
        Log-And-Record "[OK] 정책 '사용 안 함'(CrashOnAuditFail=0) → 양호"
        $global:WResult["CHK_5-15"] = "양호"
    }
    elseif ($val -eq 1) {
        Log-And-Record "[FAIL] 정책 '사용'(CrashOnAuditFail=1) → 취약"
        $global:WResult["CHK_5-15"] = "취약"
    }
    else {
        Log-And-Record "[WARN] 값 부재/파싱불가 또는 비정상 값 → 검토"
        $global:WResult["CHK_5-15"] = "검토"
    }

    End-Check
    ShowResult "CHK_5-15" $global:WResult["CHK_5-15"]
}

# ---------- CHK_5-16: 보안 채널 데이터 디지털 암호화 또는 서명 설정 ----------
# 판단 기준(가이드 정합):
#  - 세 정책이 모두 '사용(1)' → 양호
#  - 세 정책이 모두 '사용 안 함(0)' → 취약
#  - 그 외(값 혼재, 누락, 파싱 실패) → 검토
function CHK_5-16 {
    param([string]$osCategory)

    Start-Check "CHK_5-16" "보안 채널 데이터 디지털 암호화 또는 서명 설정"

    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
    $props = @(
        @{Name="RequireSignOrSeal"; Desc="항상 디지털 암호화 또는 서명"},
        @{Name="SealSecureChannel"; Desc="가능한 경우 암호화"},
        @{Name="SignSecureChannel"; Desc="가능한 경우 서명"}
    )

    $vals = @{}
    $hadError = $false
    foreach ($p in $props) {
        try {
            $v = (Get-ItemProperty -Path $regPath -Name $p.Name -ErrorAction Stop).($p.Name)
            $vals[$p.Name] = [int]$v
            Log-And-Record "[INFO] $($p.Name)=$v (0=사용 안 함, 1=사용)"
            if ($v -ne 0 -and $v -ne 1) { $hadError = $true }
        } catch {
            Log-And-Record "[WARN] $($p.Name) 조회 실패: $($_.Exception.Message)"
            $vals[$p.Name] = $null
            $hadError = $true
        }
    }

    # 판정 로직
    $result = "검토"
    if (-not $hadError -and -not ($vals.Values -contains $null)) {
        $enabledCount = ($vals.Values | Where-Object { $_ -eq 1 }).Count
        if ($enabledCount -eq 3) {
            $result = "양호"
        } elseif ($enabledCount -eq 0) {
            $result = "취약"
        } else {
            $result = "검토"
        }
    } else {
        $result = "검토"
    }

    Log-And-Record ("[SUMMARY] RequireSignOrSeal={0}, SealSecureChannel={1}, SignSecureChannel={2} → {3}" -f `
        $vals["RequireSignOrSeal"], $vals["SealSecureChannel"], $vals["SignSecureChannel"], $result)

    $global:WResult['CHK_5-16'] = $result
    End-Check
    ShowResult 'CHK_5-16' $result
}

# ---------- CHK_6-1: 백신 프로그램 설치 여부 (Windows Server 전용 완전 대응) ----------
function CHK_6-1 {
    param([string]$osCategory)
    Start-Check "CHK_6-1" "백신 프로그램 설치 여부"

    $avFound = $false
    $avNames = @()

    # 1. SecurityCenter2 시도 (클라이언트 기반, 일부 서버에 수동 구성 시만 존재)
    try {
        $prod = Get-CimInstance -Namespace "root\SecurityCenter2" -Class AntiVirusProduct -ErrorAction Stop
        if ($prod.Count -gt 0) {
            $avFound = $true
            $prod | ForEach-Object {
                Log-And-Record "[INFO] 백신 감지(SecurityCenter2): $($_.displayName)"
                $avNames += $_.displayName
            }
        }
    } catch {
        Log-And-Record "[INFO] SecurityCenter2 사용 불가 (서버 계열에서는 일반적 현상)"
    }

    # 2. Legacy SecurityCenter (Windows 7/2008 등 매우 구형)
    if (-not $avFound) {
        try {
            $legacy = Get-WmiObject -Namespace "root\SecurityCenter" -Class AntiVirusProduct -ErrorAction Stop
            if ($legacy.Count -gt 0) {
                $avFound = $true
                $legacy | ForEach-Object {
                    Log-And-Record "[INFO] 백신 감지(SecurityCenter): $($_.displayName)"
                    $avNames += $_.displayName
                }
            }
        } catch {
            Log-And-Record "[INFO] SecurityCenter (구형)도 사용 불가"
        }
    }

    # 3. Windows Defender 상태 확인 (3가지 조건 모두 만족해야 함)
    if (-not $avFound) {
        try {
            $def = Get-MpComputerStatus -ErrorAction Stop
            if ($def.AntivirusEnabled -and $def.RealTimeProtectionEnabled -and $def.AMServiceEnabled) {
                Log-And-Record "[INFO] Windows Defender 활성화 및 실시간 보호 작동 중"
                $avFound = $true
                $avNames += "Windows Defender"
            }
            else {
                Log-And-Record "[INFO] Defender 설치됨, 하지만 비활성 상태"
            }
        } catch {
            Log-And-Record "[INFO] Defender 정보 조회 실패 (정책 비활성 또는 미설치)"
        }
    }

    # 4. V3 프로세스 확인 (실행 여부)
    if (-not $avFound) {
        try {
            $v3Proc = Get-Process -Name "V3LRun", "V3Service" -ErrorAction SilentlyContinue
            if ($v3Proc) {
                Log-And-Record "[INFO] V3 백신 프로세스 실행 중: $($v3Proc.Name -join ', ')"
                $avFound = $true
                $avNames += "AhnLab V3 (프로세스 기반)"
            } else {
                Log-And-Record "[INFO] V3 프로세스 미탐지"
            }
        } catch {
            Log-And-Record "[WARN] V3 프로세스 조회 중 오류: $($_.Exception.Message)"
        }
    }

    # 5. V3 설치 여부 확인 (레지스트리 기반)
    if (-not $avFound) {
        try {
            $v3Reg = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" |
                     ForEach-Object {
                         Get-ItemProperty $_.PsPath
                     } | Where-Object {
                         $_.DisplayName -match "AhnLab V3"
                     }

            if ($v3Reg) {
                Log-And-Record "[INFO] 레지스트리 상 AhnLab V3 설치 흔적 확인: $($v3Reg.DisplayName)"
                $avFound = $true
                $avNames += "AhnLab V3 (레지스트리 기반)"
            }
        } catch {
            Log-And-Record "[WARN] V3 설치 정보 레지스트리 확인 실패: $($_.Exception.Message)"
        }
    }

    # 6. 최종 판정
    if ($avFound) {
        $global:WResult["CHK_6-1"] = "양호"
    } else {
        Log-And-Record "[WARN] 설치된 백신 미탐지 또는 실시간 보호 미작동"
        $global:WResult["CHK_6-1"] = "취약"
    }

    Log-And-Record "탐지된 백신: $($avNames -join ', ')"
    End-Check
    ShowResult "CHK_6-1" $global:WResult["CHK_6-1"]
}

# ---------- CHK_6-2: 백신 프로그램 최신 엔진 업데이트 ----------
# 가이드: "최신 엔진 업데이트가 설치되어 있을 경우 양호" (기준 일수는 미명시)
# 구현: Defender는 서명 최종 업데이트일, 서드파티는 SecurityCenter2 productState로 판단
function CHK_6-2 {
    param([string]$osCategory)
    Start-Check "CHK_6-2" "백신 프로그램 최신 엔진 업데이트"

    # '최신'을 판단할 기준(일)
    $maxAgeDays = 7

    $now = Get-Date
    $anyAV = $false
    $anyUpToDate = $false
    $anyOutdated = $false
    $anyUnknown = $false

    # 1) Modern: SecurityCenter2 (Windows 8+/2012+)
    if ($osCategory -eq "Modern") {
        try {
            $prod = Get-CimInstance -Namespace "root\SecurityCenter2" -ClassName AntiVirusProduct -ErrorAction Stop
            if ($prod) {
                $anyAV = $true
                foreach ($p in $prod) {
                    # productState 비트 해석 (대략적/관용): 0x0010 = up-to-date, 0x0020 = out-of-date
                    $state = [int]$p.productState
                    $isUpToDate = (($state -band 0x0010) -ne 0) -and (($state -band 0x0020) -eq 0)
                    $isOutOfDate = (($state -band 0x0020) -ne 0)
                    Log-And-Record ("[INFO] AV={0} productState=0x{1:X} → UpToDate={2} OutOfDate={3}" -f $p.displayName, $state, $isUpToDate, $isOutOfDate)

                    if ($isUpToDate) { $anyUpToDate = $true }
                    elseif ($isOutOfDate) { $anyOutdated = $true }
                    else { $anyUnknown = $true }
                }
            }
        } catch {
            Log-And-Record "[WARN] SecurityCenter2 조회 오류: $($_.Exception.Message)"
        }
    }

    # 2) Legacy 보조: SecurityCenter (구형)
    if (-not $anyAV) {
        try {
            $legacyAV = Get-WmiObject -Namespace "root\SecurityCenter" -Class AntiVirusProduct -ErrorAction Stop
            if ($legacyAV) {
                $anyAV = $true
                foreach ($p in $legacyAV) {
                    # 구형 클래스는 최신 여부 판단이 일정치 않음 → 정보만 기록, 판정은 보수적으로 '검토'
                    Log-And-Record ("[INFO] (Legacy) AV={0} (업데이트 최신 여부 정보를 표준 방식으로 얻기 어려움)" -f $p.displayName)
                    $anyUnknown = $true
                }
            }
        } catch {
            Log-And-Record "[WARN] SecurityCenter(Legacy) 조회 오류: $($_.Exception.Message)"
        }
    }

    # 3) Defender가 활성화라면 날짜로 정밀 판정
    try {
        $def = Get-MpComputerStatus -ErrorAction Stop
        if ($def -and $def.AntivirusEnabled) {
            $anyAV = $true
            $last = $def.AntivirusSignatureLastUpdated
            $ageDays = ($now - $last).TotalDays
            Log-And-Record ("[INFO] Windows Defender: LastUpdated={0:u} (경과 {1:N1}일)" -f $last, $ageDays)
            if ($ageDays -le $maxAgeDays) { $anyUpToDate = $true } else { $anyOutdated = $true }
        }
    } catch {
        Log-And-Record "[INFO] Defender 상태 조회 불가 (다른 백신이 기본일 수 있음): $($_.Exception.Message)"
    }

    # 4) 최종 판정
    if (-not $anyAV) {
        Log-And-Record "[FAIL] 백신 제품을 확인하지 못했음 → 취약(또는 상위 항목에서 처리)"
        $global:WResult["CHK_6-2"] = "취약"
    }
    else {
        if ($anyUpToDate -and -not $anyOutdated -and -not $anyUnknown) {
            Log-And-Record "[OK] 설치된 백신의 엔진/서명이 최신 범위(≤${maxAgeDays}일)로 확인됨 → 양호"
            $global:WResult["CHK_6-2"] = "양호"
        }
        elseif ($anyOutdated) {
            Log-And-Record "[FAIL] 최신 엔진/서명 아님(경과일이 기준 초과 또는 보안센터가 구버전 표시) → 취약"
            $global:WResult["CHK_6-2"] = "취약"
        }
        else {
            Log-And-Record "[WARN] 최신 여부를 확정하기 어려움(SecurityCenter 구형/정보부족) → 검토"
            $global:WResult["CHK_6-2"] = "검토"
        }
    }

    End-Check
    ShowResult "CHK_6-2" $global:WResult["CHK_6-2"]
}

# ---------- CHK_7-1: SAM(Security Account Manager) 보안 감사 설정 ----------
function CHK_7-1 {
    param([string]$osCategory)
    Start-Check "CHK_7-1" "SAM(Security Account Manager) 보안 감사 설정"

    $result = "검토"
    try {
        # HKLM:\SAM 키를 .NET RegistryKey로 열고 SACL(Audit) 섹션을 요청
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,
                                                           [Microsoft.Win32.RegistryView]::Default)
        $samKey = $base.OpenSubKey("SAM",
            [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadSubTree,
            # SACL 읽기엔 추가 권한(SeSecurityPrivilege)이 필요할 수 있음
            [System.Security.AccessControl.RegistryRights]::ReadKey -bor
            [System.Security.AccessControl.RegistryRights]::ReadPermissions
        )

        if ($null -eq $samKey) {
            Log-And-Record "[WARN] HKLM:\\SAM 키를 열 수 없음 → 검토"
            $global:WResult["CHK_7-1"] = "검토"
            End-Check; ShowResult "CHK_7-1" $global:WResult["CHK_7-1"]; return
        }

        $sec = $samKey.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Audit)
        $auditRules = $sec.GetAuditRules($true, $true, [System.Security.Principal.NTAccount])

        # Everyone에 대한 감사 규칙이 있는지 확인
        $everyoneRules = $auditRules | Where-Object {
            $_.IdentityReference.Value -eq "Everyone" -and
            ( $_.AuditFlags -band ([System.Security.AccessControl.AuditFlags]::Success -bor
                                   [System.Security.AccessControl.AuditFlags]::Failure) )
        }

        if ($everyoneRules -and $everyoneRules.Count -gt 0) {
            Log-And-Record "[INFO] HKLM:\\SAM에 'Everyone' 감사(Success/Failure) 설정 확인 → 양호"
            $result = "양호"
        } else {
            Log-And-Record "[INFO] HKLM:\\SAM에 'Everyone' 감사 규칙 없음 → 취약"
            $result = "취약"
        }
    }
    catch {
        Log-And-Record "[WARN] SACL(감사) 조회 실패: $($_.Exception.Message) → 검토"
        $result = "검토"
    }

    $global:WResult["CHK_7-1"] = $result
    End-Check
    ShowResult "CHK_7-1" $result
}

# ---------- CHK_7-2: Null Session 설정 ----------
# 가이드: HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RestrictAnonymous = 2 → 양호
function CHK_7-2 {
    param([string]$osCategory)
    Start-Check "CHK_7-2" "Null Session 설정(RestrictAnonymous=2)"

    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    $prop    = "RestrictAnonymous"
    $result  = "검토"

    try {
        $val = $null
        if ($osCategory -eq "Legacy") {
            $cmdRes = cmd /c "reg query `"$($regPath -replace 'HKLM:\\','HKEY_LOCAL_MACHINE\\')`" /v $prop" 2>&1
            if ($cmdRes -match "$prop\s+REG_DWORD\s+0x([0-9a-fA-F]+)") {
                $val = [convert]::ToInt32($matches[1],16)
            } else {
                throw "값 미발견"
            }
        } else {
            $item = Get-ItemProperty -Path $regPath -ErrorAction Stop
            if ($item.PSObject.Properties.Name -contains $prop) {
                $val = [int]$item.$prop
            } else {
                throw "속성 미존재"
            }
        }

        Log-And-Record "[INFO] RestrictAnonymous: $val (요건: 2)"
        if ($val -eq 2) {
            $result = "양호"
        } else {
            $result = "취약"
        }
    }
    catch {
        Log-And-Record "[WARN] RestrictAnonymous 조회 오류: $($_.Exception.Message) → 검토"
        $result = "검토"
    }

    $global:WResult["CHK_7-2"] = $result
    End-Check
    ShowResult "CHK_7-2" $result
}

# ---------- CHK_7-3: Remote Registry Service 설정 ----------
function CHK_7-3 {
    param([string]$osCategory)
    Start-Check "CHK_7-3" "Remote Registry Service 설정"

    try {
        $svc = Get-Service -Name "RemoteRegistry" -ErrorAction Stop
        Log-And-Record "RemoteRegistry 상태: $($svc.Status)"
        
        if ($svc.Status -eq 'Running') {
            Log-And-Record "[INFO] RemoteRegistry 서비스 실행 중 → 취약"
            $global:WResult["CHK_7-3"] = "취약"
        }
        else {
            Log-And-Record "[INFO] RemoteRegistry 서비스 중지됨 → 양호"
            $global:WResult["CHK_7-3"] = "양호"
        }
    }
    catch {
        Log-And-Record "[WARN] RemoteRegistry 서비스 조회 오류: $($_.Exception.Message) → 검토"
        $global:WResult["CHK_7-3"] = "검토"
    }

    End-Check
    ShowResult "CHK_7-3" $global:WResult["CHK_7-3"]
}

# ---------- CHK_7-4: RDS(Remote Data Services) 제거 ----------
function CHK_7-4 {
    param([string]$osCategory)
    Start-Check "CHK_7-4" "RDS(Remote Data Services) 제거"

    # Windows 2019 가이드: 해당 OS는 체크리스트에 포함하지 않음 → N/A 처리 
    Log-And-Record "[INFO] 이 OS 버전에서는 RDS 항목이 평가 대상 아님(N/A)."
    $global:WResult["CHK_7-4"] = "N/A"
    End-Check
    ShowResult "CHK_7-4" $global:WResult["CHK_7-4"]
}

# ---------- CHK_7-5: Autologon 제한 설정 (가이드 기준 정합) ----------
function CHK_7-5 {
    param([string]$osCategory)
    Start-Check "CHK_7-5" "Autologon 제한 설정"

    try {
        $val = $null
        $userNameExists = $false
        $passwordExists = $false

        if ($osCategory -eq "Legacy") {
            $res = cmd /c "reg query `"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`" 2>&1"
            if ($res -match "AutoAdminLogon\s+REG_SZ\s+(\S+)") { $val = $matches[1] }
            if ($res -match "DefaultUserName\s+REG_SZ\s+.*")   { $userNameExists = $true }
            if ($res -match "DefaultPassword\s+REG_SZ\s+.*")   { $passwordExists = $true }
        } else {
            $item = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ErrorAction SilentlyContinue
            if ($item) {
                if ($item.PSObject.Properties.Name -contains "AutoAdminLogon") { $val = $item.AutoAdminLogon }
                if ($item.PSObject.Properties.Name -contains "DefaultUserName") { $userNameExists = $true }
                if ($item.PSObject.Properties.Name -contains "DefaultPassword") { $passwordExists = $true }
            }
        }

        Log-And-Record "[INFO] AutoAdminLogon: $val (요건: 0 또는 미설정)"
        if ($userNameExists) { Log-And-Record "[INFO] DefaultUserName 키 존재" }
        if ($passwordExists) { Log-And-Record "[WARN] DefaultPassword 키 존재(권고: 삭제 필요)" }

        # === 가이드 '진단 기준'에 따른 판정: AutoAdminLogon만으로 판정 ===
        if ($val -eq "1") {
            $global:WResult["CHK_7-5"] = "취약"
        }
        elseif (($val -eq "0") -or ($null -eq $val)) {
            $global:WResult["CHK_7-5"] = "양호"
        }
        else {
            $global:WResult["CHK_7-5"] = "검토"
        }
    }
    catch {
        Log-And-Record "[WARN] Autologon 점검 오류: $($_.Exception.Message) → 검토"
        $global:WResult["CHK_7-5"] = "검토"
    }

    End-Check
    ShowResult "CHK_7-5" $global:WResult["CHK_7-5"]
}

# ---------- CHK_7-6: DOS 공격에 대한 방어 레지스트리 설정 ----------
function CHK_7-6 {
    param([string]$osCategory)
    Start-Check "CHK_7-6" "DOS 공격에 대한 방어 레지스트리 설정"

    # 가이드라인: 해당 OS는 체크리스트에 포함하지 않음
    Log-And-Record "[INFO] 해당 OS에서는 DOS 방어 레지스트리 설정 점검을 수행하지 않음 → N/A"
    $global:WResult["CHK_7-6"] = "N/A"

    End-Check
    ShowResult "CHK_7-6" $global:WResult["CHK_7-6"]
}


# ---------- CHK_8-1: 최신 서비스팩 적용 (가이드 정합 버전) ----------
function CHK_8-1 {
    param([string]$osCategory)
    Start-Check "CHK_8-1" "최신 서비스팩 적용"
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $ver = $os.Version
        $sp  = [int]$os.ServicePackMajorVersion

        Log-And-Record "[INFO] OS Version=$ver, ServicePackMajorVersion=$sp"

        if ($ver -like "6.0*") {
            # Windows Server 2008 → 최신 SP = 2
            if ($sp -ge 2) {
                Log-And-Record "[OK] WS2008: SP2 이상 → 양호"
                $global:WResult["CHK_8-1"] = "양호"
            } else {
                Log-And-Record "[FAIL] WS2008: 최신 SP(2) 미만 → 취약"
                $global:WResult["CHK_8-1"] = "취약"
            }
        }
        elseif ($ver -like "6.1*") {
            # Windows Server 2008 R2 → 최신 SP = 1
            if ($sp -ge 1) {
                Log-And-Record "[OK] WS2008 R2: SP1 이상 → 양호"
                $global:WResult["CHK_8-1"] = "양호"
            } else {
                Log-And-Record "[FAIL] WS2008 R2: 최신 SP(1) 미만 → 취약"
                $global:WResult["CHK_8-1"] = "취약"
            }
        }
        else {
            # Windows Server 2012+ : 서비스팩 개념 없음 → N/A
            Log-And-Record "[INFO] Windows Server 2012 이후: 서비스팩 개념 없음 → N/A"
            $global:WResult["CHK_8-1"] = "N/A"
        }
    }
    catch {
        Log-And-Record "[WARN] 서비스팩 조회 오류: $($_.Exception.Message) → 검토"
        $global:WResult["CHK_8-1"] = "검토"
    }
    End-Check
    ShowResult "CHK_8-1" $global:WResult["CHK_8-1"]
}

# ---------- CHK_8-2: 최신 Hotfix 적용 ----------
function CHK_8-2 {
    param([string]$osCategory)
    Start-Check "CHK_8-2" "최신 Hotfix 적용"
    try {
        $hotfixes = Get-HotFix -ErrorAction Stop | Sort-Object InstalledOn -Descending
        if ($hotfixes.Count -eq 0) {
            Log-And-Record "[FAIL] 설치된 Hotfix 없음 → 취약"
            $global:WResult["CHK_8-2"] = "취약"
        }
        else {
            $latest = $hotfixes[0]
            $daysAgo = (New-TimeSpan -Start $latest.InstalledOn -End (Get-Date)).Days
            Log-And-Record "[INFO] 최신 Hotfix: $($latest.HotFixID) / 설치일: $($latest.InstalledOn)"

            # 예시: 최근 30일 이내 설치된 경우 '최신'으로 간주
            if ($daysAgo -le 30) {
                $global:WResult["CHK_8-2"] = "양호"
            }
            else {
                Log-And-Record "[WARN] 최신 Hotfix 설치가 오래됨(마지막 $daysAgo일 전) → 취약 가능"
                $global:WResult["CHK_8-2"] = "취약"
            }
        }
    }
    catch {
        Log-And-Record "[WARN] Hotfix 조회 오류: $($_.Exception.Message) → 검토"
        $global:WResult["CHK_8-2"] = "검토"
    }
    End-Check
    ShowResult "CHK_8-2" $global:WResult["CHK_8-2"]
}

# ---------- CHK_9-1: OpenSSL 취약점 점검 ----------
# 기준: 
#   - OpenSSL 미사용 OR 최신버전(1.1.1n 이상, 3.0.1 이상) → 양호
#   - 구버전 사용(1.0.x, 1.1.0, 1.1.1m 이하 등)          → 취약
#   - 판정 불가                                         → 검토
function CHK_9-1 {
    param([string]$osCategory)

    Start-Check "CHK_9-1" "OpenSSL 취약점 점검"

    $result = "검토"
    try {
        # openssl.exe 실행 가능 여부 확인
        $opensslPath = (Get-Command openssl.exe -ErrorAction SilentlyContinue).Source
        if (-not $opensslPath) {
            Log-And-Record "[INFO] OpenSSL.exe 설치되지 않음 → 양호"
            $result = "양호"
        }
        else {
            # 버전 확인
            $verOutput = & $opensslPath version 2>&1 | Out-String
            Log-And-Record "[INFO] openssl version 출력: $verOutput"

            if ($verOutput -match "(\d+\.\d+\.\d+[a-z]*)") {
                $ver = $Matches[1]
                Log-And-Record "[INFO] 탐지된 OpenSSL 버전: $ver"

                # 문자열 비교 → 세부 버전 분기
                if ($ver -match "^1\.0" -or $ver -match "^1\.1\.0") {
                    Log-And-Record "[FAIL] EOS(OpenSSL 1.0.x, 1.1.0.x) 사용 중 → 취약"
                    $result = "취약"
                }
                elseif ($ver -match "^1\.1\.1") {
                    # 1.1.1n 이상이면 양호, 그 이하면 취약
                    $sub = $ver.Substring(6)   # 예: "n"
                    if ($sub -cmatch "^[n-z]") {
                        $result = "양호"
                    } else {
                        $result = "취약"
                    }
                }
                elseif ($ver -match "^3\.0") {
                    # 3.0.1 이상이면 양호
                    if ($ver -ge "3.0.1") {
                        $result = "양호"
                    } else {
                        $result = "취약"
                    }
                }
                else {
                    Log-And-Record "[WARN] 버전이 가이드 목록에 없음 → 검토"
                    $result = "검토"
                }
            }
            else {
                Log-And-Record "[WARN] OpenSSL 버전 문자열 파싱 실패"
                $result = "검토"
            }
        }
    }
    catch {
        Log-And-Record "[ERROR] OpenSSL 점검 오류: $($_.Exception.Message)"
        $result = "검토"
    }

    $global:WResult["CHK_9-1"] = $result
    End-Check
    ShowResult "CHK_9-1" $result
}

# -------------------------------
# (C) 메인 실행부
# -------------------------------

# OS 버전 범주 결정 및 결과 파일 이름 설정
$osCategory = Get-OSVersionCategory
$global:osCategory = $osCategory
$global:ResultFile = Get-ResultFileName
$resultFile = $global:ResultFile
Write-Host "결과 파일: $global:ResultFile"

Log-And-Record "======================== Windows 취약점 진단 (1.1 ~ 9.1) ======================"
Log-And-Record "[Start Script] $(Get-Date)"
Log-And-Record "OS Version Category: $osCategory"
Log-And-Record ""

# 보안 정책 내보내기 및 LGPO.exe 내보내기 (Modern 환경)
Initialize-SecurityExport -osCategory $osCategory
$global:LGPOExportPath = Export-LGPO

# 진단 함수 목록 (1.1 ~ 9.1)
$checkFunctions = @(
    "CHK_1-1", "CHK_1-2", "CHK_1-3", "CHK_1-4", "CHK_1-5", "CHK_1-6",
    "CHK_1-7", "CHK_1-8", "CHK_2-1", "CHK_2-2", "CHK_2-3", "CHK_2-4",
    "CHK_2-5", "CHK_3-1", "CHK_3-2", "CHK_3-3", "CHK_3-4", "CHK_4-1", "CHK_4-2", "CHK_4-3", "CHK_5-1", "CHK_5-2", "CHK_5-3", "CHK_5-4", "CHK_5-5", "CHK_5-6", "CHK_5-7", "CHK_5-8", "CHK_5-9", "CHK_5-10", "CHK_5-11", "CHK_5-12", "CHK_5-13", "CHK_5-14", "CHK_5-15", "CHK_5-16", "CHK_6-1", "CHK_6-2", "CHK_7-1", "CHK_7-2", "CHK_7-3", "CHK_7-4", "CHK_7-5", "CHK_7-6", "CHK_8-1", "CHK_8-2", "CHK_9-1"
)

foreach ($func in $checkFunctions) {
    try {
        & $func -osCategory $osCategory
    }
    catch {
        Log-And-Record "[ERROR] 함수 $func 실행 중 오류: $($_.Exception.Message)"
        $global:WResult[$func] = "오류: $($_.Exception.Message)"
    }
}

# ──────────── 최종 결과 정리 ────────────
$global:DisableInfoPrefix = $true

Log-And-Record "`n========= 최종 정리 (1.1~9.1) ========="
foreach ($key in $global:WResult.Keys | Sort-Object) {
    Log-And-Record "$key : $($global:WResult[$key])"
}

$global:DisableInfoPrefix = $false

# ──────────── 최종 통계 요약 ────────────
$totalCount = $global:WResult.Count
$goodCount  = ($global:WResult.Values | Where-Object { $_ -match "양호" }).Count
$badCount   = ($global:WResult.Values | Where-Object { $_ -match "취약" }).Count
$reviewCount= ($global:WResult.Values | Where-Object { $_ -match "검토" }).Count
$naCount    = ($global:WResult.Values | Where-Object { $_ -match "N/A" }).Count

Log-And-Record "`n========= 최종 통계 ========="
Log-And-Record "전체 항목 개수 : $totalCount"
Log-And-Record "양호 : $goodCount"
Log-And-Record "취약 : $badCount"
Log-And-Record "검토 : $reviewCount"
Log-And-Record "N/A : $naCount"

# --- TXT 결과 저장 ---
$txtFile = $global:ResultFile   # 이미 txt 경로임

Log-And-Record "`n[End Script] $(Get-Date)"
Log-And-Record "txt 결과 파일 생성: $txtFile"