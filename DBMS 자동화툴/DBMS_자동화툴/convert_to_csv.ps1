#requires -version 3.0
param (
    [Parameter(Mandatory=$true)]
    [string]$ReportDir
)

# 최종 결과를 저장할 배열 초기화
$results = [System.Collections.Generic.List[object]]::new()

# -Recurse 옵션을 추가하여 하위 폴더(chapter4 등)까지 모두 검색
$reportFiles = Get-ChildItem -Path $ReportDir -Filter "security_report_chapter_*.txt" -Recurse | Sort-Object Name

if ($reportFiles.Count -eq 0) {
    Write-Error "No report files found in '$ReportDir' or its subdirectories."
    exit 1
}

Write-Host "Found $($reportFiles.Count) report files. Starting parsing..."

# 각 보고서 파일을 순회하며 내용 분석
foreach ($file in $reportFiles) {
    Write-Host " - Processing '$($file.Name)'..."
    
    # 파일명에 따라 다른 인코딩 방식을 적용 (한글 깨짐 방지)
    # chapter 1, 2, 3, 5는 Windows 기본 인코딩(ANSI)으로, 그 외는 UTF-8로 읽습니다.
    $encoding = 'UTF8' # 기본값
    if ($file.Name -match 'security_report_chapter_[1235]\.txt' -or $file.Name -match 'security_report_chapter_[1235]-') {
        $encoding = 'Default' # ANSI (CP949)
    }
    
    Write-Host "   - Reading with encoding: $encoding"
    
    try {
        $content = Get-Content -Path $file.FullName -Raw -Encoding $encoding -ErrorAction Stop
        
        # 내용이 비어있거나 너무 짧은 경우 건너뛰기
        if ([string]::IsNullOrWhiteSpace($content) -or $content.Length -lt 50) {
            Write-Warning "   - Skipping '$($file.Name)' - content too short or empty"
            continue
        }
        
    } catch {
        Write-Warning "   - Error reading '$($file.Name)': $($_.Exception.Message)"
        # UTF8로 다시 시도
        if ($encoding -eq 'Default') {
            try {
                Write-Host "   - Retrying with UTF8 encoding..."
                $content = Get-Content -Path $file.FullName -Raw -Encoding UTF8 -ErrorAction Stop
            } catch {
                Write-Error "   - Failed to read file with both encodings: $($_.Exception.Message)"
                continue
            }
        } else {
            continue
        }
    }
    
    # 4-1_2_3, 4_5 와 같은 다양한 항목 번호 패턴을 인식하도록 정규표현식 변경
    $items = $content -split '(?=### \[[^\]]+\])'
    
    Write-Host "   - Found $($items.Count) potential items"
    
    # 첫 번째 분리된 요소(보고서 헤더)는 건너뜀
    $processedCount = 0
    foreach ($item in $items | Select-Object -Skip 1) {
        if ([string]::IsNullOrWhiteSpace($item.Trim())) { continue }
        
        # 개선된 제목 추출 - 여러 패턴 시도
        $titleMatch = $null
        $itemLines = $item.Trim().Split([Environment]::NewLine)
        
        # 첫 번째 줄에서 제목 추출 시도
        foreach ($line in $itemLines | Select-Object -First 3) {
            $line = $line.Trim()
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            
            # 다양한 항목 번호 패턴을 추출하도록 정규표현식들을 시도
            $patterns = @(
                '### \[(?<number>[\d\.\-_]+)\] (?<name>.+?) ###',  # 원래 패턴
                '### \[(?<number>[\d\.\-_]+)\] (?<name>.+?)$',     # ### 없는 경우
                '\[(?<number>[\d\.\-_]+)\] (?<name>.+?)$',         # ### 자체가 없는 경우
                '(?<number>[\d\.\-_]+)[\.\:\-\s]+(?<name>.+?)$'   # 번호만 있는 경우
            )
            
            foreach ($pattern in $patterns) {
                $titleMatch = [regex]::Match($line, $pattern)
                if ($titleMatch.Success) {
                    break
                }
            }
            
            if ($titleMatch.Success) {
                break
            }
        }
        
        if (-not $titleMatch.Success) {
            Write-Warning "   - Could not extract title from item starting with: $($item.Substring(0, [Math]::Min(100, $item.Length)))"
            continue
        }
        
        $itemNumber = $titleMatch.Groups['number'].Value.Trim()
        $itemName = $titleMatch.Groups['name'].Value.Trim()
        
        # 배치 파일 이스케이프 문자 처리 (^( ^) 등)
        $itemName = $itemName -replace '\^(.)', '$1'
        
        # 명령어 추출 시, [진단 결론]이 없어도 항목의 끝까지 안전하게 인식하도록 변경
        $commandText = "" # 기본값은 빈 문자열
        $commandMatch = [regex]::Match($item, '\[(SQL|OS) Command\]\s*(?<command>[\s\S]*?)(?=\s*\[진단 결론\]|\s*###|$)')
        if ($commandMatch.Success) {
            # 명령어와 결과 텍스트를 가져와 앞뒤 공백 제거
            $commandText = $commandMatch.Groups['command'].Value.Trim()
            # 너무 긴 명령어는 첫 몇 줄만 사용
            if ($commandText.Length -gt 500) {
                $commandLines = $commandText.Split([Environment]::NewLine)
                $commandText = ($commandLines | Select-Object -First 3) -join "`n" + "..."
            }
        }
        
        # [진단 결론] 섹션이 없어도 항목을 건너뛰지 않도록 로직 변경
        $conclusionText = "정보 없음: [진단 결론] 섹션을 찾을 수 없습니다." # 기본값
        $status = "정보" # 기본값
        
        $conclusionMatch = [regex]::Match($item, '\[진단 결론\]\s*(?<conclusion>[\s\S]+)')
        if ($conclusionMatch.Success) {
            # 진단 결론이 있으면 첫 번째 줄만 가져오기
            $conclusionText = $conclusionMatch.Groups['conclusion'].Value.Trim().Split([Environment]::NewLine, 2)[0].Trim()
            
            # 진단 결론이 있을 경우에만 상태 업데이트
            if ($conclusionText -match '^양호') {
                $status = "양호"
            } elseif ($conclusionText -match '^취약') {
                $status = "취약"
            } elseif ($conclusionText -match '^수동') {
                $status = "수동확인필요"
            }
        }
        
        # 결과 객체 생성 및 배열에 추가
        $resultObject = [PSCustomObject]@{
            '항목번호' = $itemNumber
            '항목명'   = $itemName
            '결과'     = $status
            '상세내용' = $conclusionText
            '진단명령어' = $commandText
        }
        $results.Add($resultObject)
        $processedCount++
    }
    
    Write-Host "   - Successfully processed $processedCount items from '$($file.Name)'"
}

# 결과가 있는 경우에만 CSV 파일 생성
if ($results.Count -gt 0) {
    # 최종 결과를 CSV 파일로 저장
    $csvOutputPath = Join-Path -Path $ReportDir -ChildPath "security_report_summary.csv"
    
    # CSV 파일을 UTF-8 BOM 인코딩으로 저장하여 Excel에서 한글이 깨지지 않도록 합니다.
    $results | Export-Csv -Path $csvOutputPath -NoTypeInformation -Encoding UTF8
    
    # 요약 통계 계산
    $statusGroups = $results | Group-Object '결과'
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    # 요약 결과를 TXT 파일로 저장
    $summaryTxtPath = Join-Path -Path $ReportDir -ChildPath "result_summary.txt"
    $summaryContent = @"
Oracle Database 보안 점검 결과 요약
생성 시간: $timestamp
=====================================================

총 점검 항목: $($results.Count)개
CSV 파일: security_report_summary.csv

점검 결과 통계:
"@

    foreach ($group in $statusGroups | Sort-Object Name) {
        $summaryContent += "`n  $($group.Name): $($group.Count)개"
    }
    
    $summaryContent += "`n`n상세 항목별 결과:"
    $summaryContent += "`n" + ("-" * 50)
    
    foreach ($item in $results | Sort-Object { [decimal]($_.항목번호 -replace '[^\d\.]', '') }) {
        $summaryContent += "`n[$($item.항목번호)] $($item.항목명) - $($item.결과)"
    }
    
    $summaryContent | Out-File -FilePath $summaryTxtPath -Encoding UTF8
    
    # 요약 결과를 CSV 형태로도 저장
    $summaryCsvPath = Join-Path -Path $ReportDir -ChildPath "result_summary.csv"
    $summaryData = [PSCustomObject]@{
        '점검시간' = $timestamp
        '총항목수' = $results.Count
        '양호' = ($statusGroups | Where-Object { $_.Name -eq '양호' }).Count
        '취약' = ($statusGroups | Where-Object { $_.Name -eq '취약' }).Count
        '수동확인필요' = ($statusGroups | Where-Object { $_.Name -eq '수동확인필요' }).Count
    }
    
    # 빈 값들을 0으로 처리
    if (-not $summaryData.'양호') { $summaryData.'양호' = 0 }
    if (-not $summaryData.'취약') { $summaryData.'취약' = 0 }
    if (-not $summaryData.'수동확인필요') { $summaryData.'수동확인필요' = 0 }
    if (-not $summaryData.'정보') { $summaryData.'정보' = 0 }
    
    $summaryData | Export-Csv -Path $summaryCsvPath -NoTypeInformation -Encoding UTF8
    
    Write-Host ""
    Write-Host "=== SUMMARY ===" -ForegroundColor Green
    Write-Host "Total items processed: $($results.Count)" -ForegroundColor Green
    Write-Host "CSV file created: '$csvOutputPath'" -ForegroundColor Green
    Write-Host "Summary TXT file created: '$summaryTxtPath'" -ForegroundColor Yellow
    Write-Host "Summary CSV file created: '$summaryCsvPath'" -ForegroundColor Yellow
    
    # 상태별 통계 출력
    foreach ($group in $statusGroups) {
        Write-Host "$($group.Name): $($group.Count) items" -ForegroundColor Cyan
    }
} else {
    Write-Warning "No valid items were processed. Check the report files format."
    exit 1
}