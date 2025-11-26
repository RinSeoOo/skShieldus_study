#!/bin/bash

# ==============================================================================
# SK Shieldus Linux Security Guideline Automated Scanner
#
# - 이 스크립트는 '2022_보안가이드라인_OS진단_LINUX.pdf'를 기반으로 작성되었습니다.
# - 정확한 진단을 위해 반드시 root 권한으로 실행해야 합니다. (sudo ./filename.sh)
# ==============================================================================

# 결과 파일 이름 설정 (실행 날짜와 시간을 포함하여 자동으로 생성)
RESULT_FILE="scan_result_$(date +%Y%m%d_%H%M%S).txt"

# 이 스크립트의 모든 표준 출력(1)과 표준 오류(2)를 tee를 통해 화면과 파일로 동시에 보내도록 설정
exec > >(tee -a "$RESULT_FILE") 2>&1

# 결과 출력 색상
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# 결과 카운트를 위한 변수 초기화
count_good=0
count_vul=0
count_manual=0

# CSV 파일 이름 설정 (날짜 포함) 및 헤더 생성
CSV_FILE="scan_result_$(date +%Y%m%d_%H%M%S).csv"
printf '\xEF\xBB\xBF' > "$CSV_FILE"
echo "점검 코드,점검 항목,결과,상세 내용,양호 기준,취약 기준" >> "$CSV_FILE"

# 출력 함수
# $1: 점검 항목 코드 및 이름
# $2: 양호 기준
# $3: 취약 기준
# $4: 결과 (Good, Vul, Manual)
# $5: 상세 설명
print_result() {
    echo ""
    echo "[ $1 ]"
    echo " 양호 기준 : $2"
    echo " 취약 기준 : $3"
    
    case "$4" in
        Good)
            echo -e " ${GREEN}▶ 양호${NC} : $5"
            ((count_good++))
            ;;
        Vul)
            echo -e " ${RED}▶ 취약${NC} : $5"
            ((count_vul++))
            ;;
        Manual)
            echo " ▶ N/A : $5"
            ((count_manual++))
            ;;
    esac
    echo ""

    # CSV 파일에 저장할 데이터 정리
    local code=$(echo "$1" | awk '{print $1}')
    local name=$(echo "$1" | cut -d' ' -f2-)
    local result_text=""
    case "$4" in
        Good) result_text="양호" ;;
        Vul) result_text="취약" ;;
        Manual) result_text="N/A" ;;
    esac
    # 상세 내용($5)에 포함된 큰따옴표(")를 엑셀 CSV 형식에 맞게 두 개("")로 변경
    local details_csv=$(echo "$5" | sed 's/"/""/g')
    local good_criteria_csv=$(echo "$2" | sed 's/"/""/g')
    local vuln_criteria_csv=$(echo "$3" | sed 's/"/""/g')

    # CSV 파일에 한 줄 추가 (>>)
    echo "\"$code\",\"$name\",\"$result_text\",\"$details_csv\",\"$good_criteria_csv\",\"$vuln_criteria_csv\"" >> "$CSV_FILE"
}

# 스크립트 시작 알림
echo "==============================================================="
echo ""
echo "           Linux 보안 취약점 점검을 시작합니다."
echo "  점검 기준: SK쉴더스 2022_보안가이드라인_OS진단_LINUX (v13.0)"
echo ""
echo "==============================================================="
echo ""


echo ""
echo ""
echo "==============================================================="
echo ""
echo "     1. 계정관리"
echo ""
echo "==============================================================="
echo ""

#1.1 로그인 설정
print_result "1.1 로그인 설정" \
"패스워드 없는 계정의 로그인이 금지되어 있는 경우" \
"패스워드 없는 계정의 로그인이 허용된 경우" \
"Manual" \
"해당 OS는 체크리스트에 포함하지 않음."

#1.2 Default 계정 삭제
vulnerable_accounts=()
check_accounts=("lp" "uucp" "nuucp" "guest" "test")
for account in "${check_accounts[@]}"; do
    if grep -q "^${account}:" /etc/passwd; then
        vulnerable_accounts+=("$account")
    fi
done
if [ ${#vulnerable_accounts[@]} -gt 0 ]; then
    print_result "1.2 Default 계정 삭제" \
    "lp, uucp, nuucp 및 의심스러운 특이 계정이 존재하지 않을 경우" \
    "lp, uucp, nuucp 및 의심스러운 특이 계정이 존재하는 경우" \
    "Vul" \
    "불필요한 계정이 존재합니다: ${vulnerable_accounts[*]}"
else
    print_result "1.2 Default 계정 삭제" \
    "lp, uucp, nuucp 및 의심스러운 특이 계정이 존재하지 않을 경우" \
    "lp, uucp, nuucp 및 의심스러운 특이 계정이 존재하는 경우" \
    "Good" \
    "불필요한 기본 계정이 존재하지 않습니다."
fi

#1.3 일반계정 root 권한 관리
root_users=$(awk -F: '($3 == 0)' /etc/passwd | awk -F: '{print $1}')
num_root_users=$(echo "$root_users" | wc -l)
if [ "$num_root_users" -gt 1 ]; then
    print_result "1.3 일반계정 root 권한 관리" \
    "root 계정을 제외하고 UID가 '0'인 계정이 존재하지 않는 경우" \
    "root 계정을 제외하고 UID가 '0'인 계정이 존재하는 경우" \
    "Vul" \
    "root 권한(UID=0)을 가진 계정이 여러 개 존재합니다: $root_users"
else
    print_result "1.3 일반계정 root 권한 관리" \
    "root 계정을 제외하고 UID가 '0'인 계정이 존재하지 않는 경우" \
    "root 계정을 제외하고 UID가 '0'인 계정이 존재하는 경우" \
    "Good" \
    "root 권한(UID=0)을 가진 계정은 root만 존재합니다."
fi

#1.4 /etc/passwd 파일 권한 설정
perm=$(stat -c "%a" /etc/passwd)
owner=$(stat -c "%U" /etc/passwd)
if [ "$owner" == "root" ] && [ "$perm" -le 644 ]; then
    print_result "1.4 /etc/passwd 파일 권한 설정" \
    "/etc/passwd 파일의 소유자가 root이고, 권한이 644 이하인 경우" \
    "/etc/passwd 파일의 소유자가 root가 아니거나, 권한이 644보다 높은 경우" \
    "Good" \
    "파일 소유자: $owner, 권한: $perm"
else
    print_result "1.4 /etc/passwd 파일 권한 설정" \
    "/etc/passwd 파일의 소유자가 root이고, 권한이 644 이하인 경우" \
    "/etc/passwd 파일의 소유자가 root가 아니거나, 권한이 644보다 높은 경우" \
    "Vul" \
    "파일 소유자: $owner, 권한: $perm"
fi

#1.5 /etc/group 파일 권한 설정
perm=$(stat -c "%a" /etc/group)
owner=$(stat -c "%U" /etc/group)
if [ "$owner" == "root" ] && [ "$perm" -le 644 ]; then
    print_result "1.5 /etc/group 파일 권한 설정" \
    "/etc/group 파일의 소유자가 root이고, 권한이 644 이하인 경우" \
    "/etc/group 파일의 소유자가 root가 아니거나, 권한이 644보다 높은 경우" \
    "Good" \
    "파일 소유자: $owner, 권한: $perm"
else
    print_result "1.5 /etc/group 파일 권한 설정" \
    "/etc/group 파일의 소유자가 root이고, 권한이 644 이하인 경우" \
    "/etc/group 파일의 소유자가 root가 아니거나, 권한이 644보다 높은 경우" \
    "Vul" \
    "파일 소유자: $owner, 권한: $perm"
fi

#1.6 /etc/shadow 파일 권한 설정
if [ -f /etc/shadow ]; then
    perm=$(stat -c "%a" /etc/shadow)
    owner=$(stat -c "%U" /etc/shadow)
    if [ "$owner" == "root" ] && [ "$perm" -le 400 ]; then
        print_result "1.6 /etc/shadow 파일 권한 설정" \
        "/etc/shadow 파일의 소유자가 root이고, 권한이 400 이하인 경우" \
        "/etc/shadow 파일의 소유자가 root가 아니거나, 권한이 400보다 높은 경우" \
        "Good" \
        "파일 소유자: $owner, 권한: $perm"
    else
        print_result "1.6 /etc/shadow 파일 권한 설정" \
        "/etc/shadow 파일의 소유자가 root이고, 권한이 400 이하인 경우" \
        "/etc/shadow 파일의 소유자가 root가 아니거나, 권한이 400보다 높은 경우" \
        "Vul" \
        "파일 소유자: $owner, 권한: $perm"
    fi
else
    print_result "1.6 /etc/shadow 파일 권한 설정" \
    "/etc/shadow 파일의 소유자가 root이고, 권한이 400 이하인 경우" \
    "/etc/shadow 파일의 소유자가 root가 아니거나, 권한이 400보다 높은 경우" \
    "Vul" \
    "/etc/shadow 파일이 존재하지 않아 패스워드 암호화가 적용되지 않았습니다."
fi

#1.7 패스워드 사용 규칙 적용
pass_min_len=$(grep "^PASS_MIN_LEN" /etc/login.defs | awk '{print $2}')
pass_max_days=$(grep "^PASS_MAX_DAYS" /etc/login.defs | awk '{print $2}')
pass_min_days=$(grep "^PASS_MIN_DAYS" /etc/login.defs | awk '{print $2}')
deny_count=$(grep -v "^#" /etc/pam.d/system-auth /etc/pam.d/common-auth /etc/pam.d/password-auth 2>/dev/null | grep -E "pam_tally|pam_faillock" | grep "deny" | sed -n 's/.*deny=\([0-9]*\).*/\1/p' | head -1)

issues=()
if [[ -z "$pass_min_len" || "$pass_min_len" -lt 8 ]]; then
    issues+=("패스워드 최소 길이 미흡(PASS_MIN_LEN=${pass_min_len:-not set})")
fi
if [[ -z "$pass_max_days" || "$pass_max_days" -gt 90 ]]; then # 가이드라인은 60, 일반적 기준 90
    issues+=("패스워드 최대 사용기간 미흡(PASS_MAX_DAYS=${pass_max_days:-not set})")
fi
if [[ -z "$pass_min_days" || "$pass_min_days" -lt 1 ]]; then
    issues+=("패스워드 최소 사용기간 미흡(PASS_MIN_DAYS=${pass_min_days:-not set})")
fi
if [[ -z "$deny_count" || "$deny_count" -gt 5 ]]; then
    issues+=("계정 잠금 임계값 미흡(deny=${deny_count:-not set})")
fi

if [ ${#issues[@]} -gt 0 ]; then
    print_result "1.7 패스워드 사용 규칙 적용" \
    "패스워드 최소길이(8자 이상), 최대/최소 사용기간, 계정 잠금 임계값(5회 이하) 등이 설정된 경우" \
    "위 기준 중 하나라도 만족하지 않는 경우" \
    "Vul" \
    "정책 미흡: ${issues[*]}"
else
    print_result "1.7 패스워드 사용 규칙 적용" \
    "패스워드 최소길이(8자 이상), 최대/최소 사용기간, 계정 잠금 임계값(5회 이하) 등이 설정된 경우" \
    "위 기준 중 하나라도 만족하지 않는 경우" \
    "Good" \
    "패스워드 정책이 양호하게 설정되었습니다."
fi

#1.8 취약한 패스워드 점검
print_result "1.8 취약한 패스워드 점검" \
"추측하기 어려운 패스워드(8자 이상 영문/숫자/특수문자 조합)를 사용하는 경우" \
"추측하기 쉬운 패스워드를 사용하는 경우" \
"Manual" \
"John the Ripper 등 크랙 도구 사용 또는 담당자 인터뷰가 필요한 항목입니다."

#1.9 로그인이 불필요한 계정 shell 제한
bad_shells=()
good_shells=()
# 시스템 계정 예시 (daemon, bin, sys, adm, lp, smtp, nuucp 등)
sys_accounts=("daemon" "bin" "sys" "adm" "lp" "smtp" "uucp" "nuucp" "listen" "nobody" "noaccess")
for acc in "${sys_accounts[@]}"; do
    shell=$(grep "^${acc}:" /etc/passwd | awk -F: '{print $7}')
    if [[ -n "$shell" && "$shell" != *nologin && "$shell" != *false ]]; then
        bad_shells+=("$acc($shell)")
    else
        good_shells+=("$acc($shell)")
    fi
done
if [ ${#bad_shells[@]} -gt 0 ]; then
    print_result "1.9 로그인이 불필요한 계정 shell 제한" \
    "로그인이 불필요한 시스템 계정에 /false 또는 /nologin 쉘이 부여된 경우" \
    "시스템 계정에 로그인이 가능한 쉘이 부여된 경우" \
    "Vul" \
    "로그인이 불필요한 계정에 쉘이 부여되었습니다. : ${bad_shells[*]}"
else
    print_result "1.9 로그인이 불필요한 계정 shell 제한" \
    "로그인이 불필요한 시스템 계정에 /false 또는 /nologin 쉘이 부여된 경우" \
    "시스템 계정에 로그인이 가능한 쉘이 부여된 경우" \
    "Good" \
    "불필요한 시스템 계정의 로그인이 적절히 제한되었습니다. : ${good_shells[*]}"
fi

#1.10 SU(Select User) 사용 제한
su_restriction_found=false
if [ -f /etc/pam.d/su ]; then
    if grep -qE "^\s*auth\s+required\s+pam_wheel.so" /etc/pam.d/su; then
        su_restriction_found=true
    fi
fi
perm=$(stat -c "%a" /bin/su)
group=$(stat -c "%G" /bin/su)
if [[ "$su_restriction_found" == true || ("$perm" == "4750" && "$group" == "wheel") ]]; then
    print_result "1.10 SU(Select User) 사용 제한" \
    "su 명령어를 특정 그룹(wheel)에 속한 사용자만 사용하도록 제한된 경우" \
    "su 명령어를 모든 사용자가 사용하도록 설정된 경우" \
    "Good" \
    "su 명령어 사용이 wheel 그룹으로 제한되어 있습니다."
else
    print_result "1.10 SU(Select User) 사용 제한" \
    "su 명령어를 특정 그룹(wheel)에 속한 사용자만 사용하도록 제한된 경우" \
    "su 명령어를 모든 사용자가 사용하도록 설정된 경우" \
    "Vul" \
    "su 명령어 사용이 모든 사용자에게 허용되어 있습니다."
fi

#1.11 계정이 존재하지 않는 GID 금지
# 점검에서 제외할 필수 시스템 그룹 목록 (Whitelist)
# 여기에 오탐으로 나오는 그룹들을 추가하여 관리
exclusion_list=(
    "tty" "disk" "kmem" "operator" "src" "shadow" "utmp" "sasl" 
    "staff" "users" "systemd-journal" "crontab" "sgx" "kvm" 
    "_ssh" "ssl-cert" "netdev" "avahi-autoipd" "avahi" "messagebus"
    "colord" "gdm" "sssd" "tss" "tcpdump" "uuidd" "systemd-oom"
    "fwupd-refresh" "nm-openvpn" "postdrop" "admin"
)

# /etc/passwd 에서 사용중인 모든 GID 목록 생성
used_gids=$(cut -d: -f4 /etc/passwd | sort -u)

unnecessary_groups=()
# /etc/group 파일 순회
while IFS=: read -r group_name x gid members; do
    # 그룹 멤버 목록이 비어 있는지 확인
    if [ -z "$members" ]; then
        gid_in_use=false
        # /etc/passwd의 주 그룹으로 사용되는 GID인지 확인
        for used_gid in $used_gids; do
            if [ "$gid" == "$used_gid" ]; then
                gid_in_use=true
                break
            fi
        done
        
        if [ "$gid_in_use" = false ]; then
            # 불필요 그룹 후보가 예외 목록(Whitelist)에 있는지 확인
            is_excluded=false
            for excluded_group in "${exclusion_list[@]}"; do
                if [ "$group_name" == "$excluded_group" ]; then
                    is_excluded=true
                    break
                fi
            done
            
            # 예외 목록에 없으면 최종적으로 불필요한 그룹으로 간주
            if [ "$is_excluded" = false ]; then
                unnecessary_groups+=("$group_name(GID:$gid)")
            fi
        fi
    fi
done < /etc/group

if [ ${#unnecessary_groups[@]} -gt 0 ]; then
    print_result "1.11 계정이 존재하지 않는 GID 금지" \
    "시스템 관리나 운용에 불필요한 그룹이 존재하지 않을 경우" \
    "시스템 관리나 운용에 불필요한 그룹(소속 계정이 없는 그룹)이 존재하는 경우" \
    "Vul" \
    "소속된 계정이 없는 불필요한 그룹이 존재합니다: ${unnecessary_groups[*]}"
else
    print_result "1.11 계정이 존재하지 않는 GID 금지" \
    "시스템 관리나 운용에 불필요한 그룹이 존재하지 않을 경우" \
    "시스템 관리나 운용에 불필요한 그룹(소속 계정이 없는 그룹)이 존재하는 경우" \
    "Good" \
    "소속된 계정이 없는 불필요한 그룹이 존재하지 않습니다."
fi

#1.12 동일한 UID 금지
# 중복된 UID 목록 찾기
duplicate_uids=$(cut -d: -f3 /etc/passwd | sort | uniq -d)
result_msg=""

if [ -n "$duplicate_uids" ]; then
    # 각 중복 UID에 대해 어떤 계정들이 사용하고 있는지 찾기
    for uid in $duplicate_uids; do
        users=$(awk -F: -v u="$uid" '$3==u {print $1}' /etc/passwd | xargs)
        result_msg+="동일 UID($uid)를 사용하는 계정: $users. "
    done
    print_result "1.12 동일한 UID 금지" \
    "동일한 UID로 설정된 사용자 계정이 존재하지 않을 경우" \
    "동일한 UID로 설정된 사용자 계정이 존재하는 경우" \
    "Vul" \
    "$result_msg"
else
    print_result "1.12 동일한 UID 금지" \
    "동일한 UID로 설정된 사용자 계정이 존재하지 않을 경우" \
    "동일한 UID로 설정된 사용자 계정이 존재하는 경우" \
    "Good" \
    "모든 계정이 고유한 UID를 사용합니다."
fi

echo ""
echo ""
echo ""
echo "==============================================================="
echo ""
echo "     2. 파일 시스템"
echo ""
echo "==============================================================="
echo ""

#2.1 사용자 UMASK 설정
umask_value=$(grep -v "^#" /etc/profile /etc/bashrc 2>/dev/null | grep -i umask | awk '{print $2}' | tail -1)
if [[ -n "$umask_value" && "$umask_value" -ge "022" ]]; then
     print_result "2.1 사용자 UMASK(User MASK) 설정" \
    "umask 값이 022 이상으로 설정된 경우" \
    "umask 값이 022보다 낮게 설정된 경우" \
    "Good" \
    "UMASK 값이 $umask_value 로 적절히 설정되었습니다."
else
     print_result "2.1 사용자 UMASK(User MASK) 설정" \
    "umask 값이 022 이상으로 설정된 경우" \
    "umask 값이 022보다 낮게 설정된 경우" \
    "Vul" \
    "UMASK 값이 $umask_value 로 안전하지 않게 설정되었습니다."
fi

#2.2 SUID, SGID 설정
vulnerable_files=()
files_to_check=(
    "/sbin/dump" "/usr/bin/lpq-lpd" "/usr/bin/newgrp"
    "/sbin/restore" "/usr/sbin/lpc" "/usr/bin/lpr"
    "/sbin/unix_chkpwd" "/usr/bin/lpr-lpd" "/usr/sbin/lpc-lpd"
    "/usr/bin/lprm" "/usr/bin/at" "/usr/sbin/traceroute"
    "/usr/bin/lpq" "/usr/bin/lprm-lpd"
)

for file_path in "${files_to_check[@]}"; do
    # 파일이 존재하고, SUID(u) 또는 SGID(g) 권한이 설정되어 있는지 확인
    if [ -f "$file_path" ] && { [ -u "$file_path" ] || [ -g "$file_path" ]; }; then
        vulnerable_files+=("$file_path")
    fi
done

if [ ${#vulnerable_files[@]} -gt 0 ]; then
    print_result "2.2 SUID, SGID 설정" \
    "불필요한 파일에 SUID, SGID가 설정되어 있지 않은 경우" \
    "불필요한 파일에 SUID, SGID가 설정되어 있는 경우" \
    "Vul" \
    "불필요한 SUID/SGID가 설정된 파일이 존재합니다: ${vulnerable_files[*]}"
else
    print_result "2.2 SUID, SGID 설정" \
    "불필요한 파일에 SUID, SGID가 설정되어 있지 않은 경우" \
    "불필요한 파일에 SUID, SGID가 설정되어 있는 경우" \
    "Good" \
    "제거가 권고된 주요 파일에 SUID/SGID가 설정되어 있지 않습니다."
fi

#2.3 /etc/(x)inetd.conf 파일 권한 설정
is_vulnerable=false
vuln_details=""
found_any=false

# 점검할 파일 목록
files_to_check=("/etc/inetd.conf" "/etc/xinetd.conf")

for file_path in "${files_to_check[@]}"; do
    if [ -f "$file_path" ]; then
        found_any=true
        owner=$(stat -c "%U" "$file_path")
        perm=$(stat -c "%a" "$file_path")

        # 소유자가 root가 아니거나, other에 쓰기 권한이 있는지 확인
        if [ "$owner" != "root" ] || [[ $((8#$perm & 2)) -ne 0 ]]; then
            is_vulnerable=true
            vuln_details+="취약 파일: $file_path (소유자: $owner, 권한: $perm) "
        fi
    fi
done

# /etc/xinetd.d 디렉터리 내부 파일 점검
if [ -d "/etc/xinetd.d" ]; then
    found_any=true
    # other에 쓰기 권한이 있는 파일을 검색
    writable_files=$(find /etc/xinetd.d -type f -perm -o+w 2>/dev/null)
    if [ -n "$writable_files" ]; then
        is_vulnerable=true
        vuln_details+="/etc/xinetd.d 디렉터리 내 일부 파일에 other 쓰기 권한이 있습니다. "
    fi
fi

if [ "$is_vulnerable" = true ]; then
    print_result "2.3 /etc/(x)inetd.conf 파일 권한 설정" \
    "관련 파일 및 디렉터리 소유자가 root이고, Other에 쓰기 권한이 없는 경우 " \
    "소유자가 root가 아니거나, Other에 쓰기 권한이 부여된 경우 " \
    "Vul" \
    "$vuln_details"
elif [ "$found_any" = false ]; then
    print_result "2.3 /etc/(x)inetd.conf 파일 권한 설정" \
    "관련 파일 및 디렉터리 소유자가 root이고, Other에 쓰기 권한이 없는 경우" \
    "소유자가 root가 아니거나, Other에 쓰기 권한이 부여된 경우" \
    "Manual" \
    "관련 서비스(inetd/xinetd)가 비활성화되어 있거나 관련 파일이 없어 안전합니다."
else
    print_result "2.3 /etc/(x)inetd.conf 파일 권한 설정" \
    "관련 파일 및 디렉터리 소유자가 root이고, Other에 쓰기 권한이 없는 경우 " \
    "소유자가 root가 아니거나, Other에 쓰기 권한이 부여된 경우 " \
    "Good" \
    "관련 설정 파일의 소유자 및 권한이 안전하게 설정되어 있습니다."
fi

#2.4 .history 파일 권한 설정
is_vulnerable=false
vuln_details=""

# /etc/passwd에서 로그인 쉘을 가진 사용자 목록(/bin/bash, /bin/sh 등)을 추출
# 형식: "사용자명:홈디렉터리"
user_homedirs=$(awk -F: '$7 ~ /\/bin\/(bash|sh|ksh|zsh)$/ {print $1 ":" $6}' /etc/passwd)

for user_home in $user_homedirs; do
    user=$(echo "$user_home" | cut -d: -f1)
    home=$(echo "$user_home" | cut -d: -f2)
    
    # 점검할 히스토리 파일 목록
    history_files=(".bash_history" ".history" ".sh_history")
    
    for hf in "${history_files[@]}"; do
        file_path="$home/$hf"
        if [ -f "$file_path" ]; then
            owner=$(stat -c "%U" "$file_path")
            perm=$(stat -c "%a" "$file_path")
            
            # 소유자가 해당 사용자가 아니거나, 권한이 600이 아닌 경우
            if [ "$owner" != "$user" ] || [ "$perm" != "600" ]; then
                is_vulnerable=true
                vuln_details+="취약 파일: $file_path (소유자:$owner, 권한:$perm) "
            fi
        fi
    done
done

if [ "$is_vulnerable" = true ]; then
    print_result "2.4 .history 파일 권한 설정" \
    "모든 사용자의 히스토리 파일 소유자가 본인이고, 권한이 600인 경우" \
    "히스토리 파일의 소유자 또는 권한이 잘못 설정된 경우" \
    "Vul" \
    "$vuln_details"
else
    print_result "2.4 .history 파일 권한 설정" \
    "모든 사용자의 히스토리 파일 소유자가 본인이고, 권한이 600인 경우" \
    "히스토리 파일의 소유자 또는 권한이 잘못 설정된 경우" \
    "Good" \
    "로그인 가능한 모든 사용자의 히스토리 파일 권한이 안전하게 설정되어 있습니다."
fi

#2.5 Crontab 파일 권한 설정 및 관리
is_vulnerable=false
vuln_details=""

# 1. /etc/crontab 파일 점검
if [ -f "/etc/crontab" ]; then
    owner=$(stat -c "%U" /etc/crontab)
    perm=$(stat -c "%a" /etc/crontab)
    # 소유자가 root가 아니거나, other에 쓰기 권한이 있는 경우
    if [ "$owner" != "root" ] || [[ $((8#$perm & 2)) -ne 0 ]]; then
        is_vulnerable=true
        vuln_details+="취약 파일: /etc/crontab (소유자:$owner, 권한:$perm) "
    fi
fi

# 2. cron 관련 디렉터리 내부 파일 점검
cron_dirs=("/etc/cron.hourly" "/etc/cron.daily" "/etc/cron.weekly" "/etc/cron.monthly" "/var/spool/cron")
for dir in "${cron_dirs[@]}"; do
    if [ -d "$dir" ]; then
        # 디렉터리 내에서 소유자가 root가 아니거나, other에 권한이 있는 파일을 검색
        vuln_files=$(find "$dir" -type f \( -not -user root -o -perm /007 \) 2>/dev/null)
        if [ -n "$vuln_files" ]; then
            is_vulnerable=true
            vuln_details+="$vuln_files "
        fi
    fi
done

if [ "$is_vulnerable" = true ]; then
    print_result "2.5 Crontab 파일 권한 설정 및 관리" \
    "Crontab 관련 파일의 소유자가 root이고, 타사용자 쓰기 권한이 없는 경우" \
    "소유자가 root가 아니거나 타사용자 쓰기 권한이 있는 경우" \
    "Vul" \
    "디렉터리 내에 권한이 취약한 파일이 존재합니다. : $vuln_details"
else
    # crontab 파일 내 스크립트 자체의 권한은 별도 점검이 필요함을 명시
    print_result "2.5 Crontab 파일 권한 설정 및 관리" \
    "Crontab 관련 파일의 소유자가 root이고, 타사용자 쓰기 권한이 없는 경우" \
    "소유자가 root가 아니거나 타사용자 쓰기 권한이 있는 경우" \
    "Good" \
    "cron 관련 디렉터리 및 설정 파일의 권한이 안전합니다. (※ crontab에 등록된 개별 스크립트 파일의 권한은 별도 점검이 필요합니다)"
fi

#2.6 /etc/profile 파일 권한 설정
file_path="/etc/profile"

if [ -f "$file_path" ]; then
    owner=$(stat -c "%U" "$file_path")
    perm=$(stat -c "%a" "$file_path")
    is_vulnerable=false
    vuln_details=""

    # 1. 소유자가 root인지 확인
    if [ "$owner" != "root" ]; then
        is_vulnerable=true
        vuln_details+="소유자가 'root'가 아님 (현재: $owner). "
    fi

    # 2. Other에 쓰기(w) 권한이 있는지 확인
    if [[ $((8#$perm & 2)) -ne 0 ]]; then
        is_vulnerable=true
        vuln_details+="Other(타사용자)에게 쓰기 권한이 부여됨. "
    fi

    if [ "$is_vulnerable" = true ]; then
        print_result "2.6 /etc/profile 파일 권한 설정" \
        "소유자가 root이고, Other(타사용자)에 쓰기 권한이 없는 경우 " \
        "소유자가 root가 아니거나, Other(타사용자)에 쓰기 권한이 있는 경우 " \
        "Vul" \
        "권한 설정 취약 (경로: $file_path, 권한: $perm, 소유자: $owner). 사유: $vuln_details"
    else
        print_result "2.6 /etc/profile 파일 권한 설정" \
        "소유자가 root이고, Other(타사용자)에 쓰기 권한이 없는 경우 " \
        "소유자가 root가 아니거나, Other(타사용자)에 쓰기 권한이 있는 경우 " \
        "Good" \
        "파일 권한이 안전합니다 (경로: $file_path, 권한: $perm, 소유자: $owner)."
    fi
else
    print_result "2.6 /etc/profile 파일 권한 설정" \
    "소유자가 root이고, Other(타사용자)에 쓰기 권한이 없는 경우 " \
    "소유자가 root가 아니거나, Other(타사용자)에 쓰기 권한이 있는 경우 " \
    "Good" \
    "$file_path 파일이 존재하지 않아 점검 대상이 아닙니다."
fi

#2.7 /etc/hosts 파일 권한 설정
file_path="/etc/hosts"

if [ -f "$file_path" ]; then
    owner=$(stat -c "%U" "$file_path")
    perm=$(stat -c "%a" "$file_path")
    is_vulnerable=false
    vuln_details=""

    # 1. 소유자가 root인지 확인 
    if [ "$owner" != "root" ]; then
        is_vulnerable=true
        vuln_details+="소유자가 'root'가 아님 (현재: $owner). "
    fi

    # 2. Other에 쓰기(w) 권한이 있는지 확인 
    if [[ $((8#$perm & 2)) -ne 0 ]]; then
        is_vulnerable=true
        vuln_details+="Other(타사용자)에게 쓰기 권한이 부여됨. "
    fi

    if [ "$is_vulnerable" = true ]; then
        print_result "2.7 /etc/hosts 파일 권한 설정" \
        "소유자가 root이고, Other(타사용자)에 쓰기 권한이 없는 경우" \
        "소유자가 root가 아니거나, Other(타사용자)에 쓰기 권한이 있는 경우" \
        "Vul" \
        "권한 설정 취약 (경로: $file_path, 권한: $perm, 소유자: $owner). 사유: $vuln_details"
    else
        print_result "2.7 /etc/hosts 파일 권한 설정" \
        "소유자가 root이고, Other(타사용자)에 쓰기 권한이 없는 경우" \
        "소유자가 root가 아니거나, Other(타사용자)에 쓰기 권한이 있는 경우" \
        "Good" \
        "파일 권한이 안전합니다 (경로: $file_path, 권한: $perm, 소유자: $owner)."
    fi
else
    print_result "2.7 /etc/hosts 파일 권한 설정" \
    "소유자가 root이고, Other(타사용자)에 쓰기 권한이 없는 경우" \
    "소유자가 root가 아니거나, Other(타사용자)에 쓰기 권한이 있는 경우" \
    "Good" \
    "$file_path 파일이 존재하지 않아 점검 대상이 아닙니다."
fi

#2.8 /etc/issue 파일 권한 설정
is_vulnerable=false
vuln_details=""

# 점검할 파일 목록
files_to_check=("/etc/issue" "/etc/issue.net")

for file_path in "${files_to_check[@]}"; do
    if [ -f "$file_path" ]; then
        owner=$(stat -c "%U" "$file_path")
        perm=$(stat -c "%a" "$file_path")

        # 소유자가 root가 아니거나, other에 쓰기 권한이 있는지 확인
        if [ "$owner" != "root" ] || [[ $((8#$perm & 2)) -ne 0 ]]; then
            is_vulnerable=true
            vuln_details+="취약 파일: $file_path (소유자: $owner, 권한: $perm) "
        fi
    fi
done

if [ "$is_vulnerable" = true ]; then
    print_result "2.8 /etc/issue 파일 권한 설정" \
    "관련 파일(/etc/issue, /etc/issue.net) 소유자가 root이고, Other에 쓰기 권한이 없는 경우" \
    "소유자가 root가 아니거나, Other에 쓰기 권한이 있는 경우" \
    "Vul" \
    "$vuln_details"
else
    print_result "2.8 /etc/issue 파일 권한 설정" \
    "관련 파일(/etc/issue, /etc/issue.net) 소유자가 root이고, Other에 쓰기 권한이 없는 경우" \
    "소유자가 root가 아니거나, Other에 쓰기 권한이 있는 경우" \
    "Good" \
    "관련 파일들의 권한이 모두 안전하게 설정되어 있습니다."
fi

#2.9 사용자 홈 디렉터리 및 파일 관리
is_vulnerable=false
vuln_details=""

# /etc/passwd에서 root를 제외하고 로그인 쉘을 가진 사용자 목록을 추출
user_homedirs=$(awk -F: '$1 != "root" && $7 ~ /\/bin\/(bash|sh|ksh|zsh)$/ {print $1 ":" $6}' /etc/passwd)

for user_home in $user_homedirs; do
    user=$(echo "$user_home" | cut -d: -f1)
    home=$(echo "$user_home" | cut -d: -f2)
    
    # 1. 홈 디렉터리 존재 여부 확인
    if [ ! -d "$home" ]; then
        is_vulnerable=true
        vuln_details+="사용자 '$user'의 홈 디렉터리($home)가 존재하지 않습니다. "
        continue # 다음 사용자로 넘어감
    fi
    
    # 2. 홈 디렉터리가 '/' 인지 확인
    if [ "$home" == "/" ]; then
        is_vulnerable=true
        vuln_details+="사용자 '$user'의 홈 디렉터리가 루트 디렉터리('/')로 설정되어 있습니다. "
    fi
    
    # 3. 홈 디렉터리의 권한 확인 (other에 r,w,x 권한이 없어야 함)
    perm=$(stat -c "%a" "$home")
    if [[ $((8#$perm & 7)) -ne 0 ]]; then
        is_vulnerable=true
        vuln_details+="사용자 '$user'의 홈 디렉터리($home) 권한이 취약합니다 (권한: $perm). "
    fi
    
    # 4. 홈 디렉터리 내 환경 설정 파일 권한 확인 (other에 쓰기 권한이 없어야 함)
    # .profile, .bashrc 등 '.'으로 시작하는 파일 대상
    writable_files=$(find "$home" -maxdepth 1 -type f -name ".*" -perm -o+w 2>/dev/null)
    if [ -n "$writable_files" ]; then
        is_vulnerable=true
        vuln_details+="사용자 '$user'의 홈 디렉터리 내 설정 파일에 other 쓰기 권한이 있습니다 ($writable_files). "
    fi
done

if [ "$is_vulnerable" = true ]; then
    print_result "2.9 사용자 홈 디렉터리 및 파일 관리" \
    "홈 디렉터리가 존재하고, 타사용자에 대한 권한이 적절히 제한된 경우" \
    "홈 디렉터리가 없거나, 존재하지 않거나, 권한 설정이 취약한 경우" \
    "Vul" \
    "$vuln_details"
else
    print_result "2.9 사용자 홈 디렉터리 및 파일 관리" \
    "홈 디렉터리가 존재하고, 타사용자에 대한 권한이 적절히 제한된 경우" \
    "홈 디렉터리가 없거나, 존재하지 않거나, 권한 설정이 취약한 경우" \
    "Good" \
    "모든 일반 사용자의 홈 디렉터리 및 관련 파일 권한이 안전하게 설정되어 있습니다."
fi

#2.10 중요 디렉터리 파일 권한 설정
is_vulnerable=false
vuln_details=""

# 점검할 주요 디렉터리 목록 (가이드라인 p.44 참조)
dirs_to_check=("/sbin" "/etc" "/bin" "/usr/bin" "/usr/sbin" "/usr/lbin")

for dir_path in "${dirs_to_check[@]}"; do
    if [ -L "$dir_path" ]; then
        continue
    fi
    if [ -d "$dir_path" ]; then
        owner=$(stat -c "%U" "$dir_path")
        perm=$(stat -c "%a" "$dir_path")

        # 1. 소유자가 'root'도 아니고 'bin'도 아닌 경우
        if [ "$owner" != "root" ] && [ "$owner" != "bin" ]; then
            is_vulnerable=true
            vuln_details+="취약 디렉터리: $dir_path (사유: 소유자 아님, 현재: $owner) "
        fi

        # 2. Other에 쓰기(w) 권한이 있는지 확인
        if [[ $((8#$perm & 2)) -ne 0 ]]; then
            is_vulnerable=true
            vuln_details+="취약 디렉터리: $dir_path (사유: Other 쓰기 권한 부여됨, 권한: $perm) "
        fi
    fi
done

if [ "$is_vulnerable" = true ]; then
    print_result "2.10 중요 디렉터리 파일 권한 설정" \
    "주요 디렉터리가 root 또는 bin 소유이고, Other(타사용자)에 쓰기 권한이 없는 경우" \
    "소유자가 root 또는 bin이 아니거나, Other(타사용자)에 쓰기 권한이 있는 경우" \
    "Vul" \
    "$vuln_details"
else
    print_result "2.10 중요 디렉터리 파일 권한 설정" \
    "주요 디렉터리가 root 또는 bin 소유이고, Other(타사용자)에 쓰기 권한이 없는 경우" \
    "소유자가 root 또는 bin이 아니거나, Other(타사용자)에 쓰기 권한이 있는 경우" \
    "Good" \
    "주요 시스템 디렉터리의 권한이 안전하게 설정되어 있습니다."
fi

#2.11 PATH 환경변수 설정
is_vulnerable=false
vuln_details=""

# 점검할 설정 파일 목록
config_files=("/etc/profile" "/root/.bash_profile" "/root/.profile" "/root/.bashrc")

for file_path in "${config_files[@]}"; do
    if [ -f "$file_path" ]; then
        # 주석 처리되지 않은 PATH 설정 라인을 찾음
        path_lines=$(grep -v '^\s*#' "$file_path" | grep 'export\s\+PATH')
        if [ -n "$path_lines" ]; then
            # PATH 값에서 현재 디렉터리(.)의 위치가 부적절한지 확인
            # 1. 맨 앞에 오는 경우 (.:/path)
            # 2. 중간에 오는 경우 (/path:.:/path)
            # 3. 빈 값으로 오는 경우 (::)
            if echo "$path_lines" | grep -qE 'PATH="?\.:|:\.:|::'; then
                is_vulnerable=true
                vuln_details+="취약 설정 파일: $file_path "
            fi
        fi
    fi
done

if [ "$is_vulnerable" = true ]; then
    print_result "2.11 PATH 환경변수 설정" \
    "PATH 환경변수에 '.'이 없거나, 있더라도 맨 뒤에 위치한 경우" \
    "PATH 환경변수에 '.'이 맨 앞이나 중간에 포함되어 있는 경우" \
    "Vul" \
    "root 계정의 PATH 설정에 현재 디렉터리('.')가 안전하지 않은 위치에 포함되어 있습니다. ${vuln_details}"
else
    print_result "2.11 PATH 환경변수 설정" \
    "PATH 환경변수에 '.'이 없거나, 있더라도 맨 뒤에 위치한 경우" \
    "PATH 환경변수에 '.'이 맨 앞이나 중간에 포함되어 있는 경우" \
    "Good" \
    "root 계정의 PATH 환경 변수에 현재 디렉터리('.')가 안전하게 설정되어 있습니다."
fi

#2.12 FTP 접근제어 파일 권한 설정
is_vulnerable=false
vuln_details=""
files_checked=false

# 점검할 FTP 접근제어 파일 목록 (가이드라인 p.47 참조)
files_to_check=(
    "/etc/ftpusers"
    "/etc/ftpd/ftpusers"
    "/etc/vsftpd/ftpusers"
    "/etc/vsftpd/user_list"
    "/etc/vsftpd.user_list"
)

for file_path in "${files_to_check[@]}"; do
    if [ -f "$file_path" ]; then
        files_checked=true
        owner=$(stat -c "%U" "$file_path")
        perm=$(stat -c "%a" "$file_path")

        # 1. 소유자가 root가 아닌 경우
        if [ "$owner" != "root" ]; then
            is_vulnerable=true
            vuln_details+="취약 파일: $file_path (사유: 소유자 아님, 현재: $owner) "
        fi

        # 2. Other에 쓰기(w) 권한이 있는지 확인
        if [[ $((8#$perm & 2)) -ne 0 ]]; then
            is_vulnerable=true
            vuln_details+="취약 파일: $file_path (사유: Other 쓰기 권한 부여됨, 권한: $perm) "
        fi
    fi
done

if [ "$is_vulnerable" = true ]; then
    print_result "2.12 FTP 접근제어 파일 권한 설정" \
    "FTP 접근제어 파일의 소유자가 root이고, Other(타사용자)에 쓰기 권한이 없는 경우" \
    "소유자가 root가 아니거나, Other(타사용자)에 쓰기 권한이 있는 경우" \
    "Vul" \
    "$vuln_details"
elif [ "$files_checked" = false ]; then
    print_result "2.12 FTP 접근제어 파일 권한 설정" \
    "FTP 접근제어 파일의 소유자가 root이고, Other(타사용자)에 쓰기 권한이 없는 경우" \
    "소유자가 root가 아니거나, Other(타사용자)에 쓰기 권한이 있는 경우" \
    "Manual" \
    "점검 대상 FTP 접근제어 파일이 존재하지 않습니다."
else
    print_result "2.12 FTP 접근제어 파일 권한 설정" \
    "FTP 접근제어 파일의 소유자가 root이고, Other(타사용자)에 쓰기 권한이 없는 경우" \
    "소유자가 root가 아니거나, Other(타사용자)에 쓰기 권한이 있는 경우" \
    "Good" \
    "점검된 모든 FTP 접근제어 파일의 권한이 안전하게 설정되어 있습니다."
fi

#2.13 root 원격 접근제어 파일 권한 설정
is_vulnerable=false
vuln_details=""

# 점검할 파일 목록 (가이드라인 p.49 참조)
files_to_check=("/etc/securetty" "/etc/pam.d/login")

for file_path in "${files_to_check[@]}"; do
    if [ -f "$file_path" ]; then
        owner=$(stat -c "%U" "$file_path")
        perm=$(stat -c "%a" "$file_path")

        # 1. 소유자가 root가 아닌 경우
        if [ "$owner" != "root" ]; then
            is_vulnerable=true
            vuln_details+="취약 파일: $file_path (사유: 소유자 아님, 현재: $owner) "
        fi

        # 2. Other에 쓰기(w) 권한이 있는지 확인
        if [[ $((8#$perm & 2)) -ne 0 ]]; then
            is_vulnerable=true
            vuln_details+="취약 파일: $file_path (사유: Other 쓰기 권한 부여됨, 권한: $perm) "
        fi
    fi
done

if [ "$is_vulnerable" = true ]; then
    print_result "2.13 root 원격 접근제어 파일 권한 설정" \
    "관련 파일의 소유자가 root이고, Other(타사용자)에 쓰기 권한이 없는 경우" \
    "소유자가 root가 아니거나, Other(타사용자)에 쓰기 권한이 있는 경우" \
    "Vul" \
    "$vuln_details"
else
    print_result "2.13 root 원격 접근제어 파일 권한 설정" \
    "관련 파일의 소유자가 root이고, Other(타사용자)에 쓰기 권한이 없는 경우" \
    "소유자가 root가 아니거나, Other(타사용자)에 쓰기 권한이 있는 경우" \
    "Good" \
    "root 원격 접근제어 관련 파일의 권한이 안전하게 설정되어 있습니다."
fi

#2.14 NFS 접근제어 파일 권한 설정
file_path="/etc/exports"

if [ -f "$file_path" ]; then
    owner=$(stat -c "%U" "$file_path")
    perm=$(stat -c "%a" "$file_path")
    is_vulnerable=false
    vuln_details=""

    # 1. 소유자가 root인지 확인
    if [ "$owner" != "root" ]; then
        is_vulnerable=true
        vuln_details+="소유자가 'root'가 아님 (현재: $owner). "
    fi

    # 2. Group에 쓰기(w) 권한이 있는지 확인 (8진수 권한 값에서 20과 비트 AND 연산)
    if [[ $((8#$perm & 20)) -ne 0 ]]; then
        is_vulnerable=true
        vuln_details+="Group(그룹)에 쓰기 권한이 부여됨. "
    fi
    
    # 3. Other에 쓰기(w) 권한이 있는지 확인 (8진수 권한 값에서 2와 비트 AND 연산)
    if [[ $((8#$perm & 2)) -ne 0 ]]; then
        is_vulnerable=true
        vuln_details+="Other(타사용자)에 쓰기 권한이 부여됨. "
    fi

    if [ "$is_vulnerable" = true ]; then
        print_result "2.14 NFS 접근제어 파일 권한 설정" \
        "/etc/exports 파일의 소유자가 root이고, Group 및 Other에 쓰기 권한이 없는 경우" \
        "소유자가 root가 아니거나, Group 또는 Other에 쓰기 권한이 있는 경우" \
        "Vul" \
        "권한 설정 취약 (경로: $file_path, 권한: $perm, 소유자: $owner). 사유: $vuln_details"
    else
        print_result "2.14 NFS 접근제어 파일 권한 설정" \
        "/etc/exports 파일의 소유자가 root이고, Group 및 Other에 쓰기 권한이 없는 경우" \
        "소유자가 root가 아니거나, Group 또는 Other에 쓰기 권한이 있는 경우" \
        "Good" \
        "파일 권한이 안전합니다 (경로: $file_path, 권한: $perm, 소유자: $owner)."
    fi
else
    print_result "2.14 NFS 접근제어 파일 권한 설정" \
    "/etc/exports 파일의 소유자가 root이고, Group 및 Other에 쓰기 권한이 없는 경우" \
    "소유자가 root가 아니거나, Group 또는 Other에 쓰기 권한이 있는 경우" \
    "Manual" \
    "$file_path 파일이 존재하지 않아 NFS를 사용하지 않는 것으로 보입니다."
fi

#2.15 /etc/services 파일 권한 설정
file_path="/etc/services"

if [ -f "$file_path" ]; then
    owner=$(stat -c "%U" "$file_path")
    perm=$(stat -c "%a" "$file_path")
    is_vulnerable=false
    vuln_details=""

    # 1. 소유자가 root인지 확인
    if [ "$owner" != "root" ]; then
        is_vulnerable=true
        vuln_details+="소유자가 'root'가 아님 (현재: $owner). "
    fi

    # 2. Group에 쓰기(w) 권한이 있는지 확인 (8진수 20)
    if [[ $((8#$perm & 8#20)) -ne 0 ]]; then
        is_vulnerable=true
        vuln_details+="Group(그룹)에 쓰기 권한이 부여됨. "
    fi
    
    # 3. Other에 쓰기(w) 권한이 있는지 확인 (8진수 2)
    if [[ $((8#$perm & 2)) -ne 0 ]]; then
        is_vulnerable=true
        vuln_details+="Other(타사용자)에 쓰기 권한이 부여됨. "
    fi

    if [ "$is_vulnerable" = true ]; then
        print_result "2.15 /etc/services 파일 권한 설정" \
        "/etc/services 파일의 소유자가 root이고, Group 및 Other에 쓰기 권한이 없는 경우" \
        "소유자가 root가 아니거나, Group 또는 Other에 쓰기 권한이 있는 경우" \
        "Vul" \
        "권한 설정 취약 (경로: $file_path, 권한: $perm, 소유자: $owner). 사유: $vuln_details"
    else
        print_result "2.15 /etc/services 파일 권한 설정" \
        "/etc/services 파일의 소유자가 root이고, Group 및 Other에 쓰기 권한이 없는 경우" \
        "소유자가 root가 아니거나, Group 또는 Other에 쓰기 권한이 있는 경우" \
        "Good" \
        "파일 권한이 안전합니다 (경로: $file_path, 권한: $perm, 소유자: $owner)."
    fi
else
    print_result "2.15 /etc/services 파일 권한 설정" \
    "/etc/services 파일의 소유자가 root이고, Group 및 Other에 쓰기 권한이 없는 경우" \
    "소유자가 root가 아니거나, Group 또는 Other에 쓰기 권한이 있는 경우" \
    "Good" \
    "$file_path 파일이 존재하지 않아 점검 대상이 아닙니다."
fi

#2.16 부팅 스크립트 파일 권한 설정
is_vulnerable=false
vuln_details=""

# 1. /etc/inittab 파일 점검
if [ -f "/etc/inittab" ]; then
    perm=$(stat -c "%a" /etc/inittab)
    # Other에 쓰기(w) 권한이 있는지 확인
    if [[ $((8#$perm & 2)) -ne 0 ]]; then
        is_vulnerable=true
        vuln_details+="취약 파일: /etc/inittab (권한: $perm) "
    fi
fi

# 2. 부팅 스크립트 디렉터리 점검 (심볼릭 링크를 따라 실제 파일의 권한을 확인)
# SysVinit 및 systemd 호환 경로 포함
dirs_to_scan=("/etc/rc.d/" "/etc/init.d/")
vulnerable_scripts=$(find -L ${dirs_to_scan[@]} -type f -perm -o+w 2>/dev/null)

if [ -n "$vulnerable_scripts" ]; then
    is_vulnerable=true
    # xargs를 사용해 출력 결과를 한 줄로 만듦
    vuln_details+="Other 쓰기 권한이 부여된 부팅 스크립트: $(echo $vulnerable_scripts | xargs)"
fi

if [ "$is_vulnerable" = true ]; then
    print_result "2.16 부팅 스크립트 파일 권한 설정" \
    "부팅 관련 스크립트 파일에 Other(타사용자) 쓰기 권한이 없는 경우" \
    "부팅 관련 스크립트 파일에 Other(타사용자) 쓰기 권한이 있는 경우" \
    "Vul" \
    "$vuln_details"
else
    print_result "2.16 부팅 스크립트 파일 권한 설정" \
    "부팅 관련 스크립트 파일에 Other(타사용자) 쓰기 권한이 없는 경우" \
    "부팅 관련 스크립트 파일에 Other(타사용자) 쓰기 권한이 있는 경우" \
    "Good" \
    "주요 부팅 스크립트 파일의 권한이 안전하게 설정되어 있습니다."
fi

#2.17 /etc/hosts.allow, /etc/hosts.deny 설정
deny_file="/etc/hosts.deny"
is_vulnerable=true
details=""

if [ -f "$deny_file" ]; then
    # 주석(#)을 제외하고, 공백을 무시하며 "ALL:ALL" 패턴이 있는지 확인
    if grep -v '^\s*#' "$deny_file" | grep -qE "ALL\s*:\s*ALL"; then
        is_vulnerable=false
    fi
fi

if [ "$is_vulnerable" = true ]; then
    # RHEL/CentOS 8 이상에서는 iptables/firewalld를 사용하므로 해당 내용 안내
    details="기본 차단(ALL:ALL) 정책이 /etc/hosts.deny 파일에 설정되어 있지 않습니다. 최신 OS(RHEL 8 이상)는 iptables 또는 firewalld로 대체되었을 수 있으므로 방화벽 설정을 확인해야 합니다."
    print_result "2.17 /etc/hosts.allow, /etc/hosts.deny 설정" \
    "/etc/hosts.deny 파일에 'ALL: ALL'을 설정하여 기본 차단 정책을 적용한 경우" \
    "기본 차단 정책('ALL: ALL')이 적용되지 않은 경우" \
    "Vul" \
    "$details"
else
    details="/etc/hosts.deny 파일에 'ALL: ALL' 설정이 적용되어 있습니다. /etc/hosts.allow에 허용 정책이 올바른지 확인하십시오."
    print_result "2.17 /etc/hosts.allow, /etc/hosts.deny 설정" \
    "/etc/hosts.deny 파일에 'ALL: ALL'을 설정하여 기본 차단 정책을 적용한 경우" \
    "기본 차단 정책('ALL: ALL')이 적용되지 않은 경우" \
    "Good" \
    "$details"
fi

#2.18 기타 중요 파일 권한 설정
print_result "2.18 기타 중요 파일 권한 설정" \
"시스템 운영상 중요한 파일들의 접근 권한이 적절히 설정된 경우" \
"중요 파일에 타사용자 쓰기 권한이 부여된 경우" \
"Manual" \
"가이드라인에 따라 이 항목은 특정 점검 파일이 지정되지 않아 자동 점검에서 제외됩니다. "

#2.19 at 파일 소유자 및 권한 설정
is_vulnerable=false
vuln_details=""
files_checked=false

# 점검할 at 접근제어 파일 목록 (가이드라인 p.55 참조)
files_to_check=("/etc/at.allow" "/etc/at.deny")

for file_path in "${files_to_check[@]}"; do
    if [ -f "$file_path" ]; then
        files_checked=true
        owner=$(stat -c "%U" "$file_path")
        perm=$(stat -c "%a" "$file_path")

        # 1. 소유자가 root가 아닌 경우
        if [ "$owner" != "root" ]; then
            is_vulnerable=true
            vuln_details+="취약 파일: $file_path (사유: 소유자 아님, 현재: $owner). "
        fi

        # 2. 권한이 640을 초과하는 경우 (8진수 비교)
        if [ $((8#$perm)) -gt $((8#640)) ]; then
            is_vulnerable=true
            vuln_details+="취약 파일: $file_path (사유: 권한 초과, 현재: $perm). "
        fi
    fi
done

if [ "$is_vulnerable" = true ]; then
    print_result "2.19 at 파일 소유자 및 권한 설정" \
    "관련 파일의 소유자가 root이고 권한이 640 이하인 경우" \
    "소유자가 root가 아니거나 권한이 640을 초과하는 경우" \
    "Vul" \
    "$vuln_details"
elif [ "$files_checked" = false ]; then
    print_result "2.19 at 파일 소유자 및 권한 설정" \
    "관련 파일의 소유자가 root이고 권한이 640 이하인 경우" \
    "소유자가 root가 아니거나 권한이 640을 초과하는 경우" \
    "Manual" \
    "점검 대상 at 접근제어 파일(/etc/at.allow, /etc/at.deny)이 존재하지 않습니다."
else
    print_result "2.19 at 파일 소유자 및 권한 설정" \
    "관련 파일의 소유자가 root이고 권한이 640 이하인 경우" \
    "소유자가 root가 아니거나 권한이 640을 초과하는 경우" \
    "Good" \
    "점검된 at 접근제어 파일의 권한이 안전하게 설정되어 있습니다."
fi

#2.20 hosts.lpd 파일 소유자 및 권한 설정
file_path="/etc/hosts.lpd"

if [ -f "$file_path" ]; then
    owner=$(stat -c "%U" "$file_path")
    perm=$(stat -c "%a" "$file_path")
    is_vulnerable=false
    vuln_details=""

    # 1. 소유자가 root가 아닌 경우
    if [ "$owner" != "root" ]; then
        is_vulnerable=true
        vuln_details+="소유자가 'root'가 아님 (현재: $owner). "
    fi

    # 2. 권한이 600을 초과하는 경우 (8진수 비교)
    if [ $((8#$perm)) -gt $((8#600)) ]; then
        is_vulnerable=true
        vuln_details+="권한이 600을 초과함 (현재: $perm). "
    fi

    if [ "$is_vulnerable" = true ]; then
        print_result "2.20 hosts.lpd 파일 소유자 및 권한 설정" \
        "/etc/hosts.lpd 파일의 소유자가 root이고 권한이 600 이하인 경우" \
        "소유자가 root가 아니거나 권한이 600을 초과하는 경우" \
        "Vul" \
        "권한 설정 취약 (경로: $file_path). 사유: $vuln_details"
    else
        print_result "2.20 hosts.lpd 파일 소유자 및 권한 설정" \
        "/etc/hosts.lpd 파일의 소유자가 root이고 권한이 600 이하인 경우" \
        "소유자가 root가 아니거나 권한이 600을 초과하는 경우" \
        "Good" \
        "파일 권한이 안전합니다 (경로: $file_path, 권한: $perm, 소유자: $owner)."
    fi
else
    print_result "2.20 hosts.lpd 파일 소유자 및 권한 설정" \
    "/etc/hosts.lpd 파일의 소유자가 root이고 권한이 600 이하인 경우" \
    "소유자가 root가 아니거나 권한이 600을 초과하는 경우" \
    "Manual" \
    "$file_path 파일이 존재하지 않습니다."
fi

#2.21 /etc/(r)syslog.conf 파일 소유자 및 권한 설정
file_path=""
if [ -f "/etc/rsyslog.conf" ]; then
    file_path="/etc/rsyslog.conf"
elif [ -f "/etc/syslog.conf" ]; then
    file_path="/etc/syslog.conf"
fi

if [ -n "$file_path" ]; then
    owner=$(stat -c "%U" "$file_path")
    perm=$(stat -c "%a" "$file_path")
    is_vulnerable=false
    vuln_details=""

    # 1. 소유자가 root가 아닌 경우
    if [ "$owner" != "root" ]; then
        is_vulnerable=true
        vuln_details+="소유자가 'root'가 아님 (현재: $owner). "
    fi

    # 2. 권한이 640을 초과하는 경우 (8진수 비교)
    if [ $((8#$perm)) -gt $((8#640)) ]; then
        is_vulnerable=true
        vuln_details+="권한이 640을 초과함 (현재: $perm). "
    fi

    if [ "$is_vulnerable" = true ]; then
        print_result "2.21 /etc/(r)syslog.conf 파일 소유자 및 권한 설정" \
        "/(r)syslog.conf 파일의 소유자가 root이고 권한이 640 이하인 경우" \
        "소유자가 root가 아니거나 권한이 640을 초과하는 경우" \
        "Vul" \
        "권한 설정 취약 (경로: $file_path). 사유: $vuln_details"
    else
        print_result "2.21 /etc/(r)syslog.conf 파일 소유자 및 권한 설정" \
        "/(r)syslog.conf 파일의 소유자가 root이고 권한이 640 이하인 경우" \
        "소유자가 root가 아니거나 권한이 640을 초과하는 경우" \
        "Good" \
        "파일 권한이 안전합니다 (경로: $file_path, 권한: $perm, 소유자: $owner)."
    fi
else
    print_result "2.21 /etc/(r)syslog.conf 파일 소유자 및 권한 설정" \
    "/(r)syslog.conf 파일의 소유자가 root이고 권한이 640 이하인 경우" \
    "소유자가 root가 아니거나 권한이 640을 초과하는 경우" \
    "Good" \
    "점검 대상 로그 설정 파일(/etc/rsyslog.conf 또는 /etc/syslog.conf)이 존재하지 않습니다."
fi

#2.22 World Writable 파일 점검
vuln_files=""

# /etc/passwd에서 로그인 쉘을 가진 사용자들의 홈 디렉터리 목록을 추출
user_homedirs=$(awk -F: '$7 ~ /\/bin\/(bash|sh|ksh|zsh)$/ {print $6}' /etc/passwd)

for home in $user_homedirs; do
    if [ -d "$home" ]; then
        # 해당 홈 디렉터리 내에서 other에 쓰기 권한(-perm -002)이 있는 파일을 검색
        found_in_home=$(find "$home" -type f -perm -002 2>/dev/null)
        if [ -n "$found_in_home" ]; then
            # xargs를 사용하여 발견된 파일 목록을 한 줄로 합침
            vuln_files+="$(echo $found_in_home | xargs) "
        fi
    fi
done

if [ -n "$vuln_files" ]; then
    print_result "2.22 World Writable 파일 점검" \
    "World Writable 파일이 존재하지 않거나, 존재 시 용도를 확인하고 있는 경우" \
    "확인되지 않은 World Writable 파일이 존재하는 경우" \
    "Vul" \
    "사용자 홈 디렉터리 내에 World Writable 파일이 존재합니다: $vuln_files"
else
    print_result "2.22 World Writable 파일 점검" \
    "World Writable 파일이 존재하지 않거나, 존재 시 용도를 확인하고 있는 경우" \
    "확인되지 않은 World Writable 파일이 존재하는 경우" \
    "Good" \
    "사용자 홈 디렉터리 내에 World Writable 파일이 발견되지 않았습니다."
fi

#2.23 /dev에 존재하지 않는 device 파일 점검]
non_device_files=$(find /dev -type f 2>/dev/null)

if [ -n "$non_device_files" ]; then
    # xargs를 사용해 발견된 파일 목록을 한 줄로 합침
    vuln_files_list=$(echo "$non_device_files" | xargs)
    print_result "2.23 /dev에 존재하지 않는 device 파일 점검" \
    "/dev 디렉터리에 일반 파일(non-device file)이 존재하지 않는 경우" \
    "/dev 디렉터리에 일반 파일(non-device file)이 존재하는 경우" \
    "Vul" \
    "/dev 디렉터리에 일반 파일이 존재합니다: $vuln_files_list"
else
    print_result "2.23 /dev에 존재하지 않는 device 파일 점검" \
    "/dev 디렉터리에 일반 파일(non-device file)이 존재하지 않는 경우" \
    "/dev 디렉터리에 일반 파일(non-device file)이 존재하는 경우" \
    "Good" \
    "/dev 디렉터리 내에 일반 파일(non-device file)이 발견되지 않았습니다."
fi


echo ""
echo ""
echo ""
echo "==============================================================="
echo ""
echo "     3. 네트워크 서비스"
echo ""
echo "==============================================================="
echo ""


#3.1 RPC(Remote Procedure Call) 서비스 제한
is_vulnerable=false
vuln_details=""

# 1. (x)inetd를 통한 RPC 서비스 점검
# 가이드라인(p.61)에 명시된 점검 대상 서비스 목록
rpc_inetd_services="rstatd|rusersd|sadmind|walld|sprayd|rwalld|kcms_server|cachefsd|rexd"
# /etc/inetd.conf 또는 /etc/xinetd.d/ 내 활성화된 파일에서 패턴 검색
if [ -f /etc/inetd.conf ]; then
    found_services=$(grep -v '^\s*#' /etc/inetd.conf | egrep "$rpc_inetd_services")
    if [ -n "$found_services" ]; then
        is_vulnerable=true
        vuln_details+="/etc/inetd.conf 에 불필요한 RPC 서비스가 활성화되어 있습니다. "
    fi
fi
if [ -d /etc/xinetd.d ]; then
    # disable = yes 라인이 없는 (활성화된) 설정 파일을 찾음
    found_services=$(find /etc/xinetd.d -type f -print0 | xargs -0 grep -L "disable\s*=\s*yes" | egrep "$rpc_inetd_services")
    if [ -n "$found_services" ]; then
        is_vulnerable=true
        vuln_details+="/etc/xinetd.d 에 불필요한 RPC 서비스가 활성화되어 있습니다. "
    fi
fi


# 2. 독립 실행형 RPC 서비스 점검 (rpcbind/portmap)
# systemd 사용 시스템
if command -v systemctl >/dev/null; then
    if systemctl is-enabled rpcbind.service >/dev/null 2>&1 || systemctl is-enabled rpcbind.socket >/dev/null 2>&1; then
        is_vulnerable=true
        vuln_details+="rpcbind 서비스가 활성화되어 있습니다. "
    fi
# chkconfig 사용 시스템
elif command -v chkconfig >/dev/null; then
    if chkconfig --list | grep -E "rpcbind|portmap" | grep -q ":on"; then
        is_vulnerable=true
        vuln_details+="rpcbind 또는 portmap 서비스가 활성화되어 있습니다. "
    fi
fi


if [ "$is_vulnerable" = true ]; then
    print_result "3.1 RPC(Remote Procedure Call) 서비스 제한" \
    "불필요한 RPC 서비스가 비활성화되어 있는 경우" \
    "불필요한 RPC 서비스가 활성화되어 있는 경우" \
    "Vul" \
    "$vuln_details"
else
    print_result "3.1 RPC(Remote Procedure Call) 서비스 제한" \
    "불필요한 RPC 서비스가 비활성화되어 있는 경우" \
    "불필요한 RPC 서비스가 활성화되어 있는 경우" \
    "Good" \
    "불필요한 RPC 서비스가 비활성화되어 있습니다."
fi

#3.2 NFS(Network File System) 제한
# NFS 서비스의 활성화 여부를 점검하고, 활성화 시 설정 파일(/etc/exports)의 보안성을 확인합니다.
nfs_running=false
is_vulnerable=false
details=""

# systemd를 사용하는 최신 시스템에서 nfs-server 서비스 활성화 여부 확인
if command -v systemctl >/dev/null; then
    if systemctl is-active --quiet nfs-server.service; then
        nfs_running=true
    fi
# ps 명령어로 nfsd 데몬 직접 확인 (구버전 호환)
elif ps -ef | grep -v "grep" | grep -q "[n]fsd"; then
    nfs_running=true
fi

if [ "$nfs_running" = true ]; then
    # NFS 서비스가 실행 중일 때 /etc/exports 파일 점검
    if [ -f "/etc/exports" ]; then
         # 주석을 제외하고 'everyone' 옵션이 있는지 확인
        if grep -v '^\s*#' /etc/exports | grep -q "everyone"; then
            is_vulnerable=true
            details="NFS 서비스가 실행 중이며, /etc/exports 파일에 누구나 접근 가능한 'everyone' 공유가 존재합니다."
         else
            # everyone 옵션이 없으므로 양호
            details="NFS 서비스가 활성화되어 있으나, 'everyone' 공유 설정이 없어 안전합니다."
        fi
     else
        # 서비스는 실행중이나 exports 파일이 없어 공유가 설정되지 않은 상태 -> 양호
         details="NFS 서비스가 실행 중이지만, 설정 파일(/etc/exports)이 없어 공유가 설정되지 않았습니다."
    fi
else
    # NFS 서비스가 비활성화되어 있는 경우
    details="NFS 서비스가 비활성화되어 있습니다."
fi

# --- 4. 최종 결과 출력 ---
if [ "$nfs_running" = false ]; then
    # 서비스 비활성화 시 -> Manual
    print_result "3.2 NFS(Network File System) 제한" \
    "NFS 서비스를 사용하지 않거나, 사용 시 everyone 공유가 없는 경우" \
    "NFS 서비스가 실행 중이며, everyone 공유가 존재하는 경우" \
    "Manual" \
    "$details"
elif [ "$is_vulnerable" = true ]; then
    # 서비스 활성화 + 취약점 발견 시 -> Vul
    print_result "3.2 NFS(Network File System) 제한" \
    "NFS 서비스를 사용하지 않거나, 사용 시 everyone 공유가 없는 경우" \
    "NFS 서비스가 실행 중이며, everyone 공유가 존재하는 경우" \
    "Vul" \
    "$details"
else
    # 서비스 활성화 + 취약점 없음 -> Good
    print_result "3.2 NFS(Network File System) 제한" \
    "NFS 서비스를 사용하지 않거나, 사용 시 everyone 공유가 없는 경우" \
    "NFS 서비스가 실행 중이며, everyone 공유가 존재하는 경우" \
    "Good" \
    "$details"
fi

#3.3 Automountd 서비스 제거
is_vulnerable=false

# systemd를 사용하는 최신 시스템에서 autofs 서비스 활성화 여부 확인
if command -v systemctl >/dev/null; then
    if systemctl is-active --quiet autofs.service; then
        is_vulnerable=true
    fi
# ps 명령어로 automount 또는 autofs 데몬 직접 확인 (구버전 호환)
elif ps -ef | grep -v "grep" | grep -qE "[a]utomount|[a]utofs"; then
    is_vulnerable=true
fi

if [ "$is_vulnerable" = true ]; then
    print_result "3.3 Automountd 서비스 제거" \
    "Automountd (autofs) 서비스가 비활성화되어 있는 경우" \
    "Automountd (autofs) 서비스가 활성화되어 있는 경우" \
    "Vul" \
    "Automountd (autofs) 서비스가 실행 중입니다."
else
    print_result "3.3 Automountd 서비스 제거" \
    "Automountd (autofs) 서비스가 비활성화되어 있는 경우" \
    "Automountd (autofs) 서비스가 활성화되어 있는 경우" \
    "Good" \
    "Automountd (autofs) 서비스가 비활성화되어 있습니다."
fi

#3.4 NIS(Network Information Service) 제한
nis_processes=""
# 가이드라인(p.66)에 명시된 NIS 관련 프로세스 목록
nis_pattern="ypserv|ypbind|rpc.yppasswdd|ypxfrd|rpc.ypupdated"

# 실행 중인 프로세스 목록에서 NIS 관련 데몬을 검색 (grep 자체 프로세스는 제외)
running_nis_services=$(ps -ef | grep -v "grep" | grep -iE "$nis_pattern")

if [ -n "$running_nis_services" ]; then
    # xargs를 사용해 발견된 프로세스 목록을 한 줄로 정리
    details="활성화된 NIS/NIS+ 관련 서비스가 발견되었습니다: $(echo $running_nis_services | xargs)"
    print_result "3.4 NIS(Network Information Service) 제한" \
    "NIS, NIS+ 관련 서비스(ypserv, ypbind 등)가 비활성화된 경우" \
    "NIS, NIS+ 관련 서비스가 활성화된 경우" \
    "Vul" \
    "$details"
else
    details="NIS/NIS+ 관련 서비스가 비활성화되어 있습니다."
    print_result "3.4 NIS(Network Information Service) 제한" \
    "NIS, NIS+ 관련 서비스(ypserv, ypbind 등)가 비활성화된 경우" \
    "NIS, NIS+ 관련 서비스가 활성화된 경우" \
    "Good" \
    "$details"
fi

#3.5 'r' commands 서비스 제거
# rsh, rlogin, rexec 등 'r' 계열 서비스의 활성화 여부와 관련 파일의 보안성을 점검합니다.
is_vulnerable=false
vuln_details=""

# 1. (x)inetd를 통한 'r' 계열 서비스 활성화 점검
r_services=("shell" "login" "exec") # rsh, rlogin, rexec
# /etc/inetd.conf 확인
if [ -f /etc/inetd.conf ]; then
    for service in "${r_services[@]}"; do
        if grep -v '^\s*#' /etc/inetd.conf | grep -q "$service"; then
            is_vulnerable=true
            vuln_details+="$service 서비스가 /etc/inetd.conf 에서 활성화되어 있습니다. "
        fi
    done
fi
# /etc/xinetd.d 확인
for service in "rsh" "rlogin" "rexec"; do
    if [ -f "/etc/xinetd.d/$service" ]; then
        # disable = yes 라인이 없는 (활성화된) 경우
        if ! grep -q 'disable\s*=\s*yes' "/etc/xinetd.d/$service"; then
            is_vulnerable=true
            vuln_details+="$service 서비스가 /etc/xinetd.d 에서 활성화되어 있습니다. "
        fi
    fi
done

# 2. 신뢰 관계 파일 점검 (/etc/hosts.equiv 및 .rhosts)
# /etc/hosts.equiv 파일에 '+' 설정이 있는지 확인
if [ -f /etc/hosts.equiv ]; then
    if grep -v '^\s*#' /etc/hosts.equiv | grep -q '^\s*+'; then
        is_vulnerable=true
        vuln_details+="/etc/hosts.equiv 파일에 '+' 설정이 존재하여 보안에 매우 취약합니다. "
    fi
fi
# 모든 사용자의 홈 디렉터리에서 .rhosts 파일 내 '+' 설정 확인
user_homes=$(awk -F: '{print $6}' /etc/passwd | sort -u)
for home in $user_homes; do
    if [ -d "$home" ] && [ -f "$home/.rhosts" ]; then
        if grep -v '^\s*#' "$home/.rhosts" | grep -q '^\s*+'; then
            is_vulnerable=true
            vuln_details+="$home/.rhosts 파일에 '+' 설정이 존재하여 보안에 매우 취약합니다. "
        fi
    fi
done


if [ "$is_vulnerable" = true ]; then
    print_result "3.5 'r' commands 서비스 제거" \
    "'r' 계열 서비스(rsh, rlogin, rexec)가 비활성화 되어 있는 경우" \
    "'r' 계열 서비스가 활성화 되어 있거나, 관련 파일 설정이 취약한 경우" \
    "Vul" \
    "$vuln_details"
else
    print_result "3.5 'r' commands 서비스 제거" \
    "'r' 계열 서비스(rsh, rlogin, rexec)가 비활성화 되어 있는 경우" \
    "'r' 계열 서비스가 활성화 되어 있거나, 관련 파일 설정이 취약한 경우" \
    "Good" \
    "'r' 계열 서비스가 비활성화되어 있고, 관련 신뢰 파일에 취약한 설정이 없습니다."
fi

#3.6 불필요한 서비스 제거
vuln_services=()

# 점검할 서비스와 포트 목록 (가이드라인 p.72-73 참조)
declare -A service_ports=(
    ["echo"]=7
    ["discard"]=9
    ["daytime"]=13
    ["chargen"]=19
    ["ftp-data"]=20
    ["ftp"]=21
    ["telnet"]=23
    ["time"]=37
    ["tftp"]=69
    ["finger"]=79
    ["sftp"]=115
    ["nntp"]=119
    ["netbios-ns"]=137
    ["netbios-dgm"]=138
    ["netbios-ssn"]=139
    ["ldap"]=389
    ["printer"]=515
    ["talk"]=517
    ["ntalk"]=518
    ["uucp"]=540
    ["ldaps"]=636
    ["ingreslock"]=1524
    ["nfs"]=2049
)

# 현재 LISTEN 상태인 TCP/UDP 포트 목록을 추출
listening_ports=$(ss -lntu | awk 'NR>1 {print $5}' | sed 's/.*://' | sort -u)

for service in "${!service_ports[@]}"; do
    port=${service_ports[$service]}
    if echo "$listening_ports" | grep -q "^$port$"; then
        vuln_services+=("$service($port)")
    fi
done

if [ ${#vuln_services[@]} -gt 0 ]; then
    print_result "3.6 불필요한 서비스 제거" \
    "가이드라인에서 제거를 권고하는 불필요한 서비스가 비활성화된 경우" \
    "제거를 권고하는 불필요한 서비스가 활성화된 경우" \
    "Vul" \
    "불필요한 서비스가 활성화되어 있습니다: ${vuln_services[*]}"
else
    print_result "3.6 불필요한 서비스 제거" \
    "가이드라인에서 제거를 권고하는 불필요한 서비스가 비활성화된 경우" \
    "제거를 권고하는 불필요한 서비스가 활성화된 경우" \
    "Good" \
    "가이드라인의 블랙리스트에 포함된 불필요한 서비스가 발견되지 않았습니다."
fi

#3.7 서비스 Banner 관리
is_vulnerable=false
vuln_details=""

# 1. SSH 배너 점검 (/etc/ssh/sshd_config)
# Banner 옵션이 주석 처리되어 있거나 설정되지 않은 경우 기본 배너가 노출될 수 있음
if [ -f /etc/motd ]; then
    if ! grep -q "^\s*Banner" /etc/ssh/sshd_config; then
        is_vulnerable=true
        vuln_details+="SSH 서비스 배너가 별도로 설정되지 않아 버전 정보가 노출될 수 있습니다. "
    fi
fi

# 2. FTP 배너 점검 (vsftpd)
if [ -f /etc/vsftpd/vsftpd.conf ]; then
    # ftpd_banner 옵션이 주석 처리되어 있거나 설정되지 않은 경우
    if ! grep -q "^\s*ftpd_banner" /etc/vsftpd/vsftpd.conf; then
        is_vulnerable=true
        vuln_details+="FTP(vsftpd) 서비스 배너가 별도로 설정되지 않아 버전 정보가 노출될 수 있습니다. "
    fi
fi

if [ -f /etc/welcome.msg ]; then
    # ftpd_banner 옵션이 주석 처리되어 있거나 설정되지 않은 경우
    if ! grep -q "^\s*ftpd_banner" /etc/welcome.msg; then
        is_vulnerable=true
        vuln_details+="FTP(vsftpd) 서비스 배너가 별도로 설정되지 않아 버전 정보가 노출될 수 있습니다. "
    fi
fi

# 3. SMTP 배너 점검 (sendmail)
if [ -f /etc/mail/sendmail.cf ]; then
    # SmtpGreetingMessage에 버전 변수($v)가 포함된 경우
    if grep '^\s*O\s*SmtpGreetingMessage=' /etc/mail/sendmail.cf | grep -q '\$v'; then
        is_vulnerable=true
        vuln_details+="SMTP(sendmail) 서비스 배너에 버전 정보가 포함되어 있습니다. "
    fi
fi

# 4. Telnet 배너 점검 (/etc/issue.net)
# /etc/issue.net 파일에 OS 정보가 포함된 경우
if [ -f /etc/issue.net ]; then
    if grep -qE "Ubuntu|CentOS|Red Hat|Debian|Welcome to" /etc/issue.net; then
        is_vulnerable=true
        vuln_details+="Telnet(/etc/issue.net) 서비스 배너에 시스템 정보가 노출될 수 있습니다. "
    fi
fi


if [ "$is_vulnerable" = true ]; then
    print_result "3.7 서비스 Banner 관리" \
    "서비스 배너에 시스템 버전 등 민감한 정보가 노출되지 않는 경우" \
    "서비스 배너에 시스템 버전 등 민감한 정보가 노출되는 경우" \
    "Vul" \
    "$vuln_details"
else
    print_result "3.7 서비스 Banner 관리" \
    "서비스 배너에 시스템 버전 등 민감한 정보가 노출되지 않는 경우" \
    "서비스 배너에 시스템 버전 등 민감한 정보가 노출되는 경우" \
    "Good" \
    "주요 서비스의 배너 설정이 양호합니다."
fi

#3.8 session timeout 설정
timeout_value=-1 # TMOUT 설정 값을 저장할 변수, -1은 '설정 없음'을 의미

# /etc/profile 및 /etc/profile.d/ 내 파일에서 TMOUT 설정을 확인
# 주석 처리되지 않은 마지막 TMOUT 설정을 기준으로 함
if [ -f /etc/profile ]; then
    # -h 옵션으로 파일명 없이 내용만, 2>/dev/null로 오류 숨김
    tmout_setting=$(grep -v '^\s*#' /etc/profile /etc/profile.d/*.sh 2>/dev/null | grep 'TMOUT\s*=\s*' | tail -1)
    if [ -n "$tmout_setting" ]; then
        # 'TMOUT=300' 에서 숫자 부분만 추출
        timeout_value=$(echo "$tmout_setting" | cut -d'=' -f2 | tr -d '[:space:]')
    fi
fi

# TMOUT 값이 설정되지 않았거나, 숫자가 아니거나, 300을 초과하는 경우 취약
if [[ "$timeout_value" -eq -1 ]] || ! [[ "$timeout_value" =~ ^[0-9]+$ ]] || [[ "$timeout_value" -gt 300 ]]; then
    print_result "3.8 session timeout 설정" \
    "세션 타임아웃이 300초 (5분) 이하로 설정된 경우" \
    "세션 타임아웃이 설정되지 않았거나 300초를 초과하는 경우" \
    "Vul" \
    "세션 타임아웃이 설정되지 않았거나 300초(5분)를 초과합니다. (현재 설정: ${timeout_value:--1})"
else
    print_result "3.8 session timeout 설정" \
    "세션 타임아웃이 300초 (5분) 이하로 설정된 경우" \
    "세션 타임아웃이 설정되지 않았거나 300초를 초과하는 경우" \
    "Good" \
    "세션 타임아웃이 $timeout_value 초로 안전하게 설정되어 있습니다."
fi

#3.9 root 계정 원격 접속 제한
permit_root_login=$(sshd -T | grep -i permitrootlogin | awk '{print $2}')
if [[ "$permit_root_login" == "no" ]]; then
    print_result "3.9 root 계정 원격 접속 제한" \
    "root 계정의 원격 접속(SSH)이 차단된 경우" \
    "root 계정의 원격 접속(SSH)이 허용된 경우" \
    "Good" \
    "root의 원격 SSH 접속이 차단되어 있습니다 (PermitRootLogin no)."
else
    print_result "3.9 root 계정 원격 접속 제한" \
    "root 계정의 원격 접속(SSH)이 차단된 경우" \
    "root 계정의 원격 접속(SSH)이 허용된 경우" \
    "Vul" \
    "root의 원격 SSH 접속이 허용되어 있습니다 (PermitRootLogin ${permit_root_login})."
fi

#3.10 DNS 보안 버전 패치
named_process=$(ps -ef | grep -v "grep" | grep "[n]amed")

if [ -n "$named_process" ]; then
    # named (BIND) 프로세스가 실행 중인 경우
    bind_version_output="버전 확인 불가"
    # 'named' 명령어 경로를 찾아 -v 옵션으로 버전 확인
    if command -v named >/dev/null; then
        bind_version_output=$($(command -v named) -v 2>&1)
    fi
    
    print_result "3.10 DNS 보안 버전 패치" \
    "DNS (BIND) 서비스를 사용하지 않거나 최신 보안 패치가 적용된 버전을 사용하는 경우" \
    "DNS (BIND) 서비스를 사용하며 구버전 또는 보안 패치가 적용되지 않은 버전을 사용하는 경우" \
    "Vul" \
    "DNS(BIND) 서비스가 실행 중입니다. ($bind_version_output). 가이드라인(p.81-82)의 CVE 목록을 참고하여 최신 보안 패치가 적용되었는지 확인해야 합니다."
else
    # named (BIND) 프로세스가 실행 중이 아닌 경우
    print_result "3.10 DNS 보안 버전 패치" \
    "DNS (BIND) 서비스를 사용하지 않거나 최신 보안 패치가 적용된 버전을 사용하는 경우" \
    "DNS (BIND) 서비스를 사용하며 구버전 또는 보안 패치가 적용되지 않은 버전을 사용하는 경우" \
    "Good" \
    "DNS(BIND) 서비스가 비활성화되어 있습니다."
fi


echo ""
echo ""
echo ""
echo "==============================================================="
echo ""
echo "     4. 로그 관리"
echo ""
echo "==============================================================="
echo ""

#4.1 (x)inetd Services 로그 설정
print_result "4.1 (x)inetd Services 로그 설정" \
"TCP 연결 요구 시 로그를 기록하도록 설정된 경우" \
"TCP 연결에 대한 로그를 기록하도록 설정되어 있지 않은 경우" \
"Manual" \
"가이드라인에 따라 이 항목은 '해당 OS는 체크리스트에 포함하지 않음'으로 명시되어 있어 자동 점검에서 제외됩니다."

#4.2 시스템 로그 설정
is_vulnerable=false
vuln_details=""

# 1. su 로그 설정 점검
# /etc/login.defs 에 SULOG_FILE이 설정되어 있거나,
# /(r)syslog 설정에 authpriv 로그 규칙이 있는지 확인
sulog_conf_exists=$(grep -v '^\s*#' /etc/login.defs | grep -c "SULOG_FILE")

# /etc/rsyslog.d/ 디렉터리까지 포함하여 authpriv 규칙 검색
authpriv_conf_exists=$(grep -vh '^\s*#' /etc/rsyslog.conf /etc/syslog.conf /etc/rsyslog.d/*.conf 2>/dev/null | grep -c "authpriv\.\*")

if [[ "$sulog_conf_exists" -eq 0 && "$authpriv_conf_exists" -eq 0 ]]; then
    is_vulnerable=true
    vuln_details+="su(사용자 전환) 활동에 대한 로그 설정이 없습니다. "
fi

# 주요 syslog 규칙 점검 (notice, alert, emerg)
critical_log_rules=$(grep -vh '^\s*#' /etc/rsyslog.conf /etc/syslog.conf /etc/rsyslog.d/*.conf 2>/dev/null | grep -cE "\*\.(alert|emerg|notice)")
if [[ "$critical_log_rules" -eq 0 ]]; then
    is_vulnerable=true
    vuln_details+="시스템 중요 이벤트(alert, emerg, notice 등급)에 대한 로그 설정이 없습니다. "
fi

# 3. 주요 로그 파일 권한 점검 (other 쓰기 권한)
log_files=(
    "/var/log/wtmp"      # 성공한 로그인/로그아웃 기록
    "/var/run/utmp"      # 현재 로그인된 사용자 정보
    "/var/log/btmp"      # 실패한 로그인 기록
    "/var/log/syslog"    # 우분투의 주요 시스템 로그
    "/var/log/lastlog"   # 모든 사용자의 마지막 로그인 기록
    "/var/log/auth.log"  # 우분투의 주요 인증/보안 로그
    "/var/log/secure"    # CentOS/RHEL 계열 보안 로그 (호환성을 위해 포함)
    "/var/log/messages"  # 구버전 시스템 로그 (호환성을 위해 포함)
)
for log_file in "${log_files[@]}"; do
    if [ -f "$log_file" ]; then
        perm=$(stat -c "%a" "$log_file")
        # Other에 쓰기(w) 권한이 있는지 확인
        if [[ $((8#$perm & 2)) -ne 0 ]]; then
            is_vulnerable=true
            vuln_details+="$log_file 파일에 Other(타사용자) 쓰기 권한이 부여되어 있습니다. "
        fi
    fi
done


# 최종 결과 출력 (수정 없음)
if [ "$is_vulnerable" = true ]; then
    print_result "4.2 시스템 로그 설정" \
    "su 로그, 주요 시스템 로그, 로그 파일 권한이 모두 적절히 설정된 경우" \
    "su 로그, 주요 시스템 로그, 로그 파일 권한 중 하나라도 설정이 미흡한 경우" \
    "Vul" \
    "$vuln_details"
else
    print_result "4.2 시스템 로그 설정" \
    "su 로그, 주요 시스템 로그, 로그 파일 권한이 모두 적절히 설정된 경우" \
    "su 로그, 주요 시스템 로그, 로그 파일 권한 중 하나라도 설정이 미흡한 경우" \
    "Good" \
    "시스템 로그 관련 설정(su 로그, syslog 규칙, 파일 권한)이 안전합니다."
fi

#4.3 로그 저장 주기
print_result "4.3 로그 저장 주기" \
"로그가 관련 법규에 따라 최소 6개월 이상 보관되며, 정기적으로 백업 및 검토되는 경우 " \
"로그 보관, 백업, 검토 정책이 수립되어 있지 않거나 미흡한 경우" \
"Manual" \
"로그 보관 주기, 백업 정책, 정기 검토 여부는 담당자 인터뷰를 통해 확인해야 하는 정책 항목입니다. "


echo ""
echo ""
echo ""
echo "==============================================================="
echo ""
echo "     5. 주요 응용 설정"
echo ""
echo "==============================================================="
echo ""

#5.1 FTP 서비스 사용자 제한
# vsftpd 설정 파일(/etc/vsftpd/vsftpd.conf)을 기준으로 합니다.

# 먼저 FTP 서비스(port 21)가 활성화되어 있는지 확인
if ! ss -lnt | grep -q ":21\s"; then
    print_result "5.1 FTP 서비스 사용자 제한" \
    "root 계정 FTP 접속차단, umask 077 설정, Anonymous FTP 비활성화가 모두 적용된 경우" \
    "root 접속 허용, umask 설정 미흡, Anonymous FTP 활성화 중 하나라도 해당되는 경우" \
    "Good" \
    "FTP 서비스(port 21)가 비활성화되어 있습니다."
else
    is_vulnerable=false
    vuln_details=""
    vsftpd_conf="/etc/vsftpd/vsftpd.conf"

    if [ -f "$vsftpd_conf" ]; then
        # 1. root 계정 접속 제한 점검
        # /etc/ftpusers 파일에 'root'가 명시되어 있어야 함 (vsftpd 기본 설정)
        if [ ! -f /etc/ftpusers ] || ! grep -q "^\s*root" /etc/ftpusers; then
            is_vulnerable=true
            vuln_details+="root 계정의 FTP 접속이 차단되지 않았습니다. (/etc/ftpusers 확인 필요) "
        fi
        
        # 2. FTP umask 설정 점검
        # local_umask가 077로 설정되어 있는지 확인
        umask_setting=$(grep -v '^\s*#' "$vsftpd_conf" | grep "local_umask")
        if [[ -z "$umask_setting" ]] || [[ ! "$umask_setting" =~ umask=077 ]]; then
            is_vulnerable=true
            vuln_details+="FTP 파일 생성 umask가 077로 설정되지 않았습니다. (현재: ${umask_setting:-미설정}) "
        fi

        # 3. Anonymous FTP 제한 점검
        # anonymous_enable이 NO로 설정되어 있는지 확인
        anon_setting=$(grep -v '^\s*#' "$vsftpd_conf" | grep "anonymous_enable")
        if [[ -z "$anon_setting" ]] || [[ ! "$anon_setting" =~ enable=NO ]]; then
            is_vulnerable=true
            vuln_details+="Anonymous FTP 접속이 허용되어 있습니다. (현재: ${anon_setting:-미설정}) "
        fi

    else
        is_vulnerable=true
        vuln_details+="FTP 서비스는 활성화되어 있으나, 주 설정 파일(/etc/vsftpd/vsftpd.conf)을 찾을 수 없어 상세 점검이 불가능합니다."
    fi

    if [ "$is_vulnerable" = true ]; then
        print_result "5.1 FTP 서비스 사용자 제한" \
        "root 계정 FTP 접속차단, umask 077 설정, Anonymous FTP 비활성화가 모두 적용된 경우" \
        "root 접속 허용, umask 설정 미흡, Anonymous FTP 활성화 중 하나라도 해당되는 경우" \
        "Vul" \
        "$vuln_details"
    else
        print_result "5.1 FTP 서비스 사용자 제한" \
        "root 계정 FTP 접속차단, umask 077 설정, Anonymous FTP 비활성화가 모두 적용된 경우" \
        "root 접속 허용, umask 설정 미흡, Anonymous FTP 활성화 중 하나라도 해당되는 경우" \
        "Good" \
        "FTP 서비스(vsftpd)의 주요 보안 설정(root 접속, umask, 익명 접속)이 안전합니다."
    fi
fi

#5.2 SNMP 서비스 설정
# 1. SNMP 서비스(snmpd) 활성화 여부 확인
snmp_running=false
if command -v systemctl >/dev/null; then
    if systemctl is-active --quiet snmpd.service; then
        snmp_running=true
    fi
elif ps -ef | grep -v "grep" | grep -q "[s]nmpd"; then
    snmp_running=true
fi

if [ "$snmp_running" = false ]; then
    print_result "5.2 SNMP 서비스 설정" \
    "SNMP 서비스를 사용하지 않거나, Community String이 'public', 'private'이 아닌 경우" \
    "SNMP 서비스를 사용하며 Community String으로 'public' 또는 'private'을 사용하는 경우" \
    "Manual" \
    "SNMP 서비스가 비활성화되어 있습니다."
else
    # 2. SNMP 서비스가 실행 중일 때 설정 파일 점검
    snmpd_conf="/etc/snmp/snmpd.conf"
    is_vulnerable=false
    
    if [ -f "$snmpd_conf" ]; then
        # 주석 처리되지 않은 라인에서 'public' 또는 'private' Community String을 사용하는지 확인
        # 일반적인 설정: rocommunity public, com2sec notConfigUser default public 등
        if grep -v '^\s*#' "$snmpd_conf" | grep -qE "\s(public|private)\s*($|#)"; then
            is_vulnerable=true
        fi
    else
        # 서비스는 실행 중이나 설정 파일이 없는 경우, 기본값 사용 가능성이 높음
        is_vulnerable=true
        vuln_details="SNMP 서비스는 실행 중이나, 주 설정 파일($snmpd_conf)을 찾을 수 없습니다."
    fi

    if [ "$is_vulnerable" = true ]; then
        if [ -z "$vuln_details" ]; then
            vuln_details="SNMP 서비스가 실행 중이며, 설정 파일($snmpd_conf)에 기본 Community String(public/private)을 사용하고 있습니다."
        fi
        print_result "5.2 SNMP 서비스 설정" \
        "SNMP 서비스를 사용하지 않거나, Community String이 'public', 'private'이 아닌 경우" \
        "SNMP 서비스를 사용하며 Community String으로 'public' 또는 'private'을 사용하는 경우" \
        "Vul" \
        "$vuln_details"
    else
        print_result "5.2 SNMP 서비스 설정" \
        "SNMP 서비스를 사용하지 않거나, Community String이 'public', 'private'이 아닌 경우" \
        "SNMP 서비스를 사용하며 Community String으로 'public' 또는 'private'을 사용하는 경우" \
        "Good" \
        "SNMP 서비스가 실행 중이나, 설정 파일에서 기본 Community String이 발견되지 않았습니다."
    fi
fi

#5.3 SMTP 서비스 설정 (Postfix 버전)
# 1. SMTP 서비스(port 25) 활성화 여부 확인
if ! ss -lnt | grep -q ":25\s"; then
    print_result "5.3 SMTP 서비스 설정" \
    "Postfix의 보안 옵션이 설정되고 릴레이 기능이 제한된 경우" \
    "위 보안 설정 중 하나라도 누락된 경우" \
    "Manual" \
    "SMTP 서비스(port 25)가 비활성화되어 있습니다."
else
    # 2. SMTP 서비스가 실행 중일 때 Postfix 설정 파일 점검
    postfix_cf="/etc/postfix/main.cf"
    is_vulnerable=false
    vuln_details=""

    if [ -f "$postfix_cf" ]; then
        # Postfix의 VRFY/EXPN 명령어 제한 점검
        # 'disable_vrfy_command = yes' 설정이 없는 경우 취약
        if ! grep -qE "^\s*disable_vrfy_command\s*=\s*yes" "$postfix_cf"; then
            is_vulnerable=true
            vuln_details+="사용자 정보 확인 명령어(VRFY/EXPN) 제한이 설정되지 않았습니다. "
        fi

        # Postfix의 릴레이 방지 설정 점검
        # smtpd_relay_restrictions 설정 값 확인
        relay_settings=$(grep -v '^\s*#' "$postfix_cf" | grep "smtpd_relay_restrictions")

        # 설정이 아예 없거나, reject_unauth_destination이 없는 경우 취약
        if [ -z "$relay_settings" ] || ! echo "$relay_settings" | grep -q "reject_unauth_destination"; then
            is_vulnerable=true
            vuln_details+="SMTP 릴레이 제한(reject_unauth_destination) 설정이 미흡합니다. "
        fi
    else
        is_vulnerable=true 
        vuln_details="SMTP 서비스는 활성화되어 있으나, Postfix 주 설정 파일($postfix_cf)을 찾을 수 없습니다."
    fi

    # 3. 최종 결과 출력
    if [ "$is_vulnerable" = true ]; then
        print_result "5.3 SMTP 서비스 설정" \
        "Postfix의 보안 옵션이 설정되고 릴레이 기능이 제한된 경우" \
        "위 보안 설정 중 하나라도 누락된 경우" \
        "Vul" \
        "$vuln_details"
    else
        print_result "5.3 SMTP 서비스 설정" \
        "Postfix의 보안 옵션이 설정되고 릴레이 기능이 제한된 경우" \
        "위 보안 설정 중 하나라도 누락된 경우" \
        "Good" \
        "SMTP(Postfix) 서비스의 주요 보안 설정이 안전합니다."
    fi
fi

#5.4 DNS(Domain Name Service) 보안 설정
# 1. DNS(named) 서비스 활성화 여부 확인
named_running=false
if command -v systemctl >/dev/null; then
    if systemctl is-active --quiet named.service 2>/dev/null || systemctl is-active --quiet bind9.service 2>/dev/null; then
        named_running=true
    fi
elif ps -ef | grep -v "grep" | grep -q "[n]amed"; then
    named_running=true
fi

if [ "$named_running" = false ]; then
    print_result "5.4 DNS(Domain Name Service) 보안 설정" \
    "DNS 서비스 Zone Transfer가 허가된 IP에만 가능하도록 설정된 경우" \
    "Zone Transfer가 제한 없이 가능하게 설정된 경우" \
    "Manual" \
    "DNS(BIND) 서비스가 비활성화되어 있습니다."
else
    # 2. BIND 서비스가 실행 중일 때 설정 파일 점검
    named_conf="/etc/named.conf"
    is_vulnerable=false
    
    if [ -f "$named_conf" ]; then
        # 주석(//, #)을 제외하고 'allow-transfer' 설정 확인
        # 설정이 없거나 'any;'로 설정된 경우 취약
        if ! grep -v -E '^\s*(#|//)' "$named_conf" | grep -q "allow-transfer"; then
            is_vulnerable=true
            vuln_details="DNS(BIND) 서비스가 실행 중이나, named.conf 파일에 'allow-transfer' 설정이 없어 Zone Transfer에 취약합니다."
        elif grep -v -E '^\s*(#|//)' "$named_conf" | grep "allow-transfer" | grep -q "any;"; then
            is_vulnerable=true
            vuln_details="DNS(BIND) 서비스의 'allow-transfer' 옵션이 'any'로 설정되어 Zone Transfer에 취약합니다."
        fi
    else
        is_vulnerable=true # 상태를 단정할 수 없으므로 취약으로 보고 수동 점검 유도
        vuln_details="DNS(BIND) 서비스는 활성화되어 있으나, 주 설정 파일($named_conf)을 찾을 수 없습니다."
    fi

    if [ "$is_vulnerable" = true ]; then
        print_result "5.4 DNS(Domain Name Service) 보안 설정" \
        "DNS 서비스 Zone Transfer가 허가된 IP에만 가능하도록 설정된 경우" \
        "Zone Transfer가 제한 없이 가능하게 설정된 경우" \
        "Vul" \
        "$vuln_details"
    else
        print_result "5.4 DNS(Domain Name Service) 보안 설정" \
        "DNS 서비스 Zone Transfer가 허가된 IP에만 가능하도록 설정된 경우" \
        "Zone Transfer가 제한 없이 가능하게 설정된 경우" \
        "Good" \
        "DNS(BIND) 서비스 Zone Transfer 설정이 안전합니다."
    fi
fi

#5.5 SWAT(Samba Web Administration Tool) 보안 설정
is_vulnerable=false
vuln_details=""
found_any=false # 점검 대상 설정 파일을 하나라도 찾았는지 확인하는 플래그

# 1. /etc/inetd.conf 파일에서 swat 서비스 활성화 여부 확인
if [ -f /etc/inetd.conf ]; then
    found_any=true # 파일을 찾았으므로 플래그를 true로 설정
    if grep -v '^\s*#' /etc/inetd.conf | grep -q "swat"; then
        is_vulnerable=true
        vuln_details+="[취약] /etc/inetd.conf 파일에 swat 서비스가 활성화되어 있습니다. "
    fi
fi

# 2. /etc/xinetd.d/swat 파일에서 서비스 활성화 여부 확인
swat_xinetd_conf="/etc/xinetd.d/swat"
if [ -f "$swat_xinetd_conf" ]; then
    found_any=true # 파일을 찾았으므로 플래그를 true로 설정
    # 'disable = yes' 라인이 없거나 주석 처리된 경우, 서비스가 활성화된 것으로 간주
    if ! grep -q '^\s*disable\s*=\s*yes' "$swat_xinetd_conf"; then
        is_vulnerable=true
        vuln_details+="[취약] /etc/xinetd.d/swat 설정으로 서비스가 활성화되어 있습니다. "
    fi
fi

# 3. 최종 상태에 따라 결과 출력
if [ "$is_vulnerable" = true ]; then
    print_result "5.5 SWAT(Samba Web Administration Tool) 보안 설정" \
    "SWAT 서비스가 비활성화 되어 있는 경우" \
    "SWAT 서비스가 활성화 되어 있는 경우" \
    "Vul" \
    "$vuln_details"
elif [ "$found_any" = false ]; then
    # 점검할 설정 파일이 하나도 없는 경우 -> 서비스가 없으므로 안전
    print_result "5.5 SWAT(Samba Web Administration Tool) 보안 설정" \
    "SWAT 서비스가 비활성화 되어 있는 경우" \
    "SWAT 서비스가 활성화 되어 있는 경우" \
    "Good" \
    "SWAT 서비스 관련 설정 파일이 존재하지 않습니다."
else
    # 파일은 있지만, 취약점이 발견되지 않은 경우
    print_result "5.5 SWAT(Samba Web Administration Tool) 보안 설정" \
    "SWAT 서비스가 비활성화 되어 있는 경우" \
    "SWAT 서비스가 활성화 되어 있는 경우" \
    "Good" \
    "SWAT 서비스가 모든 설정 파일에서 비활성화되어 있습니다."
fi

#5.6 x-server 접속 제한 설정
# 모든 사용자의 자동 실행 파일 내에 'xhost +' 설정이 있는지 점검합니다.
is_vulnerable=false
vuln_details=""

# 점검할 자동 실행 파일 목록 (가이드라인 p.102 참조)
files_to_check=(
    ".login" ".profile" ".cshrc" 
    ".xinitrc" ".xsession" ".bash_profile" ".bashrc"
)

# /etc/passwd에서 모든 사용자 홈 디렉터리 목록을 중복 없이 추출
user_homes=$(awk -F: '{print $6}' /etc/passwd | sort -u)

for home in $user_homes; do
    # 홈 디렉터리가 실제 존재하는 디렉터리인지 확인
    if [ -d "$home" ]; then
        for file_name in "${files_to_check[@]}"; do
            file_path="$home/$file_name"
            if [ -f "$file_path" ]; then
                # 주석을 제외하고 'xhost +' 명령어가 있는지 확인
                # 'xhost +hostname'과 같은 경우는 제외하고 정확히 'xhost +'만 찾기 위함
                if grep -v '^\s*#' "$file_path" | grep -qE "xhost\s*\+\s*($|#|;)"; then
                    is_vulnerable=true
                    vuln_details+="$file_path "
                fi
            fi
        done
    fi
done

if [ "$is_vulnerable" = true ]; then
    print_result "5.6 x-server 접속 제한 설정" \
    "사용자 자동 실행 파일(.profile, .xinitrc 등)에 'xhost +' 설정이 없는 경우" \
    "사용자 자동 실행 파일에 모든 호스트의 접근을 허용하는 'xhost +' 설정이 있는 경우" \
    "Vul" \
    "다음 파일에서 모든 호스트의 X-server 접근을 허용하는 'xhost +' 설정이 발견되었습니다: $vuln_details"
else
    print_result "5.6 x-server 접속 제한 설정" \
    "사용자 자동 실행 파일(.profile, .xinitrc 등)에 'xhost +' 설정이 없는 경우" \
    "사용자 자동 실행 파일에 모든 호스트의 접근을 허용하는 'xhost +' 설정이 있는 경우" \
    "Good" \
    "모든 사용자 자동 실행 파일에서 'xhost +' 설정이 발견되지 않았습니다."
fi

echo ""
echo ""
echo ""
echo "==============================================================="
echo ""
echo "     6. 시스템 보안 설정"
echo ""
echo "==============================================================="
echo ""

#6.1 /etc/system 파일 보안 설정
print_result "6.1 /etc/system 파일 보안 설정" \
"Stack 영역에서 코드 실행을 방지하는 설정이 적용된 경우" \
"Stack 영역 실행 방지 설정이 적용되지 않은 경우" \
"Manual" \
"해당 OS는 체크리스트에 포함하지 않음"

#6.2 Kernel 파라미터 설정
print_result "6.2 Kernel 파라미터 설정" \
"IP Spoofing, DoS 경유지 악용 등을 방지하도록 커널 파라미터가 설정된 경우" \
"보안을 위한 커널 파라미터 설정이 미흡한 경우" \
"Manual" \
"해당 OS는 체크리스트에 포함하지 않음"

#6.3 ISN(Initial Sequence Number) 파라미터 설정
# 가이드라인에 따라 Linux OS는 점검 대상에 포함되지 않아 수동 확인으로 분류합니다.
print_result "6.3 ISN(Initial Sequence Number) 파라미터 설정" \
"TCP ISN을 랜덤하게 생성하도록 설정된 경우" \
"TCP ISN 생성이 예측 가능하게 설정된 경우" \
"Manual" \
"해당 OS는 체크리스트에 포함하지 않음"

echo ""
echo ""
echo ""
echo "==============================================================="
echo ""
echo "     7. 보안 패치"
echo ""
echo "==============================================================="
echo ""

#7.1 보안 패치 적용
print_result "7.1 보안 패치 적용" \
"보안 패치가 주기적으로 관리되고 있으며, 중요한 CVE에 노출된 패키지가 없는 경우" \
"중요한 CVE에 노출된 패키지가 존재하거나, 패치 관리가 되고있지 않는 경우" \
"Manual" \
"설치된 패키지 버전과 CVE 정보를 비교 분석해야 하므로 수동 확인이 필요합니다."

echo ""
echo ""
echo ""
echo "==============================================================="
echo ""
echo "                Linux 보안 취약점 점검 완료"
echo ""
echo "==============================================================="
echo ""
echo "                    [ 점검 결과 요약 ]"
echo ""
echo "  - 양호 : $count_good 개"
echo "  - 취약 : $count_vul 개"
echo "  -  N/A : $count_manual 개"
echo ""
echo "==============================================================="

sleep 0.1