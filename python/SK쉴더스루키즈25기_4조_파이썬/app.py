from flask import Flask, render_template, send_file, request
import requests
from bs4 import BeautifulSoup # 예스24, 알라딘
from selenium import webdriver # 교보
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
import time
import re
from datetime import datetime # 영풍

app = Flask(__name__)

# 크롤링할 사이트 URL 및 헤더 설정
YES24_BEST_URL = "https://www.yes24.com/product/category/monthweekbestseller?categoryNumber=001&pageSize=24&type=month&saleYear=2025&saleMonth=2"
ALADIN_BEST_URL = "https://www.aladin.co.kr/shop/common/wbest.aspx?BranchType=1&CID=0&Year=2025&Month=2&BestType=MonthlyBest"
HEADERS = {'User-Agent': 'Mozilla/5.0'}


# 알라딘 전용! 상세 페이지에서 평점 가져오는 함수
def aladin_detailed(book_id):
    BOOK_URL = f"https://www.aladin.co.kr/shop/wproduct.aspx?ItemId={book_id}"  # 알라딘 도서의 상세 페이지 URL 생성
    book_req = requests.get(BOOK_URL, headers=HEADERS)  # BOOK_URL에 요청 보내서 도서 정보 HTML 가져옴
    book_soup = BeautifulSoup(book_req.text, "lxml")    # BeautifulSoup 사용해서 도서 정보 HTML 파싱

    # 평점이 있는지 확인 후 반환
    rating = book_soup.select_one("#wa_product_top1_wa_Top_Ranking_pnlRanking > div.info_list.Ere_fs15.Ere_ht18 > a.Ere_sub_pink.Ere_fs16.Ere_str") # 평점 선택자를 사용해서 평점 가져오기
    if rating:
        return rating.text.strip()      # 평점이 존재하면 공백을 제거하고 평점 값을 반환
    return "평점 없음"     # 평점이 없다면 "평점 없음" 반환

# 웹 스크래핑 함수 (엑셀 저장 대신 데이터 반환)
def get_bestsellers():
    yes24_books = []
    aladin_books = []

    # 예스24 베스트셀러 크롤링
    yes24_req = requests.get(YES24_BEST_URL, headers=HEADERS)
    yes24_soup = BeautifulSoup(yes24_req.text, "lxml")
    yes24_books_list = yes24_soup.select(".item_info")      # 도서 정보가 담긴 요소들을 선택

    for rank, book in enumerate(yes24_books_list[:20], start=1):
        title = book.select_one(".gd_name").text.strip() if book.select_one(".gd_name") else "None"    # 도서 제목 // 제목이 없는 경우는 "제목 없음" 
        author = book.select_one(".info_auth a")    # 저자 정보
        publisher = book.select_one(".info_pub a")      # 출판사 정보 
        price = book.select_one(".txt_num em.yes_b")    # 가격 정보 
        rating = book.select_one(".rating_grade em.yes_b")      # 평점 정보

        # 리스트 대신 튜플을 추가
        yes24_books.append((
            "예스24",
            rank,
            title,
            author.text.strip() if author else "None",     # 변수가 존재하면 저자를 보여주고, 없으면 "저자 없음"을 반환
            price.text.strip() if price else "None",   # 변수 값이 존재하면 가격을 보여주고, 없으면 "가격 없음"을 반환
            publisher.text.strip() if publisher else "None",     # 변수가 존재하면 출판사를 보여주고, 없으면 "출판사 없음"을 반환
            rating.text.strip() if rating else "None"  #  변수 값이 존재하면 평점을 보여주고, 없으면 "평점 없음"을 반환
        ))

    # 알라딘 베스트셀러 크롤링
    aladin_req = requests.get(ALADIN_BEST_URL, headers=HEADERS)     # 알라딘 베스트셀러 페이지에 요청을 보내서 HTML을 가져오고
    aladin_soup = BeautifulSoup(aladin_req.text, "lxml")     # 가져온 HTML 데이터를 lxml 파서를 이용해 BeautifulSoup 객체로 변환
    aladin_books_list = aladin_soup.select(".ss_book_box")      # 베스트셀러 목록을 담고 있는 요소들을 선택(".ss_book_box" 클래스를 가진 요소)

    for rank, book in enumerate(aladin_books_list[:20], start=1):   # 상위 20개의 책 정보를 가져오기 위해 enumerate를 사용하여 반복
        title = book.select_one(".bo3").text.strip() if book.select_one(".bo3") else "None"    # ".bo3" 클래스를 가진 요소에서 텍스트 추출
        author = book.select_one("li > a[href*='AuthorSearch']")    # "AuthorSearch" 링크를 가진 요소에서 텍스트 추출
        publisher = book.select_one("li > a[href*='PublisherSearch']")  # "PublisherSearch" 링크를 가진 요소에서 텍스트 추출
        price = book.select_one(".ss_p2 em")    # ".ss_p2 em" 요소에서 텍스트 추출

        book_link = book.select_one("a")["href"]        # 각 책책의 상세페이지 가져옴
        book_id = book_link.split("ItemId=")[-1]        # ItemId(책 번호) 추출

        rating = aladin_detailed(book_id)   # 책 ID를 이용해 별도 함수 `aladin_detailed()`를 호출하여 평점 가져오기

        # 리스트 대신 튜플을 추가
        aladin_books.append((
            "알라딘",
            rank,
            title,
            author.text.strip() if author else "None",
            price.text.strip() if price else "None",
            publisher.text.strip() if publisher else "None",
            rating.strip() if rating else "None"
        ))

    return yes24_books, aladin_books

# 영풍문고 크롤링
def get_young_list():
    young_books = []

    now = datetime.now()
    year = now.year
    month = int(now.strftime("%m")) # 문자열을 정수로 변환
    # 1월이면 전년도 12월로 설정
    if month == 1:
        year -= 1
        month = 12
    else:
        month -= 1
    # API URL(월별 베스트셀러 상위 20개(bestCD/1/20) / 영풍문고)
    url = "https://www.ypbooks.co.kr/back_shop/base_shop/api/v1/best-seller/bestCd/1/20"
    params = { 
        "year": year, # 현재일 기준으로 전월이 표시되도록 year, month 변수
        "month": month,
        "searchDiv": "M",
        "outOfStock": "y",
        "categoryIdKey": "",
        "categoryBestCd": "A000"
    } 
    # 요청 헤더 설정
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.118 Safari/537.36"
    }

    # API 요청
    response = requests.get(url, headers=headers, params=params)

    # 응답이 성공적인지 확인
    if response.status_code == 200:
        data = response.json()  # JSON 데이터 변환

        # 베스트셀러 리스트 추출
        books = data.get("data", [])
        books_info = books.get('dataList', [])

        # print(books_info)        
        titles = []
        authors = []
        publishers = []
        prices = []
        review_exists = []
        books_code = []
        origin_prices = []

        # 필요한 정보 추출
        for book in books_info:
            
            titles.append(book['bookProductInfo']['bookTitle']) # 책 제목
            authors.append(book['bookProductInfo']['sapWriterName']) # 작가
            publishers.append(book['bookProductInfo']['pubCompanyName']) # 출판사
            price = book['salePrice'] # 가격
            review_exist = book['avgValuation'] if book['avgValuation'] else "-" # 평균 평점(평점이 없을 경우 "없음"으로 표시)
            review_exists.append(review_exist)

            books_code.append(book['bookCd'])
            origin_prices.append(book['productPrice'])
            
            # 쉼표 추가 (천 단위 구분 기호)            
            price = f"{int(price):,}"  # 가격을 정수로 변환 후 쉼표 추가
            prices.append(price)

        
        for idx in range(len(titles)):
            young_books.append((
                "영풍문고",
                idx+1,
                titles[idx],
                authors[idx],
                prices[idx],
                publishers[idx],
                review_exists[idx]
            ))
            
    else:
        print(f"API 요청 실패! 상태 코드: {response.status_code}")

    young_books_dict = {}
    for title, book_code, origin_price in zip(titles, books_code, origin_prices):
        stock_url = "https://www.ypbooks.co.kr/back_shop/base_shop/api/v1/product/stock-info"
        stock_params = {
            "iBookCd": book_code,
            "iNorPrc": origin_price,
            "iGubun": "y"
        }
        stock_response = requests.get(stock_url, headers=headers, params=stock_params)

        # 응답이 성공적인지 확인
        if stock_response.status_code == 200:
            data = stock_response.json()  # JSON 데이터 변환            
            stocks = data.get("data", []) # 재고 리스트 추출
            
            for stock in stocks:
                location = stock['werksNm'] # 영풍문고 매장 지점명
                loca_stock = stock['labst'] # 해당 지점의 보유 재고
                
                # 책 제목(title)에 대한 재고 정보를 locations 리스트에 추가
                if title in young_books_dict:
                    young_books_dict[title].append((location, loca_stock))  # 이미 존재하는 title에 재고 추가
                else:
                    # title이 처음 등장하면 초기화하고 추가
                    young_books_dict[title] = [(location, loca_stock)]
        else:
            print(f"API 요청 실패! 상태 코드: {stock_response.status_code}")
    
    return young_books_dict, young_books

# 교보문고 크롤링
def get_kyobo_list():
    options = Options()
    options.add_argument("--headless") # UI 없이 백그라운드에서만 실행
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    
    driver = webdriver.Chrome(options=options)
    driver.get("https://store.kyobobook.co.kr/bestseller/total/monthly")
    time.sleep(2) # 페이지 로드 대기시간
    html = driver.page_source
    driver.quit() # 브라우저 종료

    soup = BeautifulSoup(html, "html.parser")
    book_list = soup.select("ol.grid > li")

    kyobo_id_link = []
    kyobo_books = []
    idx = 0
    for li in book_list:
        # 제목
        title_tag = li.select_one("div.ml-4.w-full > a")
        title = title_tag.get_text(strip=True) if title_tag else "None"
        link = title_tag.get("href") if title_tag else "#"
        full_link = f"https://store.kyobobook.co.kr{link}" if link.startswith("/") else link
        kyobo_id_link.append(link)

        # 저자 및 출판사
        author_pub_tag = li.select_one("div.fz-14.mt-1")
        author_pub = author_pub_tag.get_text(strip=True) if author_pub_tag else "None"
        # print(author_pub)
        
        # 날짜 추출 (정규 표현식)
        date_pattern = r'\d{4}\.\d{2}\.\d{2}' # 날짜 형식 (YYYY.MM.DD)
        match = re.search(date_pattern, author_pub)

        if match:
            # 날짜가 시작되는 인덱스
            date_start_index = match.start()
            
            # 날짜를 나누기
            date_tag = author_pub[date_start_index:].strip()   # 날짜 부분
            author_pub_without_date = author_pub[:date_start_index].strip()  # 날짜를 제외한 나머지 부분 (저자 + 출판사)

            # ' · ' 기준으로 저자와 출판사를 분리
            if ' · ' in author_pub_without_date:
                author, publisher = author_pub_without_date.split(' · ', 1)  # 1번 인덱스를 사용하여 첫 번째 ' · '만 기준으로 나눔
                publisher = publisher.rstrip('·').strip()  # ·와 공백을 제거
            else:
                author, publisher = author_pub_without_date, "None"
        else:
            # 날짜가 없을 경우
            author, publisher, date_tag = author_pub, "None", "None"

        # 가격 (정확한 가격 span을 명시적으로 선택)
        price_tag = li.select_one("div.flex.flex-col.mt-3 > div > span:nth-child(2) > span.font-bold")
        price = price_tag.get_text(strip=True) if price_tag else "None"

        # 평점
        rating_tag = li.select_one("div.flex.w-full.flex-wrap.gap-3 span.font-bold.text-black")
        rating = rating = f"{float(rating_tag.get_text(strip=True)):.1f}" if rating_tag else "None"


        kyobo_books.append((
            "교보문고",
            idx+1,
            title,
            author,
            price,
            publisher,
            rating
        ))
        idx += 1
    
    return kyobo_books, kyobo_id_link


def get_stock_kyobo(kyobo_id_link, index):
    # print(kyobo_id_link[int(index)])
    product_id = re.search(r'/detail/(S\d+)', kyobo_id_link[int(index)])
    # print(product_id.group(1))
    api_url = f"https://store.kyobobook.co.kr/api/gw/pdt/product/{product_id.group(1)}/location-inventory"
    response = requests.get(api_url, headers=HEADERS)
    if response.status_code != 200:
        return f"요청 실패: {response.status_code}"
    
    try:
        data = response.json()
    except Exception as e:
        return f"실패: {e}"

    stores = []

    for group in data.get("data", []):
        for store in group.get("list", []):
            store_name = store.get("strName", "None")
            inventory = store.get("realInvnQntt", "None")
            stores.append({
                "store_name": store_name,
                "inventory": inventory
            })
    
    return stores    


@app.route('/')
def index():
    yes24_books, aladin_books = get_bestsellers()
    kyobo_books, kyobo_links = get_kyobo_list()
    young_books_dict, young_books = get_young_list()
    
    return render_template('index.html', yes24_books = yes24_books, aladin_books = aladin_books, kyobo_books=kyobo_books, young_books=young_books) # , young_stocks=young_stocks)

@app.route('/young_check/<book_title>')
def young_check(book_title):
    # 책 제목에 맞는 재고 정보를 가져옵니다
    index = request.args.get('idx')  # URL 쿼리 파라미터에서 index 값을 가져옴
    young_books_dict, young_books = get_young_list()
    
    # 책 제목을 사용하여 재고 정보 페이지를 렌더링합니다
    return render_template('check.html', book_title=book_title, young_stocks=young_books_dict, idx=index)


@app.route('/kyobo_check/<book_title>')
def kyobo_check(book_title):
    # 책 제목에 맞는 재고 정보를 가져옵니다
    index = request.args.get('idx')  # URL 쿼리 파라미터에서 index 값을 가져옴
    kyobo_books, kyobo_id_link = get_kyobo_list()
    kyobo_books_dict = get_stock_kyobo(kyobo_id_link, index)
    
    # 책 제목을 사용하여 재고 정보 페이지를 렌더링합니다
    return render_template('check2.html', book_title=book_title, kyobo_stocks=kyobo_books_dict, idx=index)

if __name__ == '__main__':
    app.run(debug=True)