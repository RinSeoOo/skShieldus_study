import requests
from datetime import datetime

now = datetime.now()
year = now.year
month = int(now.strftime("%m")) # 문자열을 정수로 변환

# 1월이면 전년도 12월로 설정
if month == 1:
    year -= 1
    month = 12
else:
    month -= 1

# API URL(월별 베스트셀러 상위 20개 / 영풍문고)
url = "https://www.ypbooks.co.kr/back_shop/base_shop/api/v1/best-seller/bestCd/1/20"
params = {
    "year": year,
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
    books_code = []
    origin_prices = []

    # 필요한 정보 추출
    for book in books_info:
        # print(type(book))
        # book_info = book.get('dataList', [])

        titles.append(book['bookProductInfo']['bookTitle']) # 책 제목
        author = book['bookProductInfo']['sapWriterName'] # 작가
        publisher = book['bookProductInfo']['pubCompanyName'] # 출판사
        price = book['salePrice'] # 가격
        review_exist = book['avgValuation'] # 평균 평점
        # 평점이 없는 경우가 있을 땐 '없음'이라고 표시
        if review_exist:
            review = review_exist
        else:
            review = "없음"
        isbn = book['productIdCd'] # ISBN

        books_code.append(book['bookCd'])
        origin_prices.append(book['productPrice'])


        # print(f"제목: {title}, 작가: {author}, 출판사: {publisher}, 가격: {price}원, 평점: {review}, ISBN: {isbn}, 코드: {books_code}, 원가: {origin_prices}")

else:
    print(f"API 요청 실패! 상태 코드: {response.status_code}")

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

        # 재고 리스트 추출
        stocks = data.get("data", [])

        print("=====================")
        print(f"<{title}>의 재고 확인")
        for stock in stocks:
            location = stock['werksNm'] # 영풍문고 매장 지점명
            loca_stock = stock['labst'] # 해당 지점의 보유 재고
            
            print(f"매장: {location}, 재고: {loca_stock}")

    else:
        print(f"API 요청 실패! 상태 코드: {stock_response.status_code}")