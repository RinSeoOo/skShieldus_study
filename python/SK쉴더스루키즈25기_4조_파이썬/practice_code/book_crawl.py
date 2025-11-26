import requests
from bs4 import BeautifulSoup
from openpyxl import Workbook
from datetime import datetime

# 크롤링할 사이트 URL 및 헤더 설정
YES24_BEST_URL = "http://www.yes24.com/24/category/bestseller?categorynumber=001"
ALADIN_BEST_URL = "https://www.aladin.co.kr/shop/common/wbest.aspx?BranchType=1&BestType=MonthlyBest"
HEADERS = {'User-Agent': 'Mozilla/5.0'}

# 웹 스크래핑 및 엑셀 파일 저장 함수
def scrape_and_save():
    wb = Workbook()
    ws = wb.active
    ws.title = "베스트셀러 비교"
    ws.append(['서점', '순위', '제목', '저자', '가격', '출판사', '평점'])
    
    # 예스24 베스트셀러 크롤링
    yes24_req = requests.get(YES24_BEST_URL, headers=HEADERS)
    yes24_soup = BeautifulSoup(yes24_req.text, "lxml")
    yes24_books = yes24_soup.select(".item_info")
    for rank, book in enumerate(yes24_books[:20], start=1):
        title = book.select_one(".gd_name").text.strip() if book.select_one(".gd_name") else "제목 없음"
        author = book.select_one(".info_auth a").text.strip() if book.select_one(".info_auth a") else "저자 없음"
        publisher = book.select_one(".info_pub a").text.strip() if book.select_one(".info_pub a") else "출판사 없음"
        price = book.select_one(".txt_num em.yes_b").text.strip() if book.select_one(".txt_num em.yes_b") else "가격 없음"
        rating = book.select_one(".rating_grade em.yes_b").text.strip() if book.select_one(".rating_grade em.yes_b") else "평점 없음"

        ws.append(["예스24", rank, title, author, price, publisher, rating])

    
    # 알라딘 베스트셀러 크롤링
    aladin_req = requests.get(ALADIN_BEST_URL, headers=HEADERS)
    aladin_soup = BeautifulSoup(aladin_req.text, "lxml")
    aladin_books = aladin_soup.select(".ss_book_list")
    for rank, book in enumerate(aladin_books[:20], start=1):
        title = book.select_one(".bo3").text.strip() if book.select_one(".bo3") else "제목 없음"
        author = book.select_one("li > a[href*='AuthorSearch']").text.strip() if book.select_one("li > a[href*='AuthorSearch']") else "저자 없음"
        publisher = book.select_one("li > a[href*='PublisherSearch']").text.strip() if book.select_one("li > a[href*='PublisherSearch']") else "출판사 없음"
        price = book.select_one(".ss_p2 em").text.strip() if book.select_one(".ss_p2 em") else "가격 없음"
        rating = "평점 없음"  # 추가된 rating

        ws.append(["알라딘", rank, title, author, price, publisher, rating])

    
    file_path = f"bestseller-info({datetime.now().strftime('%Y-%m-%d')}).xlsx"
    wb.save(file_path)
    print(f"엑셀 파일 '{file_path}'에 저장되었습니다.")
    return file_path

if __name__ == "__main__":
    scrape_and_save()