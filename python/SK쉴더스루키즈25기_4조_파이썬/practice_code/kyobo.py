from flask import Flask, render_template, send_file, request
import requests
from bs4 import BeautifulSoup  # 예스24, 알라딘
from selenium import webdriver  # 교보
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time
import re
from datetime import datetime  # 영풍
from openpyxl import Workbook  # 서점별 리스트 다운로드
import io


def parse_store_stock(html):
    soup = BeautifulSoup(html, "html.parser")
    stock_list = []

    # 모달 영역 선택
    modal = soup.select_one("#popStock .dialog_contents")
    if not modal:
        print("재고 모달을 찾을 수 없습니다.")
        return []

    # 지역 이름 파싱
    region_tag = modal.select_one("div > div.simplebar-wrapper p")
    region_name = region_tag.get_text(strip=True) if region_tag else "지역 없음"

    # 매장 테이블 선택 (헤더와 바디)
    table = modal.select_one("div:nth-child(2) > table")
    if not table:
        print("매장 테이블을 찾지 못했습니다.")
        return []

    # 1. 헤더에서 매장명 추출
    header_cells = table.select("thead tr th")
    store_names = [cell.get_text(strip=True) for cell in header_cells if cell.get_text(strip=True)]
    
    # 2. 본문 행에서 재고 정보 추출 (일반적으로 한 행으로 구성됨)
    body_row = table.select_one("tbody tr")
    if not body_row:
        print("매장 재고 정보 행을 찾지 못했습니다.")
        return []

    stock_cells = body_row.select("td")
    if len(stock_cells) < len(store_names):
        print("헤더의 매장명과 본문의 재고 셀 수가 일치하지 않습니다.")
    
    # 각 셀을 헤더와 매칭시켜 저장 (셀 개수가 더 적더라도, 가능한 만큼만 매칭)
    for name, cell in zip(store_names, stock_cells):
        # 재고 수량이 a 태그 안에 span으로 감싸져 있을 경우
        stock_tag = cell.select_one("a > span")
        stock_count = stock_tag.get_text(strip=True) if stock_tag else cell.get_text(strip=True)
        stock_list.append({
            "region": region_name,
            "name": name,
            "stock": stock_count
        })

    return stock_list

def main():
    # Chrome WebDriver 설정
    options = Options()
    options.add_argument("--headless")  # 브라우저 창을 띄우지 않음
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    
    # WebDriver 인스턴스 생성
    driver = webdriver.Chrome(options=options)
    
    # 목표 URL
    url = "https://product.kyobobook.co.kr/detail/S000001632467"
    
    # 페이지 로드
    driver.get(url)
    
    # 페이지의 동적 콘텐츠 로딩 대기 (최대 10초)
    try:
        # 특정 요소가 나타날 때까지 기다리기
        WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, "#popStock .tbl_col_wrap .tbl_col"))
        )
    except Exception as e:
        print("페이지 로딩 실패:", e)
        driver.quit()
        return
    
    # 페이지의 HTML 가져오기
    html = driver.page_source
    
    # WebDriver 종료
    driver.quit()

    # BeautifulSoup으로 HTML 파싱
    soup = BeautifulSoup(html, "html.parser")
    
    # 재고 정보를 담고 있는 HTML 요소 선택 (수정해야 할 부분)
    # stock_list = soup.select("#popStock > div.dialog_contents > div > div.simplebar-wrapper > div.simplebar-mask > div > div > div > div > div:nth-child(2) > table")
    stock_list = soup.select("#popStock .tbl_col_wrap .tbl_col")
    
    # 각 테이블에서 데이터를 추출
    stock_info = []
    for table in stock_list:
        rows = table.find_all('tr')
        
        for row in rows:
            columns = row.find_all('th')  # 매장 위치가 들어 있는 <th> 태그
            values = row.find_all('span', class_='text')  # 재고량이 들어 있는 <span> 태그
            
            if columns and values:
                # 매장 이름과 재고량을 짝지어서 저장
                for col, value in zip(columns, values):
                    store_name = col.get_text(strip=True)
                    stock_count = value.get_text(strip=True)
                    stock_info.append((store_name, stock_count))

    # 출력
    if stock_info:
        for store, stock in stock_info:
            print(f"매장: {store}, 재고량: {stock}")
    else:
        print("재고 정보를 찾을 수 없습니다.")
    
if __name__ == "__main__":
    main()