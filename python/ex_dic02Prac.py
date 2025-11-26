### 커피 주문 프로그램
# 메뉴 선택
# 현금 넣기
menu = {"아메리카노": 4000, "카페라떼": 4500, "카푸치노": 5000}
print("===========MENU===========")
for name, price in menu.items():
    print(f"{name} : {price}원")
print("==========================")

selected_menu = input("주문할 메뉴를 선택하세요: ")
money = int(input("돈을 넣으세요: "))

price = menu.get(selected_menu, 0)
# 구매 후, 거스름돈 받기
if price == 0:
    print("메뉴가 존재하지 않습니다:(")
else:
    change = money - price
    if change < 0:
        print("돈이 부족합니다..")
    else:
        print(f"주문하신 메뉴 나왔습니다.\n거스름돈: {change}원")