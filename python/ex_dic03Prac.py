#while 반복 while True 사용
#메뉴를 선택한다. (여러개의 메뉴를 선택 한다.)
#구매한 메뉴를 리스트로 보관도 해야 한다.
#현금을 넣는다.
#구매한후에 거스름돈을 받는다.
#구매했던 리스트와 총 구매가격? 출력!!!

menus = {"아메리카노": 4000, "카페라떼": 4500, "카푸치노": 5000}

print("=======메뉴판=======")

for name, price in menus.items():
    print(f"{name} : {price}원")

money = int(input("돈을 넣으세요: "))

order_list = {"아메리카노": 0, "카페라떼": 0, "카푸치노": 0} # order_list = []
total_price = 0
total_list = 0
while True:
    selected_menu = input("메뉴를 선택하세요(q를 누르면 종료): ")
    price = menus.get(selected_menu, 0)
    if selected_menu == 'q':
        print("구매를 종료합니다.")
        break
    elif price == 0:
        print("존재하지 않는 메뉴입니다.")
    else:
        if money < total_price:
            print("돈이 부족하여 주문이 강제 종료됩니다.")
            break
        order_list[selected_menu] += 1 # order_list.append(selected_menu)
        total_price += menus.get(selected_menu, 0)
        total_list += 1
        print(f"현재 주문까지의 가격: {total_price}, 남은 금액: {money-total_price}")

# 출력
print(f"===주문한 메뉴 리스트({total_list})===")
# for order in order_list:
#     print(order)
for idx, order in order_list.items():
    print(f"{idx}: {order}잔")
print("=======================")
print(f"총 가격: {total_price}원")
print(f"거스름돈: {money-total_price}원")