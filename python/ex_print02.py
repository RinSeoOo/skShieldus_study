# name = input("이름을 입력하세요: ")
# phone = input("번호를 입력하세요: ") # input의 기본 types: 문자열(str)
# age = int(input("나이를 입력하세요: ")) # 숫자형

# # print(name)
# # print(phone)
# print(name+"의 전화번호는", phone,"이고, 나이는", age,"세 입니다.") # +는 띄어쓰기 X (잘 안씀), ,는 띄어쓰기 O

# print('name:',type(name), 'phone:',type(phone),'age:',type(age)) # 쓸 일 거의 X
# print("내 이름은 {}이고 나이는 {}살입니다.".format(name, age))
# print(f"내 이름은 {name}이고, 나이는 {age}살이야.")

name = input("이름: ")
phone = input(f"{name}의 번호: ")
age = int(input(f"{name}의 나이: "))

print(name,"의 번호는",phone,f"이고, 나이는 {age}입니다.")
print("%s의 번호는 %s이고, 나이는 %d입니다." %(name, phone, age))
print("{}의 번호는 {}이고, 나이는 {}입니다.".format(name, phone, age))