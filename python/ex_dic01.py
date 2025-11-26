# my_dict = {"name": "John", "age": 30, "city": "New York"}

# # 모든 키만 가져오기
# keys = my_dict.keys()
# print(keys)

# # 모든 값만 가져오기
# values = my_dict.values() # list 형식
# print(values)

# # 모든 키-값 쌍 가져오기
# items = my_dict.items() # 튜플 형식으로 묶어서 가져옴
# print(items)

person = {"name": "John", "age": 30, "city": "New York"}
print(person)

# 직접 인덱싱 사용
try:
    print("Name:", person["name"])  # 존재하는 키
    print("Salary:", person["salary"])  # 존재하지 않는 키
except KeyError:
    print("KeyError: 'salary' key does not exist.")

# get() 메서드 사용
print("\nUsing get() method:")
print("Name:", person.get("name"))  # 존재하는 키
print("Salary:", person.get("salary"))  # 존재하지 않는 키, None을 반환(오류)
print("Salary with default:", person.get("salary", "Not Available"))  # 존재하지 않는 키, 기본값 "Not Available" 반환