names = ['문서영', '홍길동', '조정원', '수제비', '김씨','조정원','홍씨', '나씨']
print(names)
print(type(names)) # list

for name in names:
    print(name, end=' ')

print("\n",len(names)) # len(names): names의 길이(요소 개수)

for i in range(0,len(names),2): # 0부터 len(names)까지 2씩 증가
    if names[i] == '조정원':
        print(f"수제비는 {names.index('수제비')+1}번째에 있음")
    print(f"{i+1}번째 이름: {names[i]}")

print("\n")
for i, name in enumerate(names): # for문 변수(return하는 값) 2개 이상 사용 가능
    print(f"{i+1}번째 이름: {name}")
# txt 파일 한 줄씩 가져오기 -> 중요 정보가 몇 번째 줄에 있는지 알고 싶을 때

# import os

# # 파일 정보 리스트 얻고 싶을 때 자주 사용
# files = os.listdir('.') # list 형식
# print(files)