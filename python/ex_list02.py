# scores = [80, 90, 100, 70, 50, 40, 10, 30, 60, 120]
# print("scores: ",scores)

# print(scores[2:5]) # 2이상 5미만
# print(scores[2:]) # 2이상
# print(scores[2::2])

# 수업 때 예제- 아래는 학생들의 성적을 입력 받아서 최고값, 최소값, 평균값, 특정 점수 이상의 count 프로그램

STUDENTS = 5
lst = []
count = 0
for i in range(STUDENTS):
    value = int(input(f"{i+1}번째 학생의 성적을 입력하세요: "))
    lst.append(value)

print(f"최대 점수: {max(lst)}")
print(f"최소 점수: {min(lst)}")
print(f"평균 점수: {sum(lst)/len(lst)}") # /: 소수점까지, //: 소수점 아래 버리고 출력

avg_score = sum(lst)//len(lst)
for i in lst:
    if(i >= avg_score):
        count += 1
print(f"평균 점수 이상의 count: {count}")