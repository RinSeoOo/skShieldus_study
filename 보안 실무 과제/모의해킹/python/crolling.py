import requests
from bs4 import BeautifulSoup

# for i in range(1,10):
url = f'https://www.boannews.com/media/t_list.asp?Page=1&kind='
res = requests.get(url)
soup = BeautifulSoup(res.text, 'html.parser')
news = soup.select(f'#news_area > div > a:nth-child(1) > span')
# print(news)
for tit in news:
    print(tit.text)



#news_area > div:nth-child(1) > a:nth-child(1) > span
#news_area > div:nth-child(3) > a:nth-child(1) > span

# #news_area > div:nth-child(1) > a:nth-child(1) > span
# #news_area > div:nth-child(5) > a:nth-child(1) > span