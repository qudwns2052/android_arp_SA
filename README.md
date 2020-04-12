## 안드로이드 (CA) 주소

https://github.com/qudwns2052/android_arp_CA

## 현재 상황

1. CA -> Connect button click : socket c server와 연결함

2. CA -> Get List button click : Getlist를 RA에게 요청하여 받아옴

3. RA -> Get List 요청이 들어온 경우, findalldevs를 통해 interface list를 CA로 보냄

4. CA -> ListView : 3을 통해 가져온 interface list를 나열함

5. CA ->Listview item click : ListView에 있는 interface중 하나를 선택하여 RA에게 전송

6. RA -> 5를 통해 전달 받은 interface의 (subnet ip, ip, Mac)을 알아냄

7. RA -> 6을 통해 얻은 정보들을 바탕으로, ARP reply 패킷을 제작함

8. RA -> 7을 통해 만들어진 패킷을 Broadcast로 주기적으로 전송



### 할 일들

CA

\- 버튼 재 클릭시 ARP reply 멈추는 기능 추가

\- Exit 버튼 추가

\- RA 실행시켜주고 자동으로 꺼주기



RA

\- 코드 깔끔하게 수정

\- 필요한 부분 추가 + 불필요한 부분 제거



CA & RA

\- protocol 정하기