## 안드로이드 (CA) 주소

https://github.com/qudwns2052/android_arp_CA

## 1차 시연 영상

https://youtu.be/5efd3ipAbrU

## 2차 시연 영상

https://youtu.be/PCyZTQGiibA

## 200430 수정사항

CA : Recover 패킷 전송 추가 구현

RA : 변화 없음

## 200429 수정사항

CA : GUI 수정

RA : 코드 수정

## 200422 수정사항

RA : thread 적용 

CA : GUI 수정

## 매커니즘

1. CA -> Connect button click : socket c server와 연결함
2. CA -> Get List button click : Getlist를 RA에게 요청하여 받아옴
3. RA -> Get List 요청이 들어온 경우, findalldevs를 통해 interface list를 CA로 보냄
4. CA -> ListView : 3을 통해 가져온 interface list를 나열함
5. CA ->Listview item click : ListView에 있는 interface중 하나를 선택하여 RA에게 전송
6. RA -> 5를 통해 전달 받은 interface의 (subnet ip, ip, Mac)을 알아냄
7. RA -> 6을 통해 얻은 정보들을 바탕으로, ARP reply 패킷을 제작함
8. RA -> 7을 통해 만들어진 패킷을 Broadcast로 주기적으로 전송
9. CA -> 공격을 멈추기 위해 stop 버튼 클릭
10. RA -> 9에 의해 Recover packet을 3번 전송