# 증적 목록과 출처

| 파일 | 출처 / 신뢰 범위 |
|---|---|
| evidence/ssh/default-deny-redacted.png | 2026-11-16 실제 OPNsense Live View 화면에서 발췌. 개인주소 영역 마스킹. |
| evidence/ssh/alias-loaded-zero-redacted.png | 2026-11-16 실제 OPNsense Alias 화면에서 발췌. 개인주소 영역 마스킹. |
| evidence/firewall/icmp-block-liveview.png | 사용자 제공 2026-11-17 ICMP Block Live View 원본 화면. |
| evidence/firewall/rules-before-apply.png | 사용자 제공 2026-11-17 Firewall Rules 화면. 브라우저 영역 제거. |
| evidence/nat/*.txt | 사용자 채팅에 붙인 OPNsense LAN/WAN tcpdump 출력 수기로 전사. 원본 pcap 파일 아님. |
| evidence/suricata/fast-log-icmp.txt | 사용자 채팅에 붙인 fast.log 출력 발췌. |
| evidence/suricata/icmp-alerts-selected-fields.jsonl | 사용자 채팅의 jq 축약 결과 재구성. 서버의 실제 전체 JSONL 파일과 구분 필요. |
| configs/local.rules | 사용자가 실제 입력한 Suricata 테스트 규칙과 동일한 한 줄 텍스트. |
| configs/netplan-eth1.example.yaml | 사용자의 Netplan 설정에서 eth1만 발췌 재작성한 예시. 원본 설정 파일 아님. |

GitHub 공개 전 전체 이미지의 계정명, 호스트명, VPN 주소, 인증정보 노출 여부를 최종 육안 확인하세요.
