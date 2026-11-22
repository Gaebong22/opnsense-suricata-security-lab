# OPNsense & Suricata Security Lab

> **Hyper-V 기반 방화벽·네트워크 분리·Source NAT·IDS 탐지 검증 프로젝트**  
> OPNsense를 활용해 접근 정책과 네트워크 경로를 구성하고, 실제 패킷·방화벽 로그·Suricata 이벤트로 동작을 검증한 개인 보안 실습입니다.


### 증적 바로가기

- [SSH 접근 장애: Default deny 로그](evidence/ssh/default-deny-redacted.png) · [Alias 로드 상태](evidence/ssh/alias-loaded-zero-redacted.png)
- [ICMP 방화벽 차단 Live View](evidence/firewall/icmp-block-liveview.png) · [방화벽 규칙 화면](evidence/firewall/rules-before-apply.png)
- [Source NAT: LAN 패킷](evidence/nat/lan-icmp.txt) · [WAN 패킷](evidence/nat/wan-icmp.txt)
- [Suricata 사용자 규칙](configs/local.rules) · [선택 필드 JSONL 로그](evidence/suricata/icmp-alerts-selected-fields.jsonl)

> 본 저장소의 `.txt` 및 JSONL 증적은 대화 중 사용자에게 제공된 실제 터미널 출력을 옮겨 담은 자료입니다. 서버에서 원본 파일을 직접 복사한 바이트 단위 원본이 아니며, JSONL은 원본 `eve.json`에서 `jq`로 **선택된 필드만 출력한 4건**입니다. 스크린샷은 실제 캡처를 사용하고 공개에 불필요한 주소/계정 영역을 마스킹했습니다.

## 1. 프로젝트 개요

방화벽 정책을 설정하는 것에서 그치지 않고 **실제 패킷이 어느 인터페이스까지 도착하는지**, **허용·차단 규칙이 어떻게 적용되는지**, **출발지 NAT가 어떻게 수행되는지**, **IDS가 어떤 이벤트를 기록하는지**를 확인하는 것을 목표로 했습니다.

특히 원격 SSH 접속 장애를 해결하는 과정에서 VPN 연결 상태, 패킷 수신 여부, 방화벽 로그, Alias와 필터 규칙을 순서대로 점검했습니다. 기존 관리 연결을 유지하면서 별도 실습망을 추가해 검증했습니다.

### 핵심 검증 결과

| 영역 | 수행한 작업 | 검증 결과 |
|---|---|---|
| 가상 네트워크 | Hyper-V 가상 스위치 및 OPNsense WAN/LAN/MGMT 분리 | Ubuntu 실습망 `10.10.10.0/24` 통신 확인 |
| 원격 관리 | Tailscale VPN, 별도 계정, SSH 공개키 인증, 접근 제어 | MacBook에서 `secadmin` SSH 접속 및 `sudo` 권한 확인 |
| 방화벽 정책 | LAN ICMP 허용·차단 규칙 시험 | 허용 시 Ping 4/4, 차단 시 Live View 로그 3건 |
| Source NAT | 지정 목적지에 대한 정적 호스트 경로 및 자동 SNAT | LAN/WAN 양쪽에서 출발지 IP 변환 확인, Ping 4/4 |
| IDS 탐지 | Suricata 8.0.8, AF_PACKET, 로컬 ICMP 탐지 규칙 | ICMP 요청 4회에 대응하는 Alert 4건 |
| 이벤트 분석 | `fast.log`, `eve.json`, `jq` | 동일한 4개 이벤트 대조 및 JSONL 증적 저장 |

> **범위:** 실습 환경에서 확인한 결과입니다. OPNsense 자체의 인라인 IPS, 네트워크 전체 패킷 미러링, 상용망 운영·성능 검증을 수행한 프로젝트는 아닙니다.

---

## 2. 실습 환경

### 장비와 주요 소프트웨어

| 구분 | 환경 및 역할 |
|---|---|
| 호스트 | Windows N100 미니 PC, Hyper-V |
| 방화벽 VM | OPNsense 26.7.9_1 (FreeBSD 기반), WAN/LAN/MGMT/Tailscale 인터페이스 |
| IDS VM | Ubuntu Server 24.04.5 LTS, Suricata 8.0.8 |
| 관리 단말 | MacBook Air, Tailscale 및 SSH |
| 관리·검증 도구 | OPNsense Web GUI, SSH, `tcpdump`, `ping`, `ip`, `jq`, Netplan |

### 네트워크 구성

```text
                         MacBook (관리 단말)
                          Tailscale + SSH
                                 │
                     Tailscale VPN / tailscale0
                                 │
┌────────────────── Windows N100 / Hyper-V Host ──────────────────┐
│                                                                 │
│    Ubuntu-Lab                         OPNsense-Lab               │
│    ┌────────────────┐                ┌─────────────────────┐     │
│    │ eth0 / DHCP     ├── Default ─────┤ hn0 / WAN / DHCP    │     │
│    │ 기존 기본 경로   │   Switch       │                     │     │
│    │                │                │                     │     │
│    │ eth1           ├── SecLab-LAN ──┤ hn1 / LAN           │     │
│    │ 10.10.10.10/24 │   (Private)    │ 10.10.10.1/24       │     │
│    │ Suricata 감시  │                │                     │     │
│    └────────────────┘                │ hn2 / OPT1          │     │
│                                      │ 10.30.30.1/24       │     │
│    Windows 관리 NIC ─ SecLab-MGMT ───┤                     │     │
│    10.30.30.10/24     (Internal)     └─────────────────────┘     │
└─────────────────────────────────────────────────────────────────┘
```

| 네트워크 | 유형 | 목적 |
|---|---|---|
| Default Switch | Hyper-V Internal/NAT | 기존 인터넷 경로 및 OPNsense WAN 연결 |
| SecLab-LAN | Private | Ubuntu `eth1` ↔ OPNsense `hn1` 실습 트래픽 |
| SecLab-MGMT | Internal | Windows 호스트 ↔ OPNsense Web GUI 관리 경로 |
| Tailscale | Overlay VPN | MacBook ↔ OPNsense SSH 원격 관리 |

Ubuntu의 **기존 `eth0` 기본 게이트웨이는 유지**했습니다. 신규 `eth1`에는 실습망 주소만 지정했으며 기본 게이트웨이를 추가하지 않았습니다. 이렇게 관리 연결을 유지하면서 별도 트래픽을 시험할 수 있었습니다.

---

## 3. OPNsense 원격 관리 및 접근 통제

MacBook에서 Tailscale을 통해 OPNsense에 접근하고, 기본 root 직접 SSH 로그인 대신 별도 `secadmin` 계정을 사용했습니다.

- **SSH 인증:** ED25519 공개키 인증
- **접근 제어:** Tailscale 인터페이스의 TCP/22에 대해 허용된 MacBook 출발지 Alias(`MACBOOK_TS`) 사용
- **계정 정책:** 직접 root SSH 및 SSH 비밀번호 인증 제한
- **권한 상승:** OPNsense의 sudo 정책에서 `wheel` 그룹의 비밀번호 기반 sudo 허용

실제 권한 검증 결과:

```text
$ whoami
secadmin

$ id
uid=2000(secadmin) gid=0(wheel) groups=0(wheel)

$ sudo -l
User secadmin may run the following commands on OPNsense:
    (ALL) ALL

$ sudo -i
# whoami
root
```

### SSH 타임아웃 장애 분석

**증상:** Tailscale Ping은 응답하지만 OPNsense SSH 접속은 Timeout이 발생했습니다.

1. `tcpdump -ni tailscale0 'tcp port 22'`로 MacBook에서 전송한 **TCP SYN 패킷이 OPNsense까지 도달**했음을 확인했습니다.
2. `Firewall → Log Files → Live View`에서 해당 SSH 연결이 **`Default deny / state violation rule`**에 의해 차단되는 것을 확인했습니다.
3. 허용 규칙이 필터에 존재하는지 `pfctl -sr`로 점검했고, 해당 규칙이 `<MACBOOK_TS>` Alias를 참조한다는 점을 확인했습니다.
4. Alias 화면에서 `MACBOOK_TS`의 **`Loaded# = 0`**을 확인해, Alias 로드/규칙 매칭 문제를 주요 조사 대상으로 삼았습니다.
5. Alias 및 방화벽 정책을 재적용한 후 MacBook에서 **SSH 공개키 접속에 성공**했습니다.

**기술적 판단:** TCP SYN이 방화벽 인터페이스까지 도착했으므로, 단순 VPN 연결 장애보다는 방화벽 정책 평가와 출발지 Alias 상태를 우선 조사했습니다. 단, 문제 해결 직후의 Alias 테이블 출력이 보존되지 않아 *최종 근본 원인을 단정하지는 않습니다*.

---

## 4. LAN 방화벽 허용·차단 정책 검증

### 4.1 정상 통신 확인

Ubuntu의 실습 NIC(`eth1`)에서 OPNsense LAN 주소로 Ping을 전송했습니다.

```bash
ping -c 4 -I eth1 10.10.10.1
```

**결과:** 4개 전송, 4개 수신, 손실률 0%.

OPNsense에서는 `tcpdump`로 Echo Request/Reply를 확인했습니다.

```sh
tcpdump -ni hn1 'icmp and host 10.10.10.10'
```

```text
10.10.10.10 > 10.10.10.1: ICMP echo request
10.10.10.1 > 10.10.10.10: ICMP echo reply
```

### 4.2 ICMP 차단 규칙 적용

OPNsense의 **LAN 인바운드**에 다음과 같은 시험 규칙을 구성하고, 기존 LAN 허용 규칙보다 먼저 평가되도록 배치했습니다.

| 필드 | 설정 |
|---|---|
| Action | Block |
| Interface / Direction | LAN / in |
| Protocol | IPv4 ICMP |
| Source | `10.10.10.10` |
| Destination | LAN address (`10.10.10.1`) |
| Log | Enabled |
| Description | `LAB_BLOCK_UBUNTU_PING` |

**결과:** Ping 시험 중 Echo Request는 관찰됐지만 Echo Reply는 나타나지 않았고, Live View에서 해당 규칙에 의한 **ICMP 차단 로그 3건**이 기록됐습니다.

이후 시험 차단 규칙은 비활성화했습니다. 차단 해제 후 Ping 재시험의 별도 출력까지 증적으로 보존한 것은 아니므로, 이 절의 검증 결과는 위 허용 및 차단 시험에 한정합니다.

---

## 5. 라우팅 및 Source NAT 검증

### 5.1 기본 경로를 변경하지 않은 시험 설계

Ubuntu는 기존 `eth0` 기본 경로를 유지했습니다. 외부 테스트 주소 `1.1.1.1/32`에 대해서만 OPNsense LAN을 다음 홉으로 지정했습니다.

```bash
sudo ip route replace 1.1.1.1/32 via 10.10.10.1 dev eth1
ip route get 1.1.1.1
```

```text
1.1.1.1 via 10.10.10.1 dev eth1 src 10.10.10.10
```

이렇게 기존 원격 관리 경로에 영향을 주지 않으면서 지정 목적지의 패킷만 OPNsense를 거치도록 했습니다.

### 5.2 자동 Source NAT 규칙 확인

OPNsense의 `Firewall → NAT → Source NAT`에서 **Automatic Source NAT** 모드를 확인했습니다. 자동 생성 규칙의 출발지에 `LAN network`가 포함됐고, 변환 주소는 WAN 인터페이스 주소(`Interface address`)였습니다.

### 5.3 LAN/WAN 패킷 비교

각 인터페이스에서 동일한 외부 ICMP 흐름을 캡처했습니다.

```sh
# LAN (NAT 이전)
tcpdump -ni hn1 'icmp and host 1.1.1.1'

# WAN (NAT 이후)
tcpdump -ni hn0 'icmp and host 1.1.1.1'
```

| 구분 | 원본 캡처의 한 요청 패킷 | ICMP ID |
|---|---|---|
| OPNsense LAN `hn1` | `10.10.10.10 > 1.1.1.1` | 17179 |
| OPNsense WAN `hn0` | `172.27.187.224 > 1.1.1.1` | 9838 |

```text
LAN  14:19:05.830561 IP 10.10.10.10 > 1.1.1.1: ICMP echo request, id 17179, seq 1
WAN  14:19:05.830859 IP 172.27.187.224 > 1.1.1.1: ICMP echo request, id 9838, seq 1
```

**결과:** 요청·응답 각각 4쌍을 LAN/WAN에서 확인했고, Ubuntu의 Ping은 **4/4 성공**(평균 RTT 5.264ms)이었습니다. 출발지 주소가 WAN 인터페이스 주소로 변환된 것이 확인됩니다.

> WAN 주소 `172.27.187.224`는 캡처 당시 Hyper-V Default Switch의 **사설 IP**입니다. 공인 IP로 변환된 사례가 아닙니다.

테스트용 `/32` 경로는 이후 최종 라우팅 점검에서 존재하지 않음을 확인했습니다.

---

## 6. Suricata IDS 사용자 정의 규칙 및 탐지

### 6.1 탐지 환경

Ubuntu-Lab에서 Suricata 8.0.8 서비스를 운영하고, AF_PACKET 감시 인터페이스를 기존 `eth0`에서 **실습 전용 `eth1`**로 변경했습니다.

```yaml
# /etc/suricata/suricata.yaml 중 해당 항목
af-packet:
  - interface: eth1
```

`rule-files`에 사용자 정의 규칙 파일을 등록했습니다.

```yaml
rule-files:
  - suricata.rules
  - /etc/suricata/rules/local.rules
```

`local.rules`에 작성한 ICMP Echo Request 탐지 규칙:

```suricata
alert icmp 10.10.10.10 any -> 10.10.10.1 any (msg:"LAB ICMP Ping Detected"; itype:8; sid:1000001; rev:1;)
```

| 필드 | 의미 |
|---|---|
| `alert icmp` | ICMP 조건에 맞으면 경고 기록 |
| `itype:8` | ICMP Echo Request |
| `sid:1000001` | 사용자 정의 규칙 ID |
| `rev:1` | 규칙 버전 |

설정 문법과 서비스 상태를 검증했습니다.

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml
# Configuration provided was successfully loaded.

sudo systemctl restart suricata
sudo systemctl is-active suricata
# active
```

### 6.2 탐지 시험

```bash
ping -c 4 -I eth1 10.10.10.1
```

**결과:** ICMP Echo Request 4회에 대해 SID `1000001` 경고 4건이 `fast.log`와 `eve.json`에 기록됐습니다.

`fast.log` 실제 기록 발췌:

```text
11/18/2026-23:33:56.727689 [**] [1:1000001:1] LAB ICMP Ping Detected [**] [Classification: (null)] [Priority: 3] {ICMP} 10.10.10.10:8 -> 10.10.10.1:0
```

EVE JSON에서 추출한 선택 필드:

```json
{
  "timestamp": "2026-11-18T23:33:56.727689+0900",
  "src_ip": "10.10.10.10",
  "dest_ip": "10.10.10.1",
  "proto": "ICMP",
  "signature": "LAB ICMP Ping Detected",
  "severity": 3
}
```

분석 명령어:

```bash
sudo jq -c 'select(.event_type=="alert" and .alert.signature_id==1000001) | {timestamp,src_ip,dest_ip,proto,signature:.alert.signature,severity:.alert.severity}' /var/log/suricata/eve.json
```

시간·주소·프로토콜·시그니처가 대응하는 **동일한 4개 이벤트를 두 로그 형식으로 교차 확인**했습니다. `fast.log` 4건과 `eve.json` 4건을 합쳐 8개의 독립 이벤트로 계산하지 않았습니다.

> **IDS와 IPS의 차이:** 이 프로젝트에서 Suricata는 *탐지 및 경고(Alert)*를 수행했습니다. Ping은 정상 응답했으며, Suricata가 인라인으로 트래픽을 차단한 것은 아닙니다. OPNsense의 ICMP 정책 차단 시험과 별개의 검증입니다.

### 6.3 증적 보관

Ubuntu-Lab에서 사용자 정의 규칙과 탐지 이벤트를 보관했습니다.

```text
~/security-lab-evidence/suricata/
├── local.rules           # 사용자 정의 ICMP 탐지 규칙
└── icmp-alerts.jsonl     # SID 1000001 탐지 이벤트 4줄
```

---

## 7. 장애 분석 및 검증에서 적용한 방법

| 상황 | 확인한 근거 | 판단·조치 |
|---|---|---|
| VPN Ping 정상, SSH Timeout | `tailscale0` SYN 도착, Live View 기본 차단 | SSH 접근 규칙 및 Alias 로드 상태 조사 |
| `wheel` 그룹인데 sudo 불가 | `secadmin is not in the sudoers file` | OPNsense GUI에서 sudo 정책 설정 후 `(ALL) ALL` 확인 |
| LAN 통신 가능 여부 | `ip -br addr`, `ip route`, Ping, `hn1` tcpdump | 기존 기본 경로 유지, 실습망 통신 검증 |
| 정책 차단 여부 | Ping Request, ICMP Reply 유무, Live View | 차단 규칙의 실제 적용 확인 |
| NAT 수행 여부 | `ip route get`, LAN/WAN tcpdump | 출발지 주소 변환 및 응답 경로 확인 |
| IDS 탐지 여부 | `suricata -T`, 서비스 상태, `fast.log`, EVE JSON | 사용자 규칙 로드와 실제 경고 확인 |

이 프로젝트에서는 **설정 → 시험 → 로그/패킷 확인 → 원인 범위 축소 → 재검증** 순서로 접근했습니다.

---

## 8. 검증 범위와 후속 개선 항목

### 이번 프로젝트에서 검증한 범위

- OPNsense WAN/LAN/MGMT 네트워크 구성 및 MacBook 원격 SSH 관리
- Ubuntu 실습망 ICMP 허용·차단과 방화벽 로그
- 특정 목적지에 대한 라우팅 및 자동 Source NAT 패킷 변환
- Ubuntu `eth1`의 Suricata AF_PACKET IDS 탐지 및 JSON 이벤트 분석

### 후속 검증 항목

- Suricata **인라인 IPS**와 차단 동작 검증
- 별도 센서 또는 미러링을 이용한 **전체망 감시** 구성
- Netplan 고정 IP, Suricata 설정의 **재부팅 후 지속성 검증**
- Suricata의 `unix-manager` 소켓 생성 권한 경고 점검
- 방화벽 규칙 해제 후 ICMP 재시험 증적 추가

이 항목들은 현재 완료했다고 주장하지 않습니다.

---

## 9. 사용한 핵심 명령어

| 명령어 | 목적 |
|---|---|
| `Get-VMNetworkAdapter -VMName "OPNsense-Lab"` | Hyper-V VM의 가상 NIC 및 스위치 연결 확인 |
| `Get-VMNetworkAdapter -VMName "Ubuntu-Lab"` | Ubuntu 실습망 NIC 확인 |
| `ip -br addr` / `ip route` | IP·라우팅 상태 확인 |
| `ping -I eth1 <IP>` | 실습 인터페이스 지정 ICMP 통신 검증 |
| `tcpdump -ni hn1 ...` / `tcpdump -ni hn0 ...` | NAT 전후 LAN/WAN 패킷 관찰 |
| `pfctl -sr` | OPNsense의 실제 필터 규칙 확인 |
| `pfctl -t MACBOOK_TS -T show` | Alias 테이블 상태 점검에 사용할 수 있는 명령(출력 증적 미보존) |
| `sudo suricata -T -c /etc/suricata/suricata.yaml` | IDS 설정·규칙 문법 검사 |
| `systemctl is-active suricata` | IDS 서비스 실행 상태 확인 |
| `jq` | Suricata EVE JSON에서 특정 SID 이벤트 추출 |

---

## 10. 프로젝트를 통해 확인한 점

- **네트워크 연결 성공과 서비스 접근 허용은 다릅니다.** VPN이 연결되어 있어도 방화벽 정책에서 SSH가 차단될 수 있음을 실제 패킷과 로그로 확인했습니다.
- **정책은 설정 화면만으로 검증할 수 없습니다.** Ping 결과, `tcpdump`, Live View 로그를 함께 확인해야 실제 허용·차단 상태를 판단할 수 있었습니다.
- **NAT는 전후 인터페이스를 비교해야 명확해집니다.** 같은 ICMP 시험 흐름을 LAN/WAN에서 관찰해 출발지 주소 변환을 확인했습니다.
- **IDS Alert와 방화벽 Block은 구별해야 합니다.** Suricata의 경고와 OPNsense 방화벽의 차단은 각각 별도로 시험했습니다.

---

## 참고: 기존 개인 보안 실습

- [Ubuntu Server Security Hardening](https://github.com/Gaebong22/ubuntu-security-hardening)
- [Network Security Solution Lab](https://github.com/Gaebong22/network-security-solution-lab)

> **공개 시 유의:** SSH 개인키, 인증 토큰, Tailscale 상태 파일, OPNsense 백업 XML, 인증 URL 및 비밀번호를 저장소에 업로드하지 마세요. 캡처나 로그의 공개 필요성이 없는 IP·계정 정보도 검토 및 마스킹한 뒤 커밋하는 것을 권장합니다.
