# IdeaGuard 🛡️

![HTML5](https://img.shields.io/badge/HTML5-E34F26?style=for-the-badge&logo=html5&logoColor=white)
![CSS3](https://img.shields.io/badge/CSS3-1572B6?style=for-the-badge&logo=css3&logoColor=white)
![JavaScript](https://img.shields.io/badge/JavaScript-323330?style=for-the-badge&logo=javascript&logoColor=F7DF1E)
![Cloudflare Pages](https://img.shields.io/badge/Cloudflare%20Pages-F38020?style=for-the-badge&logo=Cloudflare&logoColor=white)
![Cloudflare Workers](https://img.shields.io/badge/Cloudflare%20Workers-F38020?style=for-the-badge&logo=Cloudflare&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge)

**Zero-Knowledge 기반 SHA-256 아이디어 해시 등록 및 NDA 발급 서비스**  
*Your ideas, cryptographically secured without exposing the content.*

## 📖 프로젝트 개요 (Overview)
**IdeaGuard**는 사용자의 소중한 아이디어를 보호하기 위해 **Zero-Knowledge SHA-256 해시 증명** 방식을 사용하여, 원본 데이터를 서버로 전송하지 않고 브라우저(클라이언트) 단에서 해시값만 생성해 등록하는 안전한 서비스입니다. 아이디어가 보호됨을 증명하는 해시값과 함께 **NDA (비밀유지계약서)**를 자동으로 제공합니다.

## ✨ 주요 기능 (Features)
- **클라이언트 사이드 해싱 (Client-Side Hashing):** 원본 데이터가 절대 네트워크를 타지 않으며 브라우저 내에서 SHA-256 해시가 계산됩니다.
- **다크 모드 UI (Cryptographic Dark Theme):** 전문가와 SaaS 수준에 걸맞는 세련되고 신뢰감 있는 다크 테마 디자인을 적용했습니다.
- **빠르고 안전한 검증 (Fast & Secure Verification):** 생성된 해시값을 통해 언제든 아이디어의 원본 여부 및 등록 시점을 검증할 수 있습니다.
- **Serverless API 통신:** Cloudflare Workers 기반의 빠르고 가벼운 백엔드 API와 통신하여 데이터를 안전하게 처리합니다.

## 🛠️ 기술 스택 (Tech Stack)
- **Frontend:** Vanilla HTML5, CSS3, JavaScript (ES6+)
- **Backend (API):** Cloudflare Workers (`https://ideaguard-worker.nalbadaju.workers.dev`)
- **Database:** Supabase PostgreSQL (ap-northeast-1 / Tokyo)
- **Hosting:** Cloudflare Pages
- **Design:** Pretendard (Korean), Montserrat (English), FontAwesome 6 Free

## 🚀 시작하기 (Getting Started)
로컬에서 프로젝트를 실행하려면 아래 단계를 따르세요.

1. 저장소를 클론합니다.
   ```bash
   git clone https://github.com/nalbadaju/ideaguard.git
   ```
2. 프로젝트 폴더로 이동합니다.
   ```bash
   cd ideaguard
   ```
3. 로컬 서버를 실행합니다. (예: VS Code의 Live Server, Python http.server 등)
   ```bash
   # Python 3 예시
   python -m http.server 8000
   ```
4. 브라우저에서 `http://localhost:8000`으로 접속합니다.

## 🔗 API 엔드포인트
| Method | Path | 기능 |
|--------|------|------|
| `GET`  | `/api/health` | 서버 상태 확인 |
| `GET`  | `/api/records` | 타일 목록 조회 |
| `POST` | `/api/records` | 해시 등록 |
| `POST` | `/api/records/verify` | 해시 검증 |
| `POST` | `/api/nda` | NDA 계약서 생성 |
| `GET`  | `/api/nda/:token` | NDA 조회 |
| `POST` | `/api/nda/:token/sign` | NDA 서명 |

## 🛡️ 보안 헤더 설정 (Security)
Cloudflare Pages 배포 시 `_headers` 파일을 통해 **CSP**, **X-Frame-Options** 등 강력한 보안 헤더를 적용하여 XSS 및 클릭재킹을 방지합니다.

## 🔐 Zero-Knowledge 원칙
- 원본 파일/텍스트 → 브라우저 Web Crypto API에서만 처리
- SHA-256 해시값만 서버 전송 (원본 내용 미전송)
- DB에 `originalContent` 컬럼 없음
- NDA `token_hash`만 저장 (plaintext token은 이메일로만 전달)

## 📄 라이선스 (License)
이 프로젝트는 [MIT License](LICENSE)를 따릅니다.
