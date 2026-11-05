# URL Guard

URL을 입력하면 Python AI와 룰 분석 결과를 합쳐 위험도, 탐지 이유, 공격 유형, 대응 방법을 보여주는 팀 프로젝트입니다.

## 배포 구조

```text
방문자 → GitHub Pages (public/)
                  ↓ HTTPS 요청
          Python FastAPI 서버
                  ↓
          AI + Rule → report_generator.py
                  ↓
              결과 화면
```

방문자 로그인은 필요하지 않습니다. AI는 Python 서버에서 실행되며, GitHub Pages는 화면만 제공합니다. GitHub 계정과 Python 호스팅 계정은 개발자가 배포할 때 사용합니다.

## 로컬 실행

Python 3.10 이상을 설치한 뒤 이 폴더에서 실행합니다.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -X utf8 ai/train_model.py
.\.venv\Scripts\python.exe -m uvicorn server:app --host 127.0.0.1 --port 8000
```

http://127.0.0.1:8000 에 접속합니다. 화면과 AI를 같은 서버에서 제공하므로 별도 주소 설정은 없습니다. 학습 모델은 Git에 올리지 않고 배포 환경에서 생성합니다.

## 온라인 배포

1. 이 프로젝트를 GitHub 저장소 루트에 업로드합니다. .github/workflows/도 포함해야 합니다.
2. Render에서 이 저장소의 render.yaml을 사용하는 Python 서비스를 생성합니다. 무료 플랜만 지정되어 있으며 결제·플랜 변경은 별도 작업입니다.
3. Python 서비스의 ALLOWED_ORIGINS를 `https://umini1002.github.io`로 지정합니다. 저장소 경로나 끝의 /를 붙이지 않습니다.
4. Python 서비스가 준비되면 HTTPS 기본 주소를 확인합니다. /api/health에서 model_ready가 true여야 합니다.
5. GitHub 저장소의 Settings → Secrets and variables → Actions → Variables에서 API_BASE_URL을 생성하고 Python 서비스 기본 주소를 입력합니다. `/api/analyze`는 붙이지 않습니다. 서버 주소는 공개 설정이며 비밀키가 아닙니다.
6. Settings → Pages → Source를 GitHub Actions로 선택합니다.
7. Actions에서 Deploy frontend to GitHub Pages를 실행합니다. 이후 main 변경 시 자동 실행됩니다.

API_BASE_URL이 없거나 유효한 HTTPS 기본 주소가 아니면 Pages 빌드는 의도적으로 중단됩니다. 동작하지 않는 API에 연결한 화면을 배포 완료로 처리하지 않기 위한 설정입니다.

Render에 GitHub 저장소 접근을 승인하거나 호스팅 계정을 생성하는 절차는 해당 계정 소유자가 확인해야 합니다. 무료 서비스의 가용성·한도는 Render 정책을 따릅니다. 사용하지 않는 동안 중단된 서버는 첫 요청이 늦을 수 있습니다.

## 주요 파일

- public/: 사용자 화면. 모델·GitHub 비밀번호·토큰이 포함되지 않습니다.
- public/config.js: 로컬용 기본 설정. Pages 배포 시 API_BASE_URL로 자동 생성됩니다.
- scripts/build-pages.mjs: 정적 파일만 _site/에 복사합니다.
- server.py: API 및 로컬 화면 제공, CORS 설정.
- analysis_pipeline.py: AI와 룰 결과를 리포트로 연결.
- report_generator.py: 위험도·이유·유형·대응 방법 생성.
- ai/: 팀원의 Python 코드 및 학습·테스트 데이터.
- render.yaml: Python 서비스 배포 설정.
- .github/workflows/: Python 테스트와 Pages 배포 자동화.

## 검증

```powershell
.\.venv\Scripts\python.exe -m pip install httpx
.\.venv\Scripts\python.exe -X utf8 -m unittest discover -s tests -p 'test_*.py' -v
$env:API_BASE_URL='https://api.example.com'
node scripts/build-pages.mjs
node --test tests/pages.test.mjs
```

예시 API 주소는 빌드·코드 테스트용이며 실제 배포에는 사용하지 않습니다.

## 분석 정책 및 출처

원본 AI 코드: https://github.com/seo905/AI-URL-/tree/main/phishing-url-detection

원본 버전: e9853c28b06f591fac8ce27c0d63fb05124b818b

원본 저장소를 수정하지 않고 통합했습니다. 가중치는 임시로 AI 80%·룰 20%, 룰 최대 점수는 20입니다. 종합 점수는 실제 피싱 확률이 아닙니다. 세부 공격 유형은 원본에서 제공하지 않아 미확인으로 표시합니다. 공개 전 팀에서 가중치와 원본 코드 사용 조건을 확인하세요.

## 공식 배포 문서

- https://docs.github.com/en/pages/getting-started-with-github-pages/using-custom-workflows-with-github-pages
- https://render.com/docs/deploy-fastapi
- https://render.com/docs/blueprint-spec
