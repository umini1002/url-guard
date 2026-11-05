"""Local Python service: uvicorn server:app --host 127.0.0.1 --port 8000."""
import logging
import os
from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from analysis_pipeline import analyze_url

ROOT = Path(__file__).resolve().parent
app = FastAPI(title='URL Guard API')
origins = [v.strip() for v in os.environ.get('ALLOWED_ORIGINS', '').split(',') if v.strip()]
if origins:
    app.add_middleware(CORSMiddleware, allow_origins=origins, allow_methods=['POST', 'GET'], allow_headers=['Content-Type'])

class AnalysisRequest(BaseModel):
    url: str = Field(min_length=1, max_length=4096)

@app.get('/api/health')
def health():
    return {'model_ready': (ROOT / 'ai/model/xgboost_model.pkl').exists(), 'feature_count': 23, 'training_data': 'team_provided_dataset'}

@app.post('/api/analyze')
def analyze(body: AnalysisRequest):
    try:
        return analyze_url(body.url)
    except FileNotFoundError:
        raise HTTPException(503, '분석 서비스 준비 중입니다. 잠시 후 다시 시도해 주세요.')
    except (ValueError, UnicodeError):
        raise HTTPException(422, '올바른 http/https 주소를 입력해 주세요.')
    except Exception:
        logging.exception('Analysis failed')
        raise HTTPException(503, '분석을 완료하지 못했습니다. 잠시 후 다시 시도해 주세요.')

app.mount('/', StaticFiles(directory=ROOT / 'public', html=True), name='website')