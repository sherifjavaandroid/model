#!/usr/bin/env python
# -*- coding: utf-8 -*-

from fastapi import FastAPI, Body, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn
import joblib
import re
import os
from typing import List, Optional, Dict, Any
import pandas as pd
import json
import logging
from datetime import datetime

# إعداد التسجيل
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("app.log")
    ]
)
logger = logging.getLogger("mobile-security-analyzer")

# تحميل قاعدة المعرفة الأمنية
from utils.security_knowledge import security_knowledge
from utils.code_analyzer import extract_security_patterns, analyze_code_security
from utils.data_utils import load_dataset

# تعريف الـ FastAPI
app = FastAPI(
    title="Mobile Security Analyzer API",
    description="An API for analyzing code for security vulnerabilities based on the Mobile Security Dataset",
    version="1.0.0"
)

# إضافة CORS middleware للسماح بالطلبات من مختلف المصادر
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # يسمح بالوصول من أي مصدر (يمكن تعديله للإنتاج)
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# تعريف نماذج الطلب والاستجابة
class CodeAnalysisRequest(BaseModel):
    code: str
    category: str = "Finance"  # القيمة الافتراضية هي Finance

    class Config:
        schema_extra = {
            "example": {
                "code": """
                function login(username, password) {
                    var query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'";
                    connection.query(query, function(err, results) {
                        if (results.length > 0) {
                            session.user = results[0];
                            return true;
                        }
                        return false;
                    });
                }
                """,
                "category": "Finance"
            }
        }

class SecurityVulnerability(BaseModel):
    name: str
    description: str
    severity: str

class MitigationStrategy(BaseModel):
    name: str
    description: str
    implementation_complexity: str

class SecurityRecommendation(BaseModel):
    description: str
    priority: str

class AssessmentTool(BaseModel):
    name: str
    purpose: str
    url: Optional[str] = None

class SecurityAnalysisResponse(BaseModel):
    vulnerabilities: List[SecurityVulnerability]
    mitigation_strategies: List[MitigationStrategy]
    security_recommendations: List[SecurityRecommendation]
    assessment_tools: List[AssessmentTool]

# المسارات للملفات والمجلدات
MODEL_DIR = os.environ.get("MODEL_DIR", "models")
DATA_PATH = os.environ.get("DATA_PATH", "data/Mobile_Security_Dataset.csv")

# تحميل النموذج والمحول
try:
    model_path = os.path.join(MODEL_DIR, "security_model.joblib")
    vectorizer_path = os.path.join(MODEL_DIR, "vectorizer.joblib")

    model = joblib.load(model_path)
    vectorizer = joblib.load(vectorizer_path)
    logger.info("تم تحميل النموذج والمحول بنجاح!")
except Exception as e:
    logger.warning(f"لم يتم العثور على النموذج أو المحول: {e}")
    model = None
    vectorizer = None

# تحميل مجموعة البيانات
try:
    security_data = load_dataset(DATA_PATH)
    logger.info(f"تم تحميل مجموعة البيانات بنجاح! {len(security_data)} سجل.")
except Exception as e:
    logger.warning(f"لم يتم العثور على مجموعة البيانات: {e}")
    security_data = None

# وسيط لتسجيل الطلبات والاستجابات
@app.middleware("http")
async def log_requests(request: Request, call_next):
    # تسجيل معلومات الطلب
    request_id = f"{datetime.now().strftime('%Y%m%d%H%M%S')}-{id(request)}"
    logger.info(f"طلب جديد: {request_id} - {request.method} {request.url.path}")

    # تنفيذ الطلب
    response = await call_next(request)

    # تسجيل معلومات الاستجابة
    logger.info(f"استجابة: {request_id} - {response.status_code}")

    return response

# دالة لإثراء النتائج بمعلومات من قاعدة المعرفة
def enrich_response(raw_results):
    """إثراء نتائج التحليل الأولية بمعلومات من قاعدة المعرفة."""
    enriched = {
        "vulnerabilities": [],
        "mitigation_strategies": [],
        "security_recommendations": [],
        "assessment_tools": []
    }

    # إثراء الثغرات الأمنية
    for vuln in raw_results.get("vulnerabilities", []):
        vuln_name = vuln if isinstance(vuln, str) else vuln.get("name", "")
        vuln_info = security_knowledge["vulnerabilities"].get(vuln_name, {})

        enriched["vulnerabilities"].append(SecurityVulnerability(
            name=vuln_name,
            description=vuln_info.get("description", "A security vulnerability that could compromise the application."),
            severity=vuln_info.get("severity", "Medium")
        ))

    # إثراء استراتيجيات التخفيف
    for strat in raw_results.get("mitigation_strategies", []):
        strat_name = strat if isinstance(strat, str) else strat.get("name", "")
        strat_info = security_knowledge["mitigations"].get(strat_name, {})

        enriched["mitigation_strategies"].append(MitigationStrategy(
            name=strat_name,
            description=strat_info.get("description", "A strategy to mitigate security vulnerabilities."),
            implementation_complexity=strat_info.get("implementation_complexity", "Medium")
        ))

    # إثراء التوصيات الأمنية
    for rec in raw_results.get("security_recommendations", []):
        rec_desc = rec if isinstance(rec, str) else rec.get("description", "")

        enriched["security_recommendations"].append(SecurityRecommendation(
            description=rec_desc,
            priority="High" if "critical" in rec_desc.lower() else "Medium"
        ))

    # إثراء أدوات التقييم
    for tool in raw_results.get("assessment_tools", []):
        tool_name = tool if isinstance(tool, str) else tool.get("name", "")
        tool_info = security_knowledge["tools"].get(tool_name, {})

        enriched["assessment_tools"].append(AssessmentTool(
            name=tool_name,
            purpose=tool_info.get("purpose", "A security assessment tool."),
            url=tool_info.get("url")
        ))

    return SecurityAnalysisResponse(**enriched)

# نقطة نهاية لتحليل الكود
@app.post("/analyze", response_model=SecurityAnalysisResponse)
async def analyze_code(request: CodeAnalysisRequest):
    """
    تحليل الكود للكشف عن الثغرات الأمنية وتقديم توصيات.

    - **code**: الكود المصدري المراد تحليله
    - **category**: فئة التطبيق (مثل Finance, Health, Social)
    """
    if not request.code:
        raise HTTPException(status_code=400, detail="الكود لا يمكن أن يكون فارغاً")

    logger.info(f"تحليل كود جديد (الفئة: {request.category}, الطول: {len(request.code)} حرف)")

    # إذا كان النموذج متاحاً، استخدمه
    if model is not None and vectorizer is not None:
        try:
            # استخراج الميزات من الكود
            patterns = extract_security_patterns(request.code)
            feature_text = f"Category: {request.category} "
            for key, value in patterns.items():
                if value:
                    feature_text += f"{key} "

            # تحويل الميزات إلى متجه
            X = vectorizer.transform([feature_text])

            # الحصول على التنبؤات
            predictions = model.predict(X)

            # استخراج النتائج
            raw_results = {
                "vulnerabilities": predictions[0][0].split(', '),
                "mitigation_strategies": predictions[0][1].split(', '),
                "security_recommendations": predictions[0][2].split(', '),
                "assessment_tools": predictions[0][3].split(', ')
            }

            logger.info(f"تم تحليل الكود بنجاح باستخدام النموذج، تم العثور على {len(raw_results['vulnerabilities'])} ثغرة أمنية")

            # إثراء النتائج وإرجاعها
            return enrich_response(raw_results)

        except Exception as e:
            logger.error(f"خطأ في تحليل الكود باستخدام النموذج: {e}")
            # الانتقال إلى التحليل المستند إلى القواعد كملاذ أخير
            return enrich_response(analyze_code_security(request.code, request.category))
    else:
        # إذا لم يكن النموذج متاحاً، استخدم التحليل المستند إلى القواعد
        logger.info("استخدام التحليل المستند إلى القواعد (النموذج غير متوفر)")
        return enrich_response(analyze_code_security(request.code, request.category))

# نقطة نهاية للصفحة الرئيسية
@app.get("/")
async def root():
    return {
        "message": "مرحباً بك في واجهة برمجة تطبيقات محلل أمان التطبيقات المحمولة",
        "documentation": "/docs",
        "analyze_endpoint": "/analyze"
    }

# نقطة نهاية للحصول على الفئات
@app.get("/categories")
async def get_categories():
    """الحصول على قائمة بجميع فئات التطبيقات من مجموعة البيانات."""
    if security_data is not None:
        categories = security_data['Category'].unique().tolist()
        return {"categories": categories}
    return {"categories": ["Finance", "Health", "Social", "Productivity", "Travel", "Education"]}

# نقطة نهاية للتحقق من حالة الخدمة
@app.get("/status")
async def get_status():
    """التحقق من حالة الخدمة والنموذج."""
    return {
        "api_status": "online",
        "model_loaded": model is not None and vectorizer is not None,
        "dataset_loaded": security_data is not None,
        "num_records": len(security_data) if security_data is not None else 0,
        "environment": os.environ.get("ENVIRONMENT", "development"),
        "version": "1.0.0"
    }

# تشغيل التطبيق
if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)