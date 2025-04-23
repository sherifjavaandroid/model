#!/usr/bin/env python
# -*- coding: utf-8 -*-

from fastapi import FastAPI, Body, HTTPException, Request, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
import uvicorn
import joblib
import re
import os
import io
import sys
from typing import List, Optional, Dict, Any
import pandas as pd
import json
import logging
from datetime import datetime
import base64
import requests

# استيراد محلل GitHub من المكان الصحيح
from utils.github_analyzer import GitHubAnalyzer, GitHubAnalysisRequest, GitHubAnalysisResponse, FileAnalysisResult

# Fix encoding issues for Windows
if sys.platform.startswith('win'):
    # Change console encoding to UTF-8
    if sys.stdout.encoding != 'utf-8':
        if hasattr(sys.stdout, 'reconfigure'):
            sys.stdout.reconfigure(encoding='utf-8')
        else:
            sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

    # Set Windows console code page to UTF-8
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleCP(65001)
        kernel32.SetConsoleOutputCP(65001)
    except:
        pass

# Create a custom logger that handles UTF-8 properly
class UTF8StreamHandler(logging.StreamHandler):
    def emit(self, record):
        try:
            msg = self.format(record)
            stream = self.stream
            # Use UTF-8 encoding
            stream.buffer.write((msg + self.terminator).encode('utf-8'))
            self.flush()
        except Exception:
            self.handleError(record)

# إعداد التسجيل
logger = logging.getLogger("mobile-security-analyzer")
logger.setLevel(logging.INFO)

# Remove any existing handlers
for handler in logger.handlers[:]:
    logger.removeHandler(handler)

# Add custom UTF-8 handlers
utf8_handler = UTF8StreamHandler(sys.stdout)
utf8_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
logger.addHandler(utf8_handler)

# Add file handler with UTF-8 encoding
file_handler = logging.FileHandler("app.log", encoding='utf-8')
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
logger.addHandler(file_handler)

# Prevent propagation to avoid duplicate logs
logger.propagate = False

# تحميل قاعدة المعرفة الأمنية
from utils.security_knowledge import security_knowledge, expand_security_knowledge
from utils.code_analyzer import extract_security_patterns, analyze_code_security, analyze_code_with_context
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
    file_extension: Optional[str] = None  # إضافة امتداد الملف للتحليل المتقدم
    analyze_context: Optional[bool] = False  # خيار لتفعيل التحليل المتقدم

    class Config:
        json_schema_extra = {
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
                "category": "Finance",
                "file_extension": ".js",
                "analyze_context": True
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

class ContextInfo(BaseModel):
    language: str
    code_complexity: str
    security_score: Dict[str, Any]
    language_specific_analysis: Optional[Dict[str, List[str]]] = None

class SecurityAnalysisResponse(BaseModel):
    vulnerabilities: List[SecurityVulnerability]
    mitigation_strategies: List[MitigationStrategy]
    security_recommendations: List[SecurityRecommendation]
    assessment_tools: List[AssessmentTool]
    context_info: Optional[ContextInfo] = None

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
    # توسيع قاعدة المعرفة باستخدام البيانات المحملة
    expand_security_knowledge(security_data)
    logger.info("تم توسيع قاعدة المعرفة الأمنية بنجاح!")
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
def enrich_response(raw_results, context_info=None):
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

    # إضافة معلومات السياق إذا كانت متوفرة
    if context_info:
        enriched["context_info"] = ContextInfo(
            language=context_info.get("language", "unknown"),
            code_complexity=context_info.get("code_complexity", "Medium"),
            security_score=context_info.get("security_score", {"score": 0, "rating": "F", "risk_level": "Very High"}),
            language_specific_analysis=context_info.get("language_specific_analysis")
        )

    return SecurityAnalysisResponse(**enriched)

# نقطة نهاية لتحليل الكود
@app.post("/analyze", response_model=SecurityAnalysisResponse)
async def analyze_code(request: CodeAnalysisRequest):
    """
    تحليل الكود للكشف عن الثغرات الأمنية وتقديم توصيات.

    - **code**: الكود المصدري المراد تحليله
    - **category**: فئة التطبيق (مثل Finance, Health, Social)
    - **file_extension**: امتداد ملف الكود (اختياري)
    - **analyze_context**: تفعيل التحليل المتقدم (اختياري)
    """
    if not request.code:
        raise HTTPException(status_code=400, detail="الكود لا يمكن أن يكون فارغاً")

    logger.info(f"تحليل كود جديد (الفئة: {request.category}, الطول: {len(request.code)} حرف)")

    try:
        # استخدام التحليل المتقدم إذا تم طلبه
        if request.analyze_context:
            raw_results = analyze_code_with_context(
                request.code,
                request.category,
                request.file_extension
            )
            context_info = raw_results.pop("context_info", None)
            return enrich_response(raw_results, context_info)

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
    except Exception as e:
        logger.error(f"خطأ في تحليل الكود: {e}")
        raise HTTPException(status_code=500, detail=f"حدث خطأ أثناء تحليل الكود: {str(e)}")

# نقطة نهاية لتحليل ملف كود
@app.post("/analyze/file", response_model=SecurityAnalysisResponse)
async def analyze_code_file(
        file: UploadFile = File(...),
        category: str = "Finance",
        analyze_context: bool = False
):
    """
    تحليل ملف كود للكشف عن الثغرات الأمنية.

    - **file**: ملف الكود المراد تحليله
    - **category**: فئة التطبيق (مثل Finance, Health, Social)
    - **analyze_context**: تفعيل التحليل المتقدم (اختياري)
    """
    try:
        # قراءة محتوى الملف
        content = await file.read()
        code = content.decode("utf-8")

        # استخراج امتداد الملف
        filename = file.filename
        file_extension = os.path.splitext(filename)[1] if filename else None

        # إنشاء طلب التحليل
        request = CodeAnalysisRequest(
            code=code,
            category=category,
            file_extension=file_extension,
            analyze_context=analyze_context
        )

        # استدعاء دالة التحليل
        return await analyze_code(request)
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="الملف غير قابل للقراءة أو بتنسيق غير مدعوم")
    except Exception as e:
        logger.error(f"خطأ في تحليل ملف الكود: {e}")
        raise HTTPException(status_code=500, detail=f"حدث خطأ أثناء تحليل ملف الكود: {str(e)}")



# نقطة نهاية لتحليل مستودع GitHub
@app.post("/analyze/github", response_model=GitHubAnalysisResponse)
async def analyze_github_repository(request: GitHubAnalysisRequest):
    """
    تحليل مستودع GitHub كامل.

    - **github_url**: رابط مستودع GitHub
    - **category**: فئة التطبيق
    - **analyze_context**: تفعيل التحليل المتقدم
    - **max_files**: الحد الأقصى لعدد الملفات للتحليل
    - **github_token**: رمز GitHub OAuth (اختياري)
    """
    try:
        # إنشاء محلل GitHub بالرمز المقدم (إن وجد)
        analyzer = GitHubAnalyzer(github_token=request.github_token)

        # الحصول على بيانات التحليل الأولية
        raw_results = analyzer.analyze_repository(
            github_url=str(request.github_url),
            category=request.category,
            analyze_context=request.analyze_context,
            max_files=request.max_files
        )

        # معالجة نتائج تحليل كل ملف وإثرائها
        enriched_files = []
        total_vulnerabilities = 0
        files_with_issues = 0
        vulnerability_types = {}
        common_mitigations = {}

        for file_data in raw_results.get("files", []):
            file_path = file_data.get("path", "")
            analysis_data = file_data.get("analysis_data", {})

            if analysis_data:
                raw_file_results = analysis_data.get("raw_results", {})
                context_info = analysis_data.get("context_info")

                # إثراء نتائج تحليل الملف
                enriched_analysis = enrich_response(raw_file_results, context_info)

                # تحقق مما إذا كانت هناك ثغرات في هذا الملف
                if enriched_analysis.vulnerabilities:
                    # إضافة هذا الملف إلى قائمة الملفات المحللة
                    enriched_files.append(FileAnalysisResult(
                        path=file_path,
                        analysis=enriched_analysis
                    ))

                    # تحديث إحصائيات الملخص
                    files_with_issues += 1
                    total_vulnerabilities += len(enriched_analysis.vulnerabilities)

                    # تجميع أنواع الثغرات
                    for vuln in enriched_analysis.vulnerabilities:
                        vuln_name = vuln.name
                        vulnerability_types[vuln_name] = vulnerability_types.get(vuln_name, 0) + 1

                    # تجميع استراتيجيات التخفيف
                    for mit in enriched_analysis.mitigation_strategies:
                        mit_name = mit.name
                        common_mitigations[mit_name] = common_mitigations.get(mit_name, 0) + 1

        # ترتيب الثغرات واستراتيجيات التخفيف حسب التكرار
        vulnerability_types = dict(sorted(vulnerability_types.items(), key=lambda x: x[1], reverse=True))
        common_mitigations = dict(sorted(common_mitigations.items(), key=lambda x: x[1], reverse=True))

        # إنشاء النتيجة النهائية
        response = GitHubAnalysisResponse(
            repository=raw_results.get("repository", {}),
            files=enriched_files,
            summary={
                "total_vulnerabilities": total_vulnerabilities,
                "files_with_issues": files_with_issues,
                "vulnerability_types": vulnerability_types,
                "common_mitigations": common_mitigations
            }
        )

        return response
    except Exception as e:
        logger.error(f"Error analyzing GitHub repository: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# نقطة نهاية للصفحة الرئيسية
@app.get("/")
async def root():
    return {
        "message": "مرحباً بك في واجهة برمجة تطبيقات محلل أمان التطبيقات المحمولة",
        "documentation": "/docs",
        "analyze_endpoint": "/analyze",
        "analyze_file_endpoint": "/analyze/file",
        "analyze_github_endpoint": "/analyze/github"
    }

# نقطة نهاية للحصول على الفئات
@app.get("/categories")
async def get_categories():
    """الحصول على قائمة بجميع فئات التطبيقات من مجموعة البيانات."""
    if security_data is not None:
        categories = security_data['Category'].unique().tolist()
        return {"categories": categories}
    return {"categories": ["Finance", "Health", "Social", "Productivity", "Travel", "Education",
                           "Lifestyle", "Entertainment", "Food & Drink", "Shopping", "Communication",
                           "Art & Design", "Business", "Events", "Environment", "Music", "Sports"]}

# نقطة نهاية للحصول على الثغرات
@app.get("/vulnerabilities")
async def get_vulnerabilities():
    """الحصول على قائمة بجميع الثغرات الأمنية من قاعدة المعرفة."""
    vulnerabilities = []

    for name, info in security_knowledge["vulnerabilities"].items():
        vulnerabilities.append({
            "name": name,
            "description": info.get("description", ""),
            "severity": info.get("severity", "Medium")
        })

    # ترتيب الثغرات حسب الخطورة
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    vulnerabilities.sort(key=lambda x: severity_order.get(x["severity"], 4))

    return {"vulnerabilities": vulnerabilities}

# نقطة نهاية للتحقق من حالة الخدمة
@app.get("/status")
async def get_status():
    """التحقق من حالة الخدمة والنموذج."""
    return {
        "api_status": "online",
        "model_loaded": model is not None and vectorizer is not None,
        "dataset_loaded": security_data is not None,
        "num_records": len(security_data) if security_data is not None else 0,
        "num_vulnerabilities": len(security_knowledge["vulnerabilities"]),
        "num_mitigations": len(security_knowledge["mitigations"]),
        "num_tools": len(security_knowledge["tools"]),
        "environment": os.environ.get("ENVIRONMENT", "development"),
        "version": "1.2.0"  # تحديث الإصدار بعد إضافة ميزة GitHub
    }

# تشغيل التطبيق
if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)