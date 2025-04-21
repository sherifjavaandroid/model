#!/usr/bin/env python
# -*- coding: utf-8 -*-

import pandas as pd
import numpy as np
import logging
import os
from typing import Tuple, Dict, Optional

logger = logging.getLogger("data-utils")

def load_dataset(data_path: str) -> pd.DataFrame:
    """
    تحميل وتحقق من مجموعة بيانات أمان التطبيقات.

    المعاملات:
        data_path (str): مسار ملف البيانات (CSV)

    العوائد:
        DataFrame: إطار البيانات المحمل

    Raises:
        FileNotFoundError: إذا لم يتم العثور على ملف البيانات
        ValueError: إذا كانت البيانات تفتقر إلى الأعمدة المطلوبة
    """
    if not os.path.exists(data_path):
        raise FileNotFoundError(f"ملف البيانات غير موجود: {data_path}")

    # تحميل البيانات
    df = pd.read_csv(data_path)

    # التحقق من الأعمدة المطلوبة
    required_columns = [
        'Category',
        'Security_Practice_Used',
        'Vulnerability_Types',
        'Mitigation_Strategies',
        'Developer_Challenges',
        'Assessment_Tools_Used',
        'Improvement_Suggestions'
    ]

    missing_columns = [col for col in required_columns if col not in df.columns]
    if missing_columns:
        raise ValueError(f"البيانات تفتقر إلى الأعمدة المطلوبة: {', '.join(missing_columns)}")

    return df

def preprocess_data(data_path: str) -> Tuple[pd.DataFrame, Dict[str, int]]:
    """
    معالجة البيانات الأولية لمجموعة بيانات أمان التطبيقات.

    المعاملات:
        data_path (str): مسار ملف البيانات (CSV)

    العوائد:
        Tuple[DataFrame, Dict]: إطار البيانات المعالج وخريطة الفئات
    """
    logger.info(f"معالجة البيانات من {data_path}...")

    # تحميل البيانات
    df = load_dataset(data_path)

    # عرض معلومات أساسية
    logger.info(f"شكل مجموعة البيانات الأصلية: {df.shape}")

    # معالجة القيم المفقودة
    df = df.dropna()
    logger.info(f"شكل مجموعة البيانات بعد إزالة القيم المفقودة: {df.shape}")

    # معالجة الفئات
    category_counts = df['Category'].value_counts()
    logger.info(f"توزيع الفئات (أعلى 5): \n{category_counts.head()}")

    # إنشاء ميزات مدمجة للتمثيل النصي
    df['combined_features'] = (
            df['Category'] + ' ' +
            df['Security_Practice_Used'] + ' ' +
            df['Vulnerability_Types'] + ' ' +
            df['Mitigation_Strategies'] + ' ' +
            df['Assessment_Tools_Used']
    )

    # إنشاء خريطة الفئات
    category_map = {cat: i for i, cat in enumerate(df['Category'].unique())}
    df['category_id'] = df['Category'].map(category_map)

    return df, category_map

def get_category_vulnerabilities(data_df: pd.DataFrame) -> Dict[str, Dict[str, int]]:
    """
    الحصول على الثغرات الأمنية الأكثر شيوعاً لكل فئة.

    المعاملات:
        data_df (DataFrame): إطار البيانات المعالج

    العوائد:
        Dict: قاموس من الثغرات الأمنية لكل فئة مع تكرارها
    """
    if data_df is None:
        return {}

    category_vulns = {}

    for category in data_df['Category'].unique():
        # تصفية البيانات حسب الفئة
        category_data = data_df[data_df['Category'] == category]

        # جمع جميع الثغرات المرتبطة بهذه الفئة
        all_vulnerabilities = []
        for vulns in category_data['Vulnerability_Types']:
            if pd.notna(vulns):
                all_vulnerabilities.extend([v.strip() for v in vulns.split(',')])

        # حساب تكرار كل ثغرة
        vuln_counts = {}
        for vuln in all_vulnerabilities:
            if vuln in vuln_counts:
                vuln_counts[vuln] += 1
            else:
                vuln_counts[vuln] = 1

        # ترتيب الثغرات حسب التكرار
        sorted_vulns = {k: v for k, v in sorted(vuln_counts.items(), key=lambda item: item[1], reverse=True)}

        category_vulns[category] = sorted_vulns

    return category_vulns

def get_common_mitigations(data_df: pd.DataFrame, vulnerability: str) -> Dict[str, int]:
    """
    الحصول على استراتيجيات التخفيف الشائعة لثغرة أمنية محددة.

    المعاملات:
        data_df (DataFrame): إطار البيانات المعالج
        vulnerability (str): اسم الثغرة الأمنية

    العوائد:
        Dict: قاموس من استراتيجيات التخفيف مع تكرارها
    """
    if data_df is None:
        return {}

    # تصفية البيانات للعثور على السجلات التي تحتوي على الثغرة المحددة
    vuln_data = data_df[data_df['Vulnerability_Types'].str.contains(vulnerability, na=False)]

    # جمع جميع استراتيجيات التخفيف المرتبطة بهذه الثغرة
    all_mitigations = []
    for mits in vuln_data['Mitigation_Strategies']:
        if pd.notna(mits):
            all_mitigations.extend([m.strip() for m in mits.split(',')])

    # حساب تكرار كل استراتيجية
    mit_counts = {}
    for mit in all_mitigations:
        if mit in mit_counts:
            mit_counts[mit] += 1
        else:
            mit_counts[mit] = 1

    # ترتيب الاستراتيجيات حسب التكرار
    sorted_mits = {k: v for k, v in sorted(mit_counts.items(), key=lambda item: item[1], reverse=True)}

    return sorted_mits

def get_recommendations_for_category(data_df: pd.DataFrame, category: str) -> list:
    """
    الحصول على توصيات التحسين لفئة محددة.

    المعاملات:
        data_df (DataFrame): إطار البيانات المعالج
        category (str): فئة التطبيق

    العوائد:
        list: قائمة من توصيات التحسين
    """
    if data_df is None:
        return []

    # تصفية البيانات حسب الفئة
    category_data = data_df[data_df['Category'] == category]

    # جمع جميع التوصيات المرتبطة بهذه الفئة
    all_recommendations = []
    for recs in category_data['Improvement_Suggestions']:
        if pd.notna(recs):
            all_recommendations.append(recs.strip())

    # إزالة التكرارات
    unique_recommendations = list(set(all_recommendations))

    return unique_recommendations

def get_tool_usage_stats(data_df: pd.DataFrame) -> Dict[str, int]:
    """
    الحصول على إحصائيات استخدام أدوات التقييم.

    المعاملات:
        data_df (DataFrame): إطار البيانات المعالج

    العوائد:
        Dict: قاموس من أدوات التقييم مع تكرار استخدامها
    """
    if data_df is None:
        return {}

    # جمع جميع أدوات التقييم
    all_tools = []
    for tools in data_df['Assessment_Tools_Used']:
        if pd.notna(tools):
            all_tools.extend([t.strip() for t in tools.split(',')])

    # حساب تكرار كل أداة
    tool_counts = {}
    for tool in all_tools:
        if tool in tool_counts:
            tool_counts[tool] += 1
        else:
            tool_counts[tool] = 1

    # ترتيب الأدوات حسب التكرار
    sorted_tools = {k: v for k, v in sorted(tool_counts.items(), key=lambda item: item[1], reverse=True)}

    return sorted_tools

def export_analysis_results(data_df: pd.DataFrame, output_dir: str = "analysis_results") -> None:
    """
    تصدير نتائج تحليل البيانات إلى ملفات CSV.

    المعاملات:
        data_df (DataFrame): إطار البيانات المعالج
        output_dir (str): مجلد الإخراج
    """
    if data_df is None:
        logger.warning("لا يمكن تصدير نتائج التحليل: البيانات غير متوفرة")
        return

    # إنشاء مجلد الإخراج إذا لم يكن موجوداً
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # تصدير إحصائيات استخدام الأدوات
    tool_stats = get_tool_usage_stats(data_df)
    tool_df = pd.DataFrame(list(tool_stats.items()), columns=['Tool', 'Usage_Count'])
    tool_df.to_csv(os.path.join(output_dir, "tool_usage_stats.csv"), index=False)

    # تصدير الثغرات حسب الفئة
    category_vulns = get_category_vulnerabilities(data_df)
    for category, vulns in category_vulns.items():
        if vulns:
            vuln_df = pd.DataFrame(list(vulns.items()), columns=['Vulnerability', 'Count'])
            safe_category = category.replace('/', '_').replace(' ', '_')
            vuln_df.to_csv(os.path.join(output_dir, f"{safe_category}_vulnerabilities.csv"), index=False)

    # تصدير فئات التطبيقات
    category_counts = data_df['Category'].value_counts()
    category_df = pd.DataFrame(category_counts).reset_index()
    category_df.columns = ['Category', 'Count']
    category_df.to_csv(os.path.join(output_dir, "category_distribution.csv"), index=False)

    logger.info(f"تم تصدير نتائج التحليل إلى مجلد {output_dir}")