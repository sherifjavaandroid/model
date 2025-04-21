#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
حزمة المرافق لنظام تحليل أمان التطبيقات المحمولة.
تحتوي على وحدات لتحليل الكود ومعالجة البيانات وقاعدة المعرفة الأمنية.
"""

from .code_analyzer import extract_security_patterns, analyze_code_security
from .data_utils import (
    load_dataset,
    preprocess_data,
    get_category_vulnerabilities,
    get_common_mitigations,
    get_recommendations_for_category,
    get_tool_usage_stats,
    export_analysis_results
)
from .security_knowledge import security_knowledge, expand_security_knowledge

__version__ = '1.0.0'