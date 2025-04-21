#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
from typing import Dict, List, Any, Tuple
import logging

logger = logging.getLogger("code-analyzer")

def extract_security_patterns(code: str) -> Dict[str, bool]:
    """
    استخراج أنماط أمنية من الكود المصدري.

    المعاملات:
        code (str): الكود المصدري للتحليل

    العوائد:
        Dict[str, bool]: قاموس من أنماط الأمان وما إذا كانت موجودة في الكود
    """
    patterns = {
        "Authentication": re.search(r'auth|login|signin|password|credential', code, re.I) is not None,
        "SQL Queries": re.search(r'SELECT|INSERT|UPDATE|DELETE.*FROM|query|sql|database', code, re.I) is not None,
        "SQL Injection Risk": re.search(r"'.*\+.*'|`.*\+.*`|\".*\+.*\"|'.*\$|`.*\$|\".*\$", code, re.I) is not None,
        "Input Validation": re.search(r'validate|sanitize|escape|filter|clean', code, re.I) is not None,
        "Encryption": re.search(r'encrypt|decrypt|AES|RSA|hash|MD5|SHA|crypto|ssl|tls', code, re.I) is not None,
        "Session Management": re.search(r'session|cookie|token|jwt|auth.*token', code, re.I) is not None,
        "Error Handling": re.search(r'try|catch|exception|error|throw|finally', code, re.I) is not None,
        "XSS Prevention": re.search(r'htmlspecialchars|escapeHTML|sanitize|innerText|textContent', code, re.I) is not None,
        "File Operations": re.search(r'file|upload|download|read|write|fs\.|path\.', code, re.I) is not None,
        "API Security": re.search(r'api|rest|http|fetch|axios|ajax', code, re.I) is not None,
        "Sensitive Data": re.search(r'credit.*card|password|token|key|secret|ssn|social|security', code, re.I) is not None,
        "HTTPS Usage": re.search(r'https:|HTTPS|TLS|SSL', code, re.I) is not None,
        "Authentication Bypass": re.search(r'admin|root|superuser|bypass', code, re.I) is not None,
        "Hardcoded Credentials": re.search(r'password\s*=\s*[\'"`]|apiKey\s*=\s*[\'"`]|secret\s*=\s*[\'"`]', code, re.I) is not None,
        "Command Injection": re.search(r'exec|eval|system|spawn|shell|child_process|subprocess', code, re.I) is not None,
        "Insecure Deserialization": re.search(r'deserialize|fromJSON|parse|unmarshal', code, re.I) is not None,
        "Weak Cryptography": re.search(r'MD5|SHA1', code, re.I) is not None
    }

    return patterns

def analyze_code_security(code: str, category: str) -> Dict[str, List[str]]:
    """
    تحليل أمان الكود باستخدام نهج قائم على القواعد.

    المعاملات:
        code (str): الكود المصدري للتحليل
        category (str): فئة التطبيق

    العوائد:
        Dict[str, List[str]]: نتائج التحليل، تتضمن الثغرات واستراتيجيات التخفيف والتوصيات والأدوات
    """
    patterns = extract_security_patterns(code)
    results = {
        "vulnerabilities": [],
        "mitigation_strategies": [],
        "security_recommendations": [],
        "assessment_tools": []
    }

    # كشف حقن SQL
    if patterns["SQL Queries"] and patterns["SQL Injection Risk"]:
        results["vulnerabilities"].append("SQL Injection")
        results["mitigation_strategies"].append("Parameterized Queries")
        results["security_recommendations"].append("Use prepared statements or parameterized queries instead of string concatenation")
        results["assessment_tools"].append("OWASP ZAP")
        results["assessment_tools"].append("SQLMap")

    # كشف ضعف المصادقة
    if patterns["Authentication"] and not patterns["Input Validation"]:
        results["vulnerabilities"].append("Weak Authentication")
        results["mitigation_strategies"].append("Input Validation")
        results["security_recommendations"].append("Implement strict input validation for all user-provided credentials")
        results["assessment_tools"].append("OWASP ZAP")

    # كشف البيانات الحساسة غير المشفرة
    if patterns["Sensitive Data"] and not patterns["Encryption"]:
        results["vulnerabilities"].append("Sensitive Data Exposure")
        results["mitigation_strategies"].append("Data Encryption")
        results["security_recommendations"].append("Encrypt sensitive data both at rest and in transit")
        results["assessment_tools"].append("Burp Suite")

    # كشف مشاكل إدارة الجلسات
    if patterns["Session Management"] and not patterns["HTTPS Usage"]:
        results["vulnerabilities"].append("Insecure Session Management")
        results["mitigation_strategies"].append("Secure Session Handling")
        results["security_recommendations"].append("Use secure cookies and HTTPS for all session management")
        results["assessment_tools"].append("OWASP ZAP")

    # كشف XSS
    if patterns["API Security"] and not patterns["XSS Prevention"]:
        results["vulnerabilities"].append("Cross-Site Scripting (XSS)")
        results["mitigation_strategies"].append("Content Security Policy")
        results["security_recommendations"].append("Implement proper output encoding and use Content Security Policy")
        results["assessment_tools"].append("OWASP ZAP")
        results["assessment_tools"].append("XSStrike")

    # كشف بيانات اعتماد ثابتة
    if patterns["Hardcoded Credentials"]:
        results["vulnerabilities"].append("Hardcoded Credentials")
        results["mitigation_strategies"].append("Secure Configuration Management")
        results["security_recommendations"].append("Use environment variables or secure vaults for storing sensitive credentials")
        results["assessment_tools"].append("SonarQube")

    # كشف حقن الأوامر
    if patterns["Command Injection"]:
        results["vulnerabilities"].append("Command Injection")
        results["mitigation_strategies"].append("Input Sanitization")
        results["security_recommendations"].append("Validate and sanitize all user inputs that might be used in command execution")
        results["assessment_tools"].append("OWASP ZAP")

    # كشف الخوارزميات الضعيفة
    if patterns["Weak Cryptography"]:
        results["vulnerabilities"].append("Weak Cryptography")
        results["mitigation_strategies"].append("Strong Cryptographic Algorithms")
        results["security_recommendations"].append("Use modern cryptographic algorithms like AES-256, SHA-256 or better")
        results["assessment_tools"].append("OWASP Dependency Check")

    # كشف خلل في معالجة الأخطاء
    if patterns["API Security"] and not patterns["Error Handling"]:
        results["vulnerabilities"].append("Improper Error Handling")
        results["mitigation_strategies"].append("Proper Error Management")
        results["security_recommendations"].append("Implement proper error handling to avoid information leakage")
        results["assessment_tools"].append("SonarQube")

    # توصيات خاصة بالفئة
    if category == "Finance":
        if not patterns["Encryption"] or not patterns["HTTPS Usage"]:
            results["vulnerabilities"].append("Insecure Financial Data")
            results["mitigation_strategies"].append("End-to-End Encryption")
            results["security_recommendations"].append("Implement end-to-end encryption for all financial transactions")
            results["assessment_tools"].append("OWASP ASVS")

        # إضافة أدوات تقييم مالية متخصصة
        if "OWASP ZAP" not in results["assessment_tools"]:
            results["assessment_tools"].append("OWASP ZAP")
        results["assessment_tools"].append("Metasploit")

    elif category == "Health":
        if not patterns["Encryption"]:
            results["vulnerabilities"].append("PHI Data Exposure")
            results["mitigation_strategies"].append("HIPAA-Compliant Encryption")
            results["security_recommendations"].append("Ensure all patient data is encrypted according to healthcare regulations")
            results["assessment_tools"].append("HIPAA Compliance Scanner")

    elif category == "Social":
        if not patterns["Encryption"] or not patterns["Input Validation"]:
            results["vulnerabilities"].append("User Privacy Violation")
            results["mitigation_strategies"].append("Privacy Controls")
            results["security_recommendations"].append("Implement strong privacy controls and data minimization")
            results["assessment_tools"].append("Privacy Impact Assessment Tools")

    # إذا لم يتم اكتشاف أي ثغرات، أضف بعض التوصيات العامة
    if not results["vulnerabilities"]:
        results["security_recommendations"].append("Regularly update dependencies and libraries to protect against new vulnerabilities")
        results["security_recommendations"].append("Implement a secure software development lifecycle (SSDLC)")
        results["assessment_tools"].append("OWASP Dependency Check")
        results["assessment_tools"].append("SonarQube")

    # إزالة التكرارات
    for key in results:
        results[key] = list(dict.fromkeys(results[key]))

    return results