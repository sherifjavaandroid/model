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
        # أنماط أساسية
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
        "Weak Cryptography": re.search(r'MD5|SHA1', code, re.I) is not None,

        # أنماط إضافية مستوحاة من قاعدة البيانات
        "Location Services": re.search(r'location|gps|geolocation|maps|coordinates|latitude|longitude', code, re.I) is not None,
        "Biometric Authentication": re.search(r'biometric|fingerprint|face.*id|touch.*id|iris|retina|voice.*recognition', code, re.I) is not None,
        "Payment Processing": re.search(r'payment|credit.*card|transaction|purchase|checkout|pay|bill|invoice', code, re.I) is not None,
        "Multi-Factor Authentication": re.search(r'2fa|mfa|multi.*factor|two.*factor|otp|one-time|second.*factor', code, re.I) is not None,
        "Cloud Storage": re.search(r'cloud|aws|azure|s3|blob|storage|bucket|firebase', code, re.I) is not None,
        "IoT Communication": re.search(r'iot|device|sensor|bluetooth|zigbee|z-wave|smart.*home', code, re.I) is not None,
        "DRM Protection": re.search(r'drm|digital.*rights|copyright|license|watermark|piracy|intellectual.*property', code, re.I) is not None,
        "Data Anonymization": re.search(r'anonymize|pseudonymize|anonymization|gdpr|privacy', code, re.I) is not None,
        "Third-Party Integration": re.search(r'api.*key|client.*id|client.*secret|third.*party|integration|connect', code, re.I) is not None,
        "Access Control": re.search(r'rbac|role|permission|privilege|access.*control|acl|authorization', code, re.I) is not None,
        "SSO Implementation": re.search(r'sso|single.*sign|oauth|openid|saml|identity.*provider', code, re.I) is not None,
        "Transaction Processing": re.search(r'transaction|transfer|send.*money|receive.*money|payment.*gateway', code, re.I) is not None,
        "Health Data": re.search(r'health|medical|patient|diagnosis|treatment|phi|hipaa|healthcare', code, re.I) is not None,
        "Session Hijacking Risk": re.search(r'session.*id|cookie.*value|sessionid', code, re.I) is not None,
        "Insecure Direct Object References": re.search(r'id\s*=|user_id|record_id|file_id', code, re.I) is not None,
        "CSRF Protection": re.search(r'csrf|xsrf|token|same-origin|cors', code, re.I) is not None,
        "Dynamic Code Execution": re.search(r'new\s+Function|setTimeout\s*\(\s*[\'"](.*)[\'"]', code, re.I) is not None,
        "DDoS Protection": re.search(r'rate.*limit|throttle|captcha|recaptcha|cloudflare', code, re.I) is not None,
        "WebRTC": re.search(r'rtc|webrtc|peer.*connection|media.*stream|getUserMedia', code, re.I) is not None,
        "WebSockets": re.search(r'websocket|ws:|wss:|socket\.io', code, re.I) is not None,
        "DeviceFingerprinting": re.search(r'fingerprint|device.*id|canvas.*fingerprint|browser.*fingerprint', code, re.I) is not None,
        "Reverse Engineering Protection": re.search(r'obfuscate|obfuscation|minify|protect.*source|jscrambler', code, re.I) is not None,
        "Self-Destructing Data": re.search(r'self.*destruct|auto.*delete|ephemeral|temporary|expire', code, re.I) is not None,
        "Data Tampering Protection": re.search(r'checksum|hash.*check|integrity|signature|sign', code, re.I) is not None,
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

    # كشف خطر اختطاف الجلسة
    if patterns["Session Management"] and patterns["Session Hijacking Risk"]:
        results["vulnerabilities"].append("Session Hijacking")
        results["mitigation_strategies"].append("Secure Session Handling")
        results["security_recommendations"].append("Implement session regeneration, secure cookie attributes, and anti-CSRF tokens")
        results["assessment_tools"].append("Burp Suite")

    # كشف XSS
    if patterns["API Security"] and not patterns["XSS Prevention"]:
        results["vulnerabilities"].append("Cross-Site Scripting (XSS)")
        results["mitigation_strategies"].append("Content Security Policy")
        results["security_recommendations"].append("Implement proper output encoding and use Content Security Policy")
        results["assessment_tools"].append("OWASP ZAP")
        results["assessment_tools"].append("XSStrike")

    # كشف CSRF
    if patterns["API Security"] and not patterns["CSRF Protection"]:
        results["vulnerabilities"].append("Cross-Site Request Forgery (CSRF)")
        results["mitigation_strategies"].append("Anti-CSRF Tokens")
        results["security_recommendations"].append("Implement anti-CSRF tokens for all state-changing operations")
        results["assessment_tools"].append("OWASP ZAP")

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

    # كشف عمليات التجسس وانتهاك الخصوصية
    if patterns["Location Services"] and not patterns["Data Anonymization"]:
        results["vulnerabilities"].append("Location Tracking")
        results["mitigation_strategies"].append("Data Anonymization")
        results["security_recommendations"].append("Implement location data anonymization and explicit user consent")
        results["assessment_tools"].append("Privacy Impact Assessment Tools")

    # كشف معالجة الدفع غير الآمنة
    if patterns["Payment Processing"] and not patterns["Encryption"]:
        results["vulnerabilities"].append("Payment Fraud")
        results["mitigation_strategies"].append("Secure Payment Processing")
        results["security_recommendations"].append("Implement PCI-DSS compliant payment processing with tokenization")
        results["assessment_tools"].append("OWASP ASVS")

    # كشف مشاكل المصادقة متعددة العوامل
    if patterns["Authentication"] and not patterns["Multi-Factor Authentication"]:
        results["vulnerabilities"].append("Insufficient Authentication")
        results["mitigation_strategies"].append("Multi-factor Authentication")
        results["security_recommendations"].append("Implement multi-factor authentication for sensitive operations")
        results["assessment_tools"].append("OWASP ASVS")

    # كشف مشاكل IoT
    if patterns["IoT Communication"] and not patterns["Encryption"]:
        results["vulnerabilities"].append("IoT Device Vulnerabilities")
        results["mitigation_strategies"].append("Secure IoT Communication")
        results["security_recommendations"].append("Implement encrypted communication for IoT devices and secure pairing")
        results["assessment_tools"].append("Shodan")

    # كشف عمليات هندسة عكسية
    if not patterns["Reverse Engineering Protection"] and (category == "Finance" or category == "Entertainment"):
        results["vulnerabilities"].append("Reverse Engineering")
        results["mitigation_strategies"].append("Code Obfuscation")
        results["security_recommendations"].append("Implement code obfuscation and tamper detection")
        results["assessment_tools"].append("ProGuard")

    # كشف مشاكل IDOR
    if patterns["Insecure Direct Object References"] and not patterns["Access Control"]:
        results["vulnerabilities"].append("Insecure Direct Object References (IDOR)")
        results["mitigation_strategies"].append("Access Control")
        results["security_recommendations"].append("Implement proper access control checks for all resources")
        results["assessment_tools"].append("Burp Suite")

    # كشف مشاكل تنفيذ الكود الديناميكي
    if patterns["Dynamic Code Execution"]:
        results["vulnerabilities"].append("Dynamic Code Execution")
        results["mitigation_strategies"].append("Code Integrity Checks")
        results["security_recommendations"].append("Avoid dynamically generated code and implement content security policy")
        results["assessment_tools"].append("OWASP ZAP")

    # كشف مشاكل تلاعب البيانات
    if not patterns["Data Tampering Protection"]:
        results["vulnerabilities"].append("Data Tampering")
        results["mitigation_strategies"].append("Data Integrity Verification")
        results["security_recommendations"].append("Implement checksums or digital signatures for data integrity")
        results["assessment_tools"].append("Burp Suite")

    # توصيات خاصة بالفئة
    if category == "Finance":
        if not patterns["Encryption"] or not patterns["HTTPS Usage"]:
            results["vulnerabilities"].append("Insecure Financial Data")
            results["mitigation_strategies"].append("End-to-End Encryption")
            results["security_recommendations"].append("Implement end-to-end encryption for all financial transactions")
            results["assessment_tools"].append("OWASP ASVS")

        if patterns["Transaction Processing"] and not patterns["Multi-Factor Authentication"]:
            results["vulnerabilities"].append("Transaction Fraud")
            results["mitigation_strategies"].append("Transaction Signing")
            results["security_recommendations"].append("Implement transaction signing and out-of-band verification")
            results["assessment_tools"].append("Splunk")

        # إضافة أدوات تقييم مالية متخصصة
        if "OWASP ZAP" not in results["assessment_tools"]:
            results["assessment_tools"].append("OWASP ZAP")
        results["assessment_tools"].append("Metasploit")

    elif category == "Health":
        if not patterns["Encryption"] or patterns["Health Data"]:
            results["vulnerabilities"].append("PHI Data Exposure")
            results["mitigation_strategies"].append("HIPAA-Compliant Encryption")
            results["security_recommendations"].append("Ensure all patient data is encrypted according to healthcare regulations")
            results["assessment_tools"].append("HIPAA Compliance Scanner")

        if patterns["Health Data"] and not patterns["Access Control"]:
            results["vulnerabilities"].append("Unauthorized Access to Health Data")
            results["mitigation_strategies"].append("Role-Based Access Control")
            results["security_recommendations"].append("Implement strict role-based access controls for health data")
            results["assessment_tools"].append("HIPAA Compliance Scanner")

    elif category == "Social":
        if not patterns["Encryption"] or not patterns["Input Validation"]:
            results["vulnerabilities"].append("User Privacy Violation")
            results["mitigation_strategies"].append("Privacy Controls")
            results["security_recommendations"].append("Implement strong privacy controls and data minimization")
            results["assessment_tools"].append("Privacy Impact Assessment Tools")

        if patterns["Self-Destructing Data"] and not patterns["Encryption"]:
            results["vulnerabilities"].append("Self-Destructing Messages Bypass")
            results["mitigation_strategies"].append("Secure Message Deletion")
            results["security_recommendations"].append("Implement proper encryption and secure deletion for ephemeral content")
            results["assessment_tools"].append("Signal Protocol")

    elif category == "Entertainment" or category == "Art & Design":
        if patterns["DRM Protection"] and not patterns["Encryption"]:
            results["vulnerabilities"].append("Piracy")
            results["mitigation_strategies"].append("DRM Techniques")
            results["security_recommendations"].append("Implement proper DRM protection and watermarking for content")
            results["assessment_tools"].append("Widevine")
            results["assessment_tools"].append("Digimarc")

    elif category == "Travel":
        if patterns["Location Services"] and not patterns["HTTPS Usage"]:
            results["vulnerabilities"].append("Location Spoofing")
            results["mitigation_strategies"].append("Dynamic Authentication Based on Location")
            results["security_recommendations"].append("Implement secure location verification and anomaly detection")
            results["assessment_tools"].append("Google Maps API")

    elif category == "Productivity":
        if patterns["Cloud Storage"] and not patterns["Encryption"]:
            results["vulnerabilities"].append("Data Leakage")
            results["mitigation_strategies"].append("Encrypted Cloud Storage")
            results["security_recommendations"].append("Implement end-to-end encryption for all cloud-stored data")
            results["assessment_tools"].append("AWS Inspector")

    elif category == "Events":
        if not patterns["DDoS Protection"]:
            results["vulnerabilities"].append("DDoS Attacks")
            results["mitigation_strategies"].append("CDN Utilization")
            results["security_recommendations"].append("Implement CDN protection and rate limiting for high-traffic events")
            results["assessment_tools"].append("Cloudflare")

    elif category == "Lifestyle" or category == "Environment":
        if patterns["IoT Communication"] and not patterns["Data Anonymization"]:
            results["vulnerabilities"].append("IoT Privacy Concerns")
            results["mitigation_strategies"].append("Privacy by Design")
            results["security_recommendations"].append("Implement privacy-preserving data collection in IoT devices")
            results["assessment_tools"].append("Shodan")

    elif category == "Communication":
        if patterns["WebRTC"] and not patterns["Encryption"]:
            results["vulnerabilities"].append("Eavesdropping")
            results["mitigation_strategies"].append("End-to-End Encryption")
            results["security_recommendations"].append("Implement end-to-end encryption for all communications")
            results["assessment_tools"].append("Signal Protocol")

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

def analyze_code_with_context(code: str, category: str, file_extension: str = None) -> Dict[str, Any]:
    """
    تحليل الكود مع الأخذ في الاعتبار سياقه ولغة البرمجة.

    المعاملات:
        code (str): الكود المصدري للتحليل
        category (str): فئة التطبيق
        file_extension (str): امتداد ملف الكود (اختياري)

    العوائد:
        Dict[str, Any]: نتائج التحليل المتقدم
    """
    # الحصول على نتائج التحليل الأساسي
    base_results = analyze_code_security(code, category)

    # تحديد لغة البرمجة إذا تم توفير امتداد الملف
    language = "unknown"
    if file_extension:
        extension_map = {
            "js": "JavaScript",
            "ts": "TypeScript",
            "java": "Java",
            "py": "Python",
            "php": "PHP",
            "rb": "Ruby",
            "cs": "C#",
            "go": "Go",
            "swift": "Swift",
            "kt": "Kotlin",
            "dart": "Dart",
            "sh": "Shell",
            "sql": "SQL",
            "html": "HTML",
            "css": "CSS",
            "xml": "XML",
        }
        language = extension_map.get(file_extension.lstrip(".").lower(), "unknown")

    # تحليلات إضافية خاصة باللغة
    language_specific_vulnerabilities = []
    language_specific_mitigations = []

    if language == "JavaScript":
        if re.search(r'innerHTML|document\.write', code, re.I):
            language_specific_vulnerabilities.append("DOM-based XSS")
            language_specific_mitigations.append("Safer DOM Manipulation")

        if re.search(r'localStorage|sessionStorage', code, re.I) and not re.search(r'encrypt', code, re.I):
            language_specific_vulnerabilities.append("Client-Side Storage of Sensitive Data")
            language_specific_mitigations.append("Encrypted Client Storage")

    elif language == "Java":
        if re.search(r'Serializable|readObject|writeObject', code, re.I):
            language_specific_vulnerabilities.append("Java Serialization Vulnerability")
            language_specific_mitigations.append("Safer Serialization Alternatives")

        if re.search(r'System\.exit', code, re.I):
            language_specific_vulnerabilities.append("Denial of Service Risk")
            language_specific_mitigations.append("Graceful Error Handling")

    elif language == "Python":
        if re.search(r'pickle\.load|json\.loads', code, re.I):
            language_specific_vulnerabilities.append("Python Deserialization Vulnerability")
            language_specific_mitigations.append("Safer Deserialization")

        if re.search(r'subprocess\.call|os\.system', code, re.I):
            language_specific_vulnerabilities.append("Python Command Injection")
            language_specific_mitigations.append("Safer Process Execution")

    elif language == "PHP":
        if re.search(r'include\s*\(|require\s*\(', code, re.I):
            language_specific_vulnerabilities.append("PHP File Inclusion Vulnerability")
            language_specific_mitigations.append("Proper Path Validation")

        if re.search(r'\$_GET|\$_POST|\$_REQUEST', code, re.I) and not re.search(r'filter_var|htmlspecialchars', code, re.I):
            language_specific_vulnerabilities.append("PHP Input Validation Missing")
            language_specific_mitigations.append("PHP Input Filtering")

    elif language == "Dart":
        if re.search(r'jsonDecode|fromJson', code, re.I):
            language_specific_vulnerabilities.append("Dart JSON Deserialization")
            language_specific_mitigations.append("Input Validation for JSON")

        if re.search(r'TextEditingController', code, re.I) and not re.search(r'InputDecoration', code, re.I):
            language_specific_vulnerabilities.append("Flutter Input Validation Missing")
            language_specific_mitigations.append("Flutter Input Validation")

    # إضافة النتائج الخاصة باللغة إلى النتائج الأساسية
    base_results["vulnerabilities"].extend(language_specific_vulnerabilities)
    base_results["mitigation_strategies"].extend(language_specific_mitigations)

    # إضافة معلومات السياق
    context_info = {
        "language": language,
        "code_complexity": calculate_code_complexity(code),
        "security_score": calculate_security_score(base_results["vulnerabilities"]),
        "language_specific_analysis": {
            "vulnerabilities": language_specific_vulnerabilities,
            "mitigations": language_specific_mitigations
        }
    }

    # دمج النتائج
    enhanced_results = {**base_results, "context_info": context_info}

    return enhanced_results

def calculate_code_complexity(code: str) -> str:
    """
    حساب تعقيد الكود بشكل بسيط.

    المعاملات:
        code (str): الكود المصدري للتحليل

    العوائد:
        str: مستوى التعقيد (منخفض، متوسط، عالي)
    """
    # حساب عدد الأسطر كمؤشر بسيط للتعقيد
    lines = code.split('\n')
    line_count = len([line for line in lines if line.strip() and not line.strip().startswith('//')])

    # حساب عدد التعبيرات الشرطية والحلقات
    conditional_count = len(re.findall(r'\bif\b|\belse\b|\bswitch\b|\bcase\b', code, re.I))
    loop_count = len(re.findall(r'\bfor\b|\bwhile\b|\bdo\b', code, re.I))

    # حساب عدد الدوال
    function_count = len(re.findall(r'\bfunction\b|\bdef\b|[a-zA-Z_][a-zA-Z0-9_]*\s*\([^)]*\)\s*{', code, re.I))

    # حساب مستوى التعقيد
    complexity_score = line_count * 0.1 + conditional_count * 0.5 + loop_count * 0.5 + function_count * 0.3

    if complexity_score < 10:
        return "Low"
    elif complexity_score < 30:
        return "Medium"
    else:
        return "High"

def calculate_security_score(vulnerabilities: List[str]) -> Dict[str, Any]:
    """
    حساب درجة أمان الكود بناءً على الثغرات المكتشفة.

    المعاملات:
        vulnerabilities (List[str]): قائمة الثغرات المكتشفة

    العوائد:
        Dict[str, Any]: درجة الأمان ومعلومات إضافية
    """
    # تعيين درجات خطورة للثغرات المختلفة
    vulnerability_severity = {
        "SQL Injection": 9,
        "Command Injection": 9,
        "Cross-Site Scripting (XSS)": 7,
        "Insecure Direct Object References (IDOR)": 7,
        "Sensitive Data Exposure": 7,
        "Weak Authentication": 8,
        "Insecure Session Management": 6,
        "Cross-Site Request Forgery (CSRF)": 6,
        "Hardcoded Credentials": 8,
        "Weak Cryptography": 7,
        "Improper Error Handling": 5,
        "Insecure Financial Data": 9,
        "PHI Data Exposure": 9,
        "User Privacy Violation": 7,
        "Location Tracking": 6,
        "Payment Fraud": 9,
        "Session Hijacking": 8,
        "Unauthorized Access to Health Data": 9,
        "Insufficient Authentication": 7,
        "IoT Device Vulnerabilities": 7,
        "Reverse Engineering": 6,
        "Dynamic Code Execution": 8,
        "Data Tampering": 7,
        "Transaction Fraud": 9,
        "Self-Destructing Messages Bypass": 6,
        "Piracy": 7,
        "Location Spoofing": 6,
        "Data Leakage": 7,
        "DDoS Attacks": 7,
        "IoT Privacy Concerns": 6,
        "Eavesdropping": 7,
        # درجات افتراضية للثغرات غير المعروفة
        "default": 5
    }

    if not vulnerabilities:
        return {
            "score": 100,
            "rating": "A+",
            "risk_level": "Very Low",
            "highest_severity_vulnerability": None
        }

    # حساب إجمالي درجة الخطورة
    total_severity = 0
    highest_severity = 0
    highest_severity_vuln = None

    for vuln in vulnerabilities:
        severity = vulnerability_severity.get(vuln, vulnerability_severity["default"])
        total_severity += severity

        if severity > highest_severity:
            highest_severity = severity
            highest_severity_vuln = vuln

    # حساب درجة الأمان (أقصى 100)
    max_possible_score = 100
    penalty_per_vulnerability = 5  # خصم ثابت لكل ثغرة
    severity_penalty = total_severity / len(vulnerabilities)  # متوسط خطورة الثغرات

    security_score = max(0, max_possible_score - (len(vulnerabilities) * penalty_per_vulnerability) - severity_penalty)

    # تحديد التصنيف
    if security_score >= 90:
        rating = "A+"
        risk_level = "Very Low"
    elif security_score >= 80:
        rating = "A"
        risk_level = "Low"
    elif security_score >= 70:
        rating = "B"
        risk_level = "Moderate"
    elif security_score >= 60:
        rating = "C"
        risk_level = "Medium"
    elif security_score >= 50:
        rating = "D"
        risk_level = "High"
    else:
        rating = "F"
        risk_level = "Very High"

    return {
        "score": round(security_score, 1),
        "rating": rating,
        "risk_level": risk_level,
        "highest_severity_vulnerability": highest_severity_vuln
    }