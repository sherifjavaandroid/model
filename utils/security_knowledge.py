#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
قاعدة المعرفة الأمنية المستخدمة لإثراء نتائج تحليل الكود.
تحتوي على معلومات مفصلة عن الثغرات الأمنية واستراتيجيات التخفيف وأدوات التقييم.
"""

# قاعدة معرفية للأمان تستخدم لإثراء النتائج
security_knowledge = {
    "vulnerabilities": {
        "SQL Injection": {
            "description": "A code injection technique that can destroy your database by inserting malicious SQL statements.",
            "severity": "High"
        },
        "Cross-Site Scripting (XSS)": {
            "description": "An attack where malicious scripts are injected into trusted websites.",
            "severity": "Medium"
        },
        "Insecure Communication": {
            "description": "Transmission of sensitive data over unencrypted channels.",
            "severity": "High"
        },
        "Unauthorized Access": {
            "description": "Access to resources by users who should not have access.",
            "severity": "High"
        },
        "Data Leakage": {
            "description": "Unintentional exposure of sensitive information.",
            "severity": "High"
        },
        "Weak Authentication": {
            "description": "Authentication mechanisms that can be easily bypassed.",
            "severity": "High"
        },
        "Sensitive Data Exposure": {
            "description": "Improper protection of sensitive information such as financial data, healthcare information, or PII.",
            "severity": "High"
        },
        "Insecure Session Management": {
            "description": "Improper handling of session tokens that can lead to session hijacking attacks.",
            "severity": "High"
        },
        "Hardcoded Credentials": {
            "description": "Including authentication credentials directly in the source code.",
            "severity": "High"
        },
        "Command Injection": {
            "description": "An attack where malicious system commands are injected through unsanitized input.",
            "severity": "High"
        },
        "Weak Cryptography": {
            "description": "Using outdated or broken cryptographic algorithms that do not provide adequate security.",
            "severity": "High"
        },
        "Improper Error Handling": {
            "description": "Revealing sensitive information in error messages that could aid attackers.",
            "severity": "Medium"
        },
        "Insecure Financial Data": {
            "description": "Improper protection of financial information like credit card numbers, account details, or transaction data.",
            "severity": "Critical"
        },
        "PHI Data Exposure": {
            "description": "Improper protection of Protected Health Information (PHI) that could violate HIPAA regulations.",
            "severity": "Critical"
        },
        "User Privacy Violation": {
            "description": "Improper handling of user privacy settings or data that could lead to privacy breaches.",
            "severity": "High"
        },
        "Broken Authentication": {
            "description": "Implementation flaws in authentication that allow attackers to assume other user identities.",
            "severity": "High"
        },
        "XML External Entity (XXE)": {
            "description": "Processing of unsanitized XML input containing hostile content.",
            "severity": "High"
        },
        "Security Misconfiguration": {
            "description": "Improper implementation of security controls due to insecure configuration.",
            "severity": "Medium"
        },
        "Insecure Deserialization": {
            "description": "Processing untrusted data without proper verification, allowing for remote code execution.",
            "severity": "High"
        },
        "Using Components with Known Vulnerabilities": {
            "description": "Using libraries, frameworks, or other software modules with known security issues.",
            "severity": "Medium"
        },
        "Insufficient Logging & Monitoring": {
            "description": "Lack of proper logging and monitoring to detect and respond to security incidents.",
            "severity": "Medium"
        },
        "Server-Side Request Forgery (SSRF)": {
            "description": "Attacks that force a server to make requests to internal resources.",
            "severity": "High"
        },
        "Cross-Site Request Forgery (CSRF)": {
            "description": "Forces an end user to execute unwanted actions on a web application.",
            "severity": "Medium"
        },
        "Path Traversal": {
            "description": "Allows attackers to access files and directories outside of the intended path.",
            "severity": "High"
        },
        "API Vulnerabilities": {
            "description": "Security issues specific to APIs, including improper authentication, rate limiting, or validation.",
            "severity": "High"
        }
    },

    "mitigations": {
        "Parameterized Queries": {
            "description": "Use prepared statements with parameterized queries to prevent SQL injection.",
            "implementation_complexity": "Low"
        },
        "Content Security Policy": {
            "description": "A security layer that helps detect and mitigate certain types of attacks.",
            "implementation_complexity": "Medium"
        },
        "Data Encryption": {
            "description": "Encrypt sensitive data in storage and during transmission.",
            "implementation_complexity": "Medium"
        },
        "Multi-factor Authentication": {
            "description": "Require multiple forms of verification before granting access.",
            "implementation_complexity": "Medium"
        },
        "Input Validation": {
            "description": "Validate and sanitize all user inputs to ensure they meet expected formats.",
            "implementation_complexity": "Low"
        },
        "Secure Session Handling": {
            "description": "Implement secure practices for managing user sessions, including secure cookies and proper expiration.",
            "implementation_complexity": "Medium"
        },
        "Secure Configuration Management": {
            "description": "Use environment variables or secure vaults for storing sensitive configuration.",
            "implementation_complexity": "Medium"
        },
        "Input Sanitization": {
            "description": "Clean and validate all user inputs to prevent injection attacks.",
            "implementation_complexity": "Low"
        },
        "Strong Cryptographic Algorithms": {
            "description": "Use modern, strong encryption algorithms and properly manage keys.",
            "implementation_complexity": "Medium"
        },
        "Proper Error Management": {
            "description": "Implement centralized error handling that does not reveal sensitive information.",
            "implementation_complexity": "Low"
        },
        "End-to-End Encryption": {
            "description": "Implement encryption for data at rest, in transit, and during processing.",
            "implementation_complexity": "High"
        },
        "HIPAA-Compliant Encryption": {
            "description": "Use encryption methods that comply with healthcare regulations.",
            "implementation_complexity": "High"
        },
        "Privacy Controls": {
            "description": "Implement robust user privacy settings and data minimization practices.",
            "implementation_complexity": "Medium"
        },
        "Role-Based Access Control": {
            "description": "Restrict system access to authorized users based on roles.",
            "implementation_complexity": "Medium"
        },
        "Secure API Design": {
            "description": "Design APIs with security in mind, including proper authentication and authorization.",
            "implementation_complexity": "Medium"
        },
        "Output Encoding": {
            "description": "Encode output data to prevent XSS and other injection attacks.",
            "implementation_complexity": "Low"
        },
        "Rate Limiting": {
            "description": "Limit the number of requests a user can make to prevent abuse.",
            "implementation_complexity": "Medium"
        },
        "Security Headers": {
            "description": "Implement HTTP security headers to enhance browser security.",
            "implementation_complexity": "Low"
        },
        "Secure Dependency Management": {
            "description": "Regularly update and scan dependencies for security vulnerabilities.",
            "implementation_complexity": "Medium"
        }
    },

    "tools": {
        "OWASP ZAP": {
            "purpose": "An open-source web application security scanner.",
            "url": "https://www.zaproxy.org/"
        },
        "Burp Suite": {
            "purpose": "An integrated platform for performing security testing of web applications.",
            "url": "https://portswigger.net/burp"
        },
        "SonarQube": {
            "purpose": "A platform for continuous inspection of code quality and security.",
            "url": "https://www.sonarqube.org/"
        },
        "SQLMap": {
            "purpose": "An open source penetration testing tool that automates the detection and exploitation of SQL injection vulnerabilities.",
            "url": "https://sqlmap.org/"
        },
        "XSStrike": {
            "purpose": "An advanced XSS detection suite.",
            "url": "https://github.com/s0md3v/XSStrike"
        },
        "OWASP Dependency Check": {
            "purpose": "A tool that identifies project dependencies and checks for known vulnerabilities.",
            "url": "https://owasp.org/www-project-dependency-check/"
        },
        "Metasploit": {
            "purpose": "A penetration testing framework that makes hacking simpler.",
            "url": "https://www.metasploit.com/"
        },
        "HIPAA Compliance Scanner": {
            "purpose": "A tool designed to check compliance with healthcare security regulations.",
            "url": None
        },
        "Privacy Impact Assessment Tools": {
            "purpose": "Tools to assess the privacy implications of software and systems.",
            "url": None
        },
        "OWASP ASVS": {
            "purpose": "Application Security Verification Standard - a framework for security requirements.",
            "url": "https://owasp.org/www-project-application-security-verification-standard/"
        },
        "Firebase Test Lab": {
            "purpose": "Test your mobile apps across a variety of devices and configurations.",
            "url": "https://firebase.google.com/docs/test-lab"
        },
        "Android Lint": {
            "purpose": "Static code analysis tool for Android applications.",
            "url": "https://developer.android.com/studio/write/lint"
        },
        "Veracode": {
            "purpose": "Cloud-based application security testing.",
            "url": "https://www.veracode.com/"
        },
        "QARK": {
            "purpose": "Tool to look for security vulnerabilities in Android applications.",
            "url": "https://github.com/linkedin/qark"
        },
        "MobSF": {
            "purpose": "Mobile Security Framework for automated mobile app testing.",
            "url": "https://github.com/MobSF/Mobile-Security-Framework-MobSF"
        },
        "Nessus": {
            "purpose": "Vulnerability scanner that identifies security vulnerabilities in IT systems.",
            "url": "https://www.tenable.com/products/nessus"
        },
        "OpenVAS": {
            "purpose": "Open source vulnerability scanner and vulnerability management solution.",
            "url": "https://www.openvas.org/"
        },
        "Wireshark": {
            "purpose": "Network protocol analyzer for security analysis and troubleshooting.",
            "url": "https://www.wireshark.org/"
        },
        "Kali Linux": {
            "purpose": "Linux distribution designed for digital forensics and penetration testing.",
            "url": "https://www.kali.org/"
        }
    }
}

# توسيع المعرفة باستخدام معلومات من مجموعة البيانات
def expand_security_knowledge(data_df):
    """
    توسيع قاعدة المعرفة باستخدام معلومات من مجموعة البيانات.

    المعاملات:
        data_df: إطار البيانات الذي يحتوي على معلومات الأمان
    """
    if data_df is None:
        return security_knowledge

    # إضافة ثغرات أمنية جديدة
    unique_vulnerabilities = data_df['Vulnerability_Types'].dropna().unique()
    for vuln in unique_vulnerabilities:
        if vuln not in security_knowledge["vulnerabilities"]:
            security_knowledge["vulnerabilities"][vuln] = {
                "description": f"A security vulnerability related to {vuln}.",
                "severity": "Medium"
            }

    # إضافة استراتيجيات تخفيف جديدة
    unique_mitigations = data_df['Mitigation_Strategies'].dropna().unique()
    for mitigation in unique_mitigations:
        if mitigation not in security_knowledge["mitigations"]:
            security_knowledge["mitigations"][mitigation] = {
                "description": f"A strategy to mitigate {mitigation}.",
                "implementation_complexity": "Medium"
            }

    # إضافة أدوات تقييم جديدة
    unique_tools = data_df['Assessment_Tools_Used'].dropna().unique()
    for tool in unique_tools:
        if tool not in security_knowledge["tools"]:
            security_knowledge["tools"][tool] = {
                "purpose": f"A tool used for {tool}.",
                "url": None
            }

    return security_knowledge