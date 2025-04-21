#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
import os
import sys

# إضافة المجلد الرئيسي إلى مسار البحث
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# استيراد الوظائف المراد اختبارها
from utils.code_analyzer import extract_security_patterns, analyze_code_security

class TestCodeAnalyzer(unittest.TestCase):
    """اختبارات لمحلل الكود"""

    def test_extract_security_patterns_sql_injection(self):
        """اختبار استخراج أنماط الأمان - حقن SQL"""
        code_with_sql_injection = """
        function authenticate(username, password) {
            var query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'";
            return executeQuery(query);
        }
        """

        patterns = extract_security_patterns(code_with_sql_injection)

        self.assertTrue(patterns["Authentication"])
        self.assertTrue(patterns["SQL Queries"])
        self.assertTrue(patterns["SQL Injection Risk"])
        self.assertFalse(patterns["Input Validation"])

    def test_extract_security_patterns_encryption(self):
        """اختبار استخراج أنماط الأمان - التشفير"""
        code_with_encryption = """
        function encryptData(data) {
            const crypto = require('crypto');
            const cipher = crypto.createCipher('aes-256-cbc', 'key');
            let encrypted = cipher.update(data, 'utf8', 'hex');
            encrypted += cipher.final('hex');
            return encrypted;
        }
        """

        patterns = extract_security_patterns(code_with_encryption)

        self.assertTrue(patterns["Encryption"])
        self.assertFalse(patterns["SQL Queries"])
        self.assertFalse(patterns["Authentication"])

    def test_extract_security_patterns_xss(self):
        """اختبار استخراج أنماط الأمان - XSS"""
        code_with_xss_risk = """
        function displayUser(user) {
            document.getElementById('user-info').innerHTML = user.name;
        }
        """

        patterns = extract_security_patterns(code_with_xss_risk)

        self.assertFalse(patterns["XSS Prevention"])
        self.assertFalse(patterns["Input Validation"])

    def test_extract_security_patterns_secure_code(self):
        """اختبار استخراج أنماط الأمان - كود آمن"""
        secure_code = """
        function authenticate(username, password) {
            const query = "SELECT * FROM users WHERE username = ? AND password = ?";
            return executeQuery(query, [username, password]);
        }
        
        function displayUser(user) {
            const userInfoElement = document.getElementById('user-info');
            userInfoElement.textContent = user.name; // استخدام textContent لمنع XSS
        }
        """

        patterns = extract_security_patterns(secure_code)

        self.assertTrue(patterns["Authentication"])
        self.assertTrue(patterns["SQL Queries"])
        self.assertFalse(patterns["SQL Injection Risk"])
        self.assertTrue(patterns["XSS Prevention"])

    def test_analyze_code_security_sql_injection(self):
        """اختبار تحليل أمان الكود - حقن SQL"""
        code_with_sql_injection = """
        function authenticate(username, password) {
            var query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'";
            return executeQuery(query);
        }
        """

        analysis = analyze_code_security(code_with_sql_injection, "Finance")

        self.assertIn("SQL Injection", analysis["vulnerabilities"])
        self.assertIn("Parameterized Queries", analysis["mitigation_strategies"])

    def test_analyze_code_security_sensitive_data(self):
        """اختبار تحليل أمان الكود - البيانات الحساسة"""
        code_with_sensitive_data = """
        function storeUserData(creditCardNumber, ssn) {
            localStorage.setItem('creditCard', creditCardNumber);
            localStorage.setItem('ssn', ssn);
        }
        """

        analysis = analyze_code_security(code_with_sensitive_data, "Finance")

        self.assertIn("Sensitive Data Exposure", analysis["vulnerabilities"])
        self.assertIn("Data Encryption", analysis["mitigation_strategies"])

    def test_analyze_code_security_category_specific(self):
        """اختبار تحليل أمان الكود - تحليل خاص بالفئة"""
        # كود به مشكلة مع بيانات حساسة في فئة المالية
        code = """
        function processPayment(cardNumber, cvv) {
            const payment = {
                card: cardNumber,
                verification: cvv
            };
            sendData('/api/payment', payment);
        }
        """

        # تحليل الكود في فئة المالية
        finance_analysis = analyze_code_security(code, "Finance")
        self.assertIn("Insecure Financial Data", finance_analysis["vulnerabilities"])

        # تحليل نفس الكود في فئة أخرى
        other_analysis = analyze_code_security(code, "Social")
        # يجب أن يحتوي على تحذيرات مختلفة أو أقل
        if "Insecure Financial Data" in other_analysis["vulnerabilities"]:
            self.fail("تم اكتشاف ثغرات مالية في فئة غير مالية")

if __name__ == "__main__":
    unittest.main()