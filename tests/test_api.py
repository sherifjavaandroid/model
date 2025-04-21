#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
import json
import os
import sys
from fastapi.testclient import TestClient

# إضافة المجلد الرئيسي إلى مسار البحث
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# استيراد التطبيق
from app import app

class TestAPI(unittest.TestCase):
    """اختبارات لواجهة برمجة التطبيقات (API)"""

    def setUp(self):
        """إعداد بيئة الاختبار"""
        self.client = TestClient(app)

    def test_root_endpoint(self):
        """اختبار نقطة النهاية الرئيسية /"""
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("message", response.json())

    def test_status_endpoint(self):
        """اختبار نقطة نهاية الحالة /status"""
        response = self.client.get("/status")
        self.assertEqual(response.status_code, 200)
        self.assertIn("api_status", response.json())
        self.assertIn("model_loaded", response.json())
        self.assertIn("dataset_loaded", response.json())

    def test_categories_endpoint(self):
        """اختبار نقطة نهاية الفئات /categories"""
        response = self.client.get("/categories")
        self.assertEqual(response.status_code, 200)
        self.assertIn("categories", response.json())
        self.assertIsInstance(response.json()["categories"], list)

    def test_analyze_endpoint_with_valid_data(self):
        """اختبار نقطة نهاية التحليل /analyze مع بيانات صالحة"""
        # إنشاء كود للتحليل
        test_code = """
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
        """

        # إرسال طلب التحليل
        response = self.client.post(
            "/analyze",
            json={"code": test_code, "category": "Finance"}
        )

        # اختبار الاستجابة
        self.assertEqual(response.status_code, 200)
        self.assertIn("vulnerabilities", response.json())
        self.assertIn("mitigation_strategies", response.json())
        self.assertIn("security_recommendations", response.json())
        self.assertIn("assessment_tools", response.json())

    def test_analyze_endpoint_with_empty_code(self):
        """اختبار نقطة نهاية التحليل /analyze مع كود فارغ"""
        response = self.client.post(
            "/analyze",
            json={"code": "", "category": "Finance"}
        )
        self.assertEqual(response.status_code, 400)

    def test_analyze_endpoint_with_invalid_category(self):
        """اختبار نقطة نهاية التحليل /analyze مع فئة غير صالحة"""
        # إنشاء كود للتحليل
        test_code = """console.log("Hello, World!");"""

        # إرسال طلب التحليل مع فئة غير صالحة
        # يجب أن يتم قبول الطلب لأن الفئة غير المعروفة ستستخدم كما هي
        response = self.client.post(
            "/analyze",
            json={"code": test_code, "category": "InvalidCategory"}
        )

        # اختبار الاستجابة
        self.assertEqual(response.status_code, 200)

    def test_analyze_endpoint_with_secure_code(self):
        """اختبار نقطة نهاية التحليل /analyze مع كود آمن"""
        # إنشاء كود آمن للتحليل
        secure_code = """
        function login(username, password) {
            // استخدام استعلامات مجهزة
            const query = "SELECT * FROM users WHERE username = ? AND password = ?";
            connection.query(query, [username, password], function(err, results) {
                // التحقق من الخطأ
                if (err) {
                    console.error("خطأ في الاستعلام:", err);
                    return false;
                }
                
                // التحقق من النتائج
                if (results && results.length > 0) {
                    // إعداد جلسة مع وقت انتهاء
                    session.user = results[0];
                    session.cookie.maxAge = 3600000; // ساعة واحدة
                    return true;
                }
                return false;
            });
        }
        """

        # إرسال طلب التحليل
        response = self.client.post(
            "/analyze",
            json={"code": secure_code, "category": "Finance"}
        )

        # اختبار الاستجابة - يجب أن تكون ناجحة حتى لو كان الكود آمناً
        self.assertEqual(response.status_code, 200)

if __name__ == "__main__":
    unittest.main()