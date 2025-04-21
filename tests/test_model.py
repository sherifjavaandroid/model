def test_model_training(self):
    """اختبار تدريب النموذج"""
    # معالجة البيانات
    df, category_map = preprocess_data(self.test_data_path)

    # تدريب النموذج
    model, vectorizer, score = train_security_model(
        df,
        output_dir=self.test_models_dir,
        n_estimators=10,  # عدد أقل من الأشجار للاختبار السريع
        max_features=100
    )

    # التحقق من وجود ملفات النموذج
    self.assertTrue(os.path.exists(os.path.join(self.test_models_dir, "security_model.joblib")))
    self.assertTrue(os.path.exists(os.path.join(self.test_models_dir, "vectorizer.joblib")))
    self.assertTrue(os.path.exists(os.path.join(self.test_models_dir, "category_map.txt")))

    # التحقق من نوع النموذج
    self.assertIsInstance(model, MultiOutputClassifier)
    self.assertIsInstance(vectorizer, TfidfVectorizer)

    # التحقق من الدقة (لا ينبغي أن تكون صفراً)
    self.assertGreater(score, 0)

def test_model_predictions(self):
    """اختبار تنبؤات النموذج"""
    # تحميل النموذج والمحول (إذا كانوا موجودين بالفعل)
    try:
        model = joblib.load(os.path.join(self.test_models_dir, "security_model.joblib"))
        vectorizer = joblib.load(os.path.join(self.test_models_dir, "vectorizer.joblib"))
    except:
        # تدريب النموذج إذا لم يكن موجوداً
        df, _ = preprocess_data(self.test_data_path)
        model, vectorizer, _ = train_security_model(
            df,
            output_dir=self.test_models_dir,
            n_estimators=10,
            max_features=100
        )

    # إنشاء ميزات للاختبار
    test_feature = "Category: Finance Authentication SQL Queries SQL Injection Risk"
    X_test = vectorizer.transform([test_feature])

    # التنبؤ
    predictions = model.predict(X_test)

    # التحقق من شكل التنبؤات
    self.assertEqual(len(predictions), 1)  # عدد الصفوف
    self.assertEqual(len(predictions[0]), 4)  # عدد الأعمدة (الأهداف)

    # التحقق من أن التنبؤات ليست فارغة
    for i in range(4):
        self.assertTrue(predictions[0][i])

def test_model_with_code_analyzer(self):
    """اختبار النموذج مع محلل الكود"""
    from utils.code_analyzer import extract_security_patterns

    # تحميل النموذج والمحول (إذا كانوا موجودين بالفعل)
    try:
        model = joblib.load(os.path.join(self.test_models_dir, "security_model.joblib"))
        vectorizer = joblib.load(os.path.join(self.test_models_dir, "vectorizer.joblib"))
    except:
        # تدريب النموذج إذا لم يكن موجوداً
        df, _ = preprocess_data(self.test_data_path)
        model, vectorizer, _ = train_security_model(
            df,
            output_dir=self.test_models_dir,
            n_estimators=10,
            max_features=100
        )

    # كود للاختبار
    test_code = """
        function authenticate(username, password) {
            var query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'";
            return executeQuery(query);
        }
        """

    # استخراج أنماط الأمان
    patterns = extract_security_patterns(test_code)

    # إنشاء نص الميزات
    feature_text = f"Category: Finance "
    for key, value in patterns.items():
        if value:
            feature_text += f"{key} "

    # تحويل النص إلى متجه ميزات
    X = vectorizer.transform([feature_text])

    # التنبؤ
    predictions = model.predict(X)

    # التحقق من وجود تنبؤات
    self.assertIsNotNone(predictions)
    self.assertEqual(predictions.shape, (1, 4))

    # يجب أن تحتوي التنبؤات على معلومات عن SQL Injection على الأقل
    self.assertTrue(any("SQL" in str(pred) for pred in predictions[0]))

@classmethod
def tearDownClass(cls):
    """تنظيف بعد الاختبارات"""
    # حذف بيانات الاختبار (اختياري)
    if os.path.exists(cls.test_data_path):
        # يمكن تعليق هذا السطر للاحتفاظ ببيانات الاختبار
        # os.remove(cls.test_data_path)
        pass


if __name__ == "__main__":
    unittest.main()#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
import os
import sys
import pandas as pd
import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.multioutput import MultiOutputClassifier
from sklearn.ensemble import RandomForestClassifier

# إضافة المجلد الرئيسي إلى مسار البحث
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.data_utils import preprocess_data
from train_model import train_security_model

class TestModel(unittest.TestCase):
    """اختبارات لنموذج تحليل الأمان"""

    @classmethod
    def setUpClass(cls):
        """إعداد البيئة للاختبارات"""
        # إنشاء بيانات اختبار صغيرة
        cls.test_data_path = os.path.join(os.path.dirname(__file__), 'test_data.csv')

        # إنشاء مجلد للنماذج المدربة
        cls.test_models_dir = os.path.join(os.path.dirname(__file__), 'test_models')
        if not os.path.exists(cls.test_models_dir):
            os.makedirs(cls.test_models_dir)

        # إنشاء بيانات اختبار إذا لم تكن موجودة
        if not os.path.exists(cls.test_data_path):
            cls._create_test_data()

    @classmethod
    def _create_test_data(cls):
        """إنشاء بيانات اختبار صغيرة"""
        # إنشاء بيانات اختبار مصغرة
        test_data = {
            'App_ID': range(1, 11),
            'Category': ['Finance', 'Finance', 'Health', 'Health', 'Social', 'Social', 'Productivity', 'Productivity', 'Travel', 'Travel'],
            'Security_Practice_Used': [
                'SSL Pinning, Encrypted Storage',
                'Transaction Signing, Secure Coding Standards',
                'Data Encryption, Secure API Communication',
                'Secure Cloud Storage, Data Minimization',
                'End-to-end Encryption, Access Control',
                'Data Access Controls, Secure APIs',
                'Input Validation, Secure Local Storage',
                'Secure Cloud Sync, Multi-Factor Authentication',
                'API Security, User Authentication',
                'Geofencing, Anomaly Detection Algorithms'
            ],
            'Vulnerability_Types': [
                'Insecure Communication, Unauthorized Data Access',
                'Phishing, Man-in-the-Middle Attacks',
                'Vulnerable Code, Insecure Data Storage',
                'Unauthorized Access, Data Leakage',
                'Data Leakage, Insufficient Logging and Monitoring',
                'Insecure Direct Object References (IDOR), API Abuse',
                'SQL Injection, Cross-Site Scripting (XSS)',
                'Cloud Misconfiguration, Account Takeover',
                'Broken Authentication, Sensitive Data Exposure',
                'Location Spoofing, Unauthorized Account Access'
            ],
            'Mitigation_Strategies': [
                'Implement Network Security Configuration, Use of Biometric Authentication',
                'Multi-factor Authentication, SSL Pinning',
                'Regular Code Audits, Secure Coding Practices',
                'Role-Based Access Control, Data Encryption',
                'Enhanced Encryption Techniques, User Behavior Analysis',
                'Implementing OAuth 2.0 Scopes, Rate Limiting',
                'Use of Parameterized Queries, Content Security Policy',
                'Encrypted Data Storage, Regular Security Audits',
                'Two-Factor Authentication, Data Anonymization',
                'Two-Factor Authentication, Behavioral Analysis'
            ],
            'Developer_Challenges': [
                'Lack of expertise in secure coding, Time constraints',
                'Rapid technology changes, Regulatory compliance',
                'High cost of security tools, Complexity of healthcare regulations',
                'Balancing functionality with security, User adoption',
                'Balancing user convenience with security, Scalability issues',
                'API security management, Scalability',
                'Integration of multiple data sources, Keeping up with security patches',
                'Cloud data security, Multi-factor authentication ease of use',
                'User privacy concerns, Efficiently managing API keys',
                'Dealing with inaccurate location data, Privacy laws'
            ],
            'Assessment_Tools_Used': [
                'OWASP ZAP, Android Studio\'s Security Lint',
                'QARK, MobSF',
                'Burp Suite, SonarQube',
                'Firebase Test Lab, Android Studio\'s Lint',
                'Firebase Test Lab, LeakCanary',
                'Postman, API Security Checklist',
                'Android Lint, Veracode',
                'AWS Inspector, Google Authenticator',
                'Postman, OWASP ZAP',
                'Google Maps API, Fail2Ban'
            ],
            'Improvement_Suggestions': [
                'Introduce automated security testing in the CI/CD pipeline, Conduct regular security training for developers',
                'Regular security awareness training, Engage in ethical hacking exercises',
                'Implement a secure by design framework, Regular updates on security regulations',
                'Implement privacy by design, Regularly update data protection policies',
                'Streamline user authentication, Foster a culture of security awareness',
                'Enhancing API gateway security, Conducting regular API security audits',
                'Adopt continuous integration and deployment (CI/CD) for security updates, Regular security audits',
                'Enhancing cloud security configurations, Simplifying MFA processes',
                'Increase budget for security tools, Adopt a zero-trust architecture',
                'Enhancing privacy controls, Developing more sophisticated anomaly detection models'
            ]
        }

        # إنشاء DataFrame وحفظه
        df = pd.DataFrame(test_data)
        df.to_csv(cls.test_data_path, index=False)