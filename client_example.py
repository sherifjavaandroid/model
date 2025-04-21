#!/usr/bin/env python
# -*- coding: utf-8 -*-

import requests
import json
import argparse
import os
import sys
import colorama
from colorama import Fore, Back, Style
from tabulate import tabulate

# تهيئة دعم الألوان
colorama.init()

# إعداد الترميز لدعم اللغة العربية
if sys.stdout.encoding != 'utf-8':
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
    elif hasattr(sys.stdout, 'buffer'):
        import io
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

class SecurityAnalyzer:
    """
    فئة لتحليل أمان الكود باستخدام API تحليل الأمان
    """

    def __init__(self, api_url="http://localhost:8000"):
        """تهيئة محلل الأمان مع رابط API"""
        self.api_url = api_url
        self.categories = self._get_categories()

    def _get_categories(self):
        """الحصول على فئات التطبيقات المدعومة"""
        try:
            response = requests.get(f"{self.api_url}/categories")
            if response.status_code == 200:
                return response.json().get("categories", [])
            return ["Finance", "Health", "Social", "Productivity", "Travel", "Education"]
        except Exception as e:
            print(f"خطأ في الاتصال بالخدمة: {e}")
            return ["Finance", "Health", "Social", "Productivity", "Travel", "Education"]

    def check_api_status(self):
        """التحقق من حالة API"""
        try:
            response = requests.get(f"{self.api_url}/status")
            if response.status_code == 200:
                return response.json()
            return {"api_status": "غير متصل", "model_loaded": False, "dataset_loaded": False}
        except Exception as e:
            print(f"خطأ في الاتصال بالخدمة: {e}")
            return {"api_status": "غير متصل", "model_loaded": False, "dataset_loaded": False}

    def analyze_code(self, code, category="Finance"):
        """تحليل الكود للثغرات الأمنية"""
        if category not in self.categories:
            print(f"تحذير: الفئة '{category}' غير موجودة في قائمة الفئات المدعومة. سيتم استخدام 'Finance' كفئة افتراضية.")
            category = "Finance"

        try:
            response = requests.post(
                f"{self.api_url}/analyze",
                json={"code": code, "category": category}
            )

            if response.status_code == 200:
                return response.json()
            else:
                print(f"خطأ: {response.status_code}")
                print(response.text)
                return None
        except Exception as e:
            print(f"خطأ في الاتصال بالخدمة: {e}")
            return None

    def print_analysis_results(self, results):
        """عرض نتائج التحليل بتنسيق مناسب"""
        if not results:
            print("لا توجد نتائج للعرض.")
            return

        print("\n" + "="*80)
        print(Fore.CYAN + "📊 نتائج تحليل أمان الكود".center(80) + Style.RESET_ALL)
        print("="*80)

        # عرض الثغرات الأمنية في جدول
        vulnerabilities = results.get("vulnerabilities", [])
        if vulnerabilities:
            print("\n" + Fore.RED + "🔴 الثغرات الأمنية المكتشفة:" + Style.RESET_ALL)
            vuln_table = []
            for vuln in vulnerabilities:
                severity_color = Fore.RED if vuln['severity'] == 'High' or vuln['severity'] == 'Critical' else (Fore.YELLOW if vuln['severity'] == 'Medium' else Fore.GREEN)
                vuln_table.append([
                    Fore.WHITE + vuln['name'] + Style.RESET_ALL,
                    severity_color + vuln['severity'] + Style.RESET_ALL,
                    vuln['description']
                ])

            print(tabulate(vuln_table, headers=["الثغرة", "الخطورة", "الوصف"], tablefmt="grid"))
        else:
            print("\n" + Fore.GREEN + "✅ لم يتم اكتشاف أي ثغرات أمنية واضحة" + Style.RESET_ALL)

        # عرض استراتيجيات التخفيف في جدول
        mitigation_strategies = results.get("mitigation_strategies", [])
        if mitigation_strategies:
            print("\n" + Fore.GREEN + "🛡️ استراتيجيات التخفيف المقترحة:" + Style.RESET_ALL)
            mitig_table = []
            for strat in mitigation_strategies:
                complexity_color = Fore.GREEN if strat['implementation_complexity'] == 'Low' else (Fore.YELLOW if strat['implementation_complexity'] == 'Medium' else Fore.RED)
                mitig_table.append([
                    Fore.WHITE + strat['name'] + Style.RESET_ALL,
                    complexity_color + strat['implementation_complexity'] + Style.RESET_ALL,
                    strat['description']
                ])

            print(tabulate(mitig_table, headers=["الاستراتيجية", "التعقيد", "الوصف"], tablefmt="grid"))

        # عرض التوصيات
        recommendations = results.get("security_recommendations", [])
        if recommendations:
            print("\n" + Fore.BLUE + "🔵 توصيات تحسين الأمان:" + Style.RESET_ALL)
            rec_table = []
            for rec in recommendations:
                priority_color = Fore.RED if rec['priority'] == 'High' else (Fore.YELLOW if rec['priority'] == 'Medium' else Fore.GREEN)
                rec_table.append([
                    priority_color + rec['priority'] + Style.RESET_ALL,
                    rec['description']
                ])

            print(tabulate(rec_table, headers=["الأولوية", "الوصف"], tablefmt="grid"))

        # عرض أدوات التقييم
        tools = results.get("assessment_tools", [])
        if tools:
            print("\n" + Fore.MAGENTA + "🛠️ أدوات التقييم الموصى بها:" + Style.RESET_ALL)
            tool_table = []
            for tool in tools:
                tool_table.append([
                    Fore.WHITE + tool['name'] + Style.RESET_ALL,
                    tool['purpose'],
                    tool.get('url', 'غير متوفر')
                ])

            print(tabulate(tool_table, headers=["الأداة", "الغرض", "الرابط"], tablefmt="grid"))

        print("\n" + "="*80 + "\n")

def main():
    """النقطة الرئيسية لتشغيل البرنامج"""
    parser = argparse.ArgumentParser(description="تحليل أمان الكود باستخدام API تحليل الأمان")
    parser.add_argument("--url", type=str, default="http://localhost:8000", help="عنوان URL لـ API تحليل الأمان")
    parser.add_argument("--file", type=str, help="مسار ملف الكود المراد تحليله")
    parser.add_argument("--category", type=str, default="Finance", help="فئة التطبيق (مثل Finance, Health, Social)")
    parser.add_argument("--status", action="store_true", help="التحقق من حالة API")
    parser.add_argument("--output", type=str, help="حفظ النتائج في ملف JSON")

    args = parser.parse_args()

    # إنشاء محلل الأمان
    analyzer = SecurityAnalyzer(api_url=args.url)

    # التحقق من حالة API
    if args.status:
        status = analyzer.check_api_status()
        print("\n" + Fore.CYAN + "حالة API تحليل الأمان:" + Style.RESET_ALL)
        print(f"حالة الخدمة: {Fore.GREEN if status['api_status'] == 'online' else Fore.RED}{status['api_status']}{Style.RESET_ALL}")
        print(f"النموذج محمّل: {Fore.GREEN + 'نعم' if status['model_loaded'] else Fore.RED + 'لا'}{Style.RESET_ALL}")
        print(f"مجموعة البيانات محمّلة: {Fore.GREEN + 'نعم' if status['dataset_loaded'] else Fore.RED + 'لا'}{Style.RESET_ALL}")
        print(f"الفئات المدعومة: {', '.join(analyzer.categories)}")
        return

    # تحقق من ملف الكود
    if args.file:
        if not os.path.exists(args.file):
            print(f"{Fore.RED}خطأ: ملف الكود '{args.file}' غير موجود.{Style.RESET_ALL}")
            return

        # قراءة محتوى ملف الكود
        with open(args.file, 'r', encoding='utf-8') as f:
            code = f.read()

        # تحليل الكود
        print(f"جاري تحليل الكود من ملف '{args.file}' (الفئة: {args.category})...")
        results = analyzer.analyze_code(code, args.category)

        # حفظ النتائج في ملف إذا تم تحديد ذلك
        if args.output and results:
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(results, f, ensure_ascii=False, indent=2)
            print(f"{Fore.GREEN}تم حفظ النتائج في ملف: {args.output}{Style.RESET_ALL}")

        # عرض النتائج
        analyzer.print_analysis_results(results)
    else:
        print(f"{Fore.YELLOW}الرجاء تحديد ملف الكود باستخدام '--file'{Style.RESET_ALL}")
        print("مثال: python client_example.py --file app.js --category Finance")

if __name__ == "__main__":
    main()