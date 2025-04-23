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
from datetime import datetime

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
        self.vulnerabilities = self._get_vulnerabilities()

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

    def _get_vulnerabilities(self):
        """الحصول على الثغرات الأمنية المدعومة"""
        try:
            response = requests.get(f"{self.api_url}/vulnerabilities")
            if response.status_code == 200:
                return response.json().get("vulnerabilities", [])
            return []
        except Exception as e:
            print(f"خطأ في الاتصال بالخدمة: {e}")
            return []

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

    def analyze_code(self, code, category="Finance", analyze_context=False, file_extension=None):
        """تحليل الكود للثغرات الأمنية"""
        if category not in self.categories:
            print(f"تحذير: الفئة '{category}' غير موجودة في قائمة الفئات المدعومة. سيتم استخدام 'Finance' كفئة افتراضية.")
            category = "Finance"

        try:
            response = requests.post(
                f"{self.api_url}/analyze",
                json={
                    "code": code,
                    "category": category,
                    "analyze_context": analyze_context,
                    "file_extension": file_extension
                }
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

    def analyze_file(self, file_path, category="Finance", analyze_context=False):
        """تحليل ملف كود للثغرات الأمنية باستخدام نقطة نهاية الملفات"""
        if not os.path.exists(file_path):
            print(f"{Fore.RED}خطأ: ملف الكود '{file_path}' غير موجود.{Style.RESET_ALL}")
            return None

        if category not in self.categories:
            print(f"تحذير: الفئة '{category}' غير موجودة في قائمة الفئات المدعومة. سيتم استخدام 'Finance' كفئة افتراضية.")
            category = "Finance"

        try:
            with open(file_path, 'rb') as file:
                files = {'file': (os.path.basename(file_path), file, 'text/plain')}
                data = {'category': category, 'analyze_context': str(analyze_context).lower()}

                response = requests.post(
                    f"{self.api_url}/analyze/file",
                    files=files,
                    data=data
                )

            if response.status_code == 200:
                return response.json()
            else:
                print(f"خطأ: {response.status_code}")
                print(response.text)
                return None
        except Exception as e:
            print(f"خطأ في تحليل الملف: {e}")
            return None

    def analyze_github_repository(self, github_url, category="Finance", analyze_context=True,
                                  max_files=100, github_token=None):
        """تحليل مستودع GitHub كامل"""
        if category not in self.categories:
            print(f"تحذير: الفئة '{category}' غير موجودة في قائمة الفئات المدعومة. سيتم استخدام 'Finance' كفئة افتراضية.")
            category = "Finance"

        try:
            response = requests.post(
                f"{self.api_url}/analyze/github",
                json={
                    "github_url": github_url,
                    "category": category,
                    "analyze_context": analyze_context,
                    "max_files": max_files,
                    "github_token": github_token
                }
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

        # عرض معلومات السياق إذا كانت متوفرة
        context_info = results.get("context_info")
        if context_info:
            print("\n" + Fore.BLUE + "🔍 معلومات السياق:" + Style.RESET_ALL)
            security_score = context_info.get("security_score", {})
            score_color = Fore.GREEN if security_score.get("score", 0) >= 70 else (Fore.YELLOW if security_score.get("score", 0) >= 50 else Fore.RED)

            print(f"• لغة البرمجة: {Fore.CYAN}{context_info.get('language', 'غير معروفة')}{Style.RESET_ALL}")
            print(f"• تعقيد الكود: {Fore.CYAN}{context_info.get('code_complexity', 'متوسط')}{Style.RESET_ALL}")
            print(f"• درجة الأمان: {score_color}{security_score.get('score', 0)}/100 (التصنيف: {security_score.get('rating', 'F')}, مستوى الخطورة: {security_score.get('risk_level', 'مرتفع')}){Style.RESET_ALL}")

            # عرض أي تحليل خاص باللغة
            lang_analysis = context_info.get("language_specific_analysis", {})
            if lang_analysis and (lang_analysis.get("vulnerabilities") or lang_analysis.get("mitigations")):
                print(f"• تحليل خاص بلغة {context_info.get('language', 'البرمجة')}:")
                if lang_analysis.get("vulnerabilities"):
                    print(f"  - ثغرات: {Fore.RED}{', '.join(lang_analysis.get('vulnerabilities', []))}{Style.RESET_ALL}")
                if lang_analysis.get("mitigations"):
                    print(f"  - معالجات: {Fore.GREEN}{', '.join(lang_analysis.get('mitigations', []))}{Style.RESET_ALL}")

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

    def print_github_analysis_results(self, results):
        """عرض نتائج تحليل مستودع GitHub"""
        if not results:
            print("لا توجد نتائج للعرض.")
            return

        print("\n" + "="*80)
        print(Fore.CYAN + "📊 نتائج تحليل مستودع GitHub".center(80) + Style.RESET_ALL)
        print("="*80)

        # معلومات المستودع
        repo_info = results.get("repository", {})
        print(f"\n{Fore.BLUE}📁 معلومات المستودع:{Style.RESET_ALL}")
        print(f"• المالك: {Fore.CYAN}{repo_info.get('owner', 'غير معروف')}{Style.RESET_ALL}")
        print(f"• الاسم: {Fore.CYAN}{repo_info.get('name', 'غير معروف')}{Style.RESET_ALL}")
        print(f"• الرابط: {Fore.CYAN}{repo_info.get('url', 'غير معروف')}{Style.RESET_ALL}")
        print(f"• إجمالي الملفات: {Fore.CYAN}{repo_info.get('total_files', 0)}{Style.RESET_ALL}")
        print(f"• الملفات التي تم تحليلها: {Fore.CYAN}{repo_info.get('analyzed_files', 0)}{Style.RESET_ALL}")

        # ملخص النتائج
        summary = results.get("summary", {})
        print(f"\n{Fore.BLUE}📊 ملخص التحليل:{Style.RESET_ALL}")
        print(f"• إجمالي الثغرات: {Fore.RED}{summary.get('total_vulnerabilities', 0)}{Style.RESET_ALL}")
        print(f"• الملفات المتأثرة: {Fore.YELLOW}{summary.get('files_with_issues', 0)}{Style.RESET_ALL}")

        # أنواع الثغرات
        vuln_types = summary.get("vulnerability_types", {})
        if vuln_types:
            print(f"\n{Fore.RED}🔴 أنواع الثغرات المكتشفة:{Style.RESET_ALL}")
            vuln_table = []
            for vuln_type, count in vuln_types.items():
                vuln_table.append([vuln_type, str(count)])
            print(tabulate(vuln_table, headers=["نوع الثغرة", "العدد"], tablefmt="grid"))

        # استراتيجيات التخفيف الشائعة
        common_mitigations = summary.get("common_mitigations", {})
        if common_mitigations:
            print(f"\n{Fore.GREEN}🛡️ استراتيجيات التخفيف الموصى بها:{Style.RESET_ALL}")
            mit_table = []
            for mitigation, count in list(common_mitigations.items())[:5]:  # أعلى 5
                mit_table.append([mitigation, str(count)])
            print(tabulate(mit_table, headers=["الاستراتيجية", "التكرار"], tablefmt="grid"))

        # الملفات المتأثرة
        affected_files = results.get("files", [])
        if affected_files:
            print(f"\n{Fore.YELLOW}📄 الملفات المتأثرة:{Style.RESET_ALL}")
            for file_info in affected_files[:10]:  # عرض أول 10 ملفات فقط
                file_path = file_info.get("path", "")
                file_analysis = file_info.get("analysis", {})
                vulnerabilities = file_analysis.get("vulnerabilities", [])

                print(f"\n• {Fore.CYAN}{file_path}{Style.RESET_ALL}")
                for vuln in vulnerabilities:
                    vuln_name = vuln.get("name", "غير معروف")
                    severity = vuln.get("severity", "متوسط")
                    severity_color = (Fore.RED if severity in ["High", "Critical"] else
                                      Fore.YELLOW if severity == "Medium" else Fore.GREEN)
                    print(f"  - {severity_color}{vuln_name} ({severity}){Style.RESET_ALL}")

            if len(affected_files) > 10:
                print(f"\n  ... و {len(affected_files) - 10} ملفات أخرى")

        print("\n" + "="*80 + "\n")

def main():
    """النقطة الرئيسية لتشغيل البرنامج"""
    parser = argparse.ArgumentParser(description="تحليل أمان الكود باستخدام API تحليل الأمان")
    parser.add_argument("--url", type=str, default="http://localhost:8000", help="عنوان URL لـ API تحليل الأمان")
    parser.add_argument("--file", type=str, help="مسار ملف الكود المراد تحليله")
    parser.add_argument("--github", type=str, help="رابط مستودع GitHub للتحليل")
    parser.add_argument("--github-token", type=str, help="رمز GitHub OAuth للوصول الخاص (اختياري)")
    parser.add_argument("--max-files", type=int, default=100, help="الحد الأقصى لعدد الملفات للتحليل في مستودع GitHub")
    parser.add_argument("--category", type=str, default="Finance", help="فئة التطبيق (مثل Finance, Health, Social)")
    parser.add_argument("--status", action="store_true", help="التحقق من حالة API")
    parser.add_argument("--output", type=str, help="حفظ النتائج في ملف JSON")
    parser.add_argument("--list-categories", action="store_true", help="عرض قائمة الفئات المدعومة")
    parser.add_argument("--list-vulnerabilities", action="store_true", help="عرض قائمة الثغرات المدعومة")
    parser.add_argument("--context", action="store_true", help="تفعيل التحليل المتقدم مع معلومات السياق")

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
        print(f"عدد السجلات: {status.get('num_records', 0)}")
        print(f"عدد الثغرات المدعومة: {status.get('num_vulnerabilities', 0)}")
        print(f"عدد استراتيجيات التخفيف: {status.get('num_mitigations', 0)}")
        print(f"عدد أدوات التقييم: {status.get('num_tools', 0)}")
        print(f"الإصدار: {status.get('version', '1.0.0')}")
        return

    # عرض قائمة الفئات
    if args.list_categories:
        print("\n" + Fore.CYAN + "فئات التطبيقات المدعومة:" + Style.RESET_ALL)
        for category in analyzer.categories:
            print(f"• {category}")
        return

    # عرض قائمة الثغرات
    if args.list_vulnerabilities:
        print("\n" + Fore.CYAN + "الثغرات الأمنية المدعومة:" + Style.RESET_ALL)
        vulnerabilities = analyzer.vulnerabilities
        vuln_table = []
        for vuln in vulnerabilities:
            severity_color = Fore.RED if vuln['severity'] == 'High' or vuln['severity'] == 'Critical' else (Fore.YELLOW if vuln['severity'] == 'Medium' else Fore.GREEN)
            vuln_table.append([
                Fore.WHITE + vuln['name'] + Style.RESET_ALL,
                severity_color + vuln['severity'] + Style.RESET_ALL,
                vuln['description']
            ])
        print(tabulate(vuln_table, headers=["الثغرة", "الخطورة", "الوصف"], tablefmt="grid"))
        return

    # تحليل مستودع GitHub
    if args.github:
        print(f"جاري تحليل مستودع GitHub: {args.github} (الفئة: {args.category})...")
        print(f"الحد الأقصى للملفات: {args.max_files}")

        results = analyzer.analyze_github_repository(
            github_url=args.github,
            category=args.category,
            analyze_context=args.context,
            max_files=args.max_files,
            github_token=args.github_token
        )

        # حفظ النتائج إذا تم تحديد ذلك
        if args.output and results:
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(results, f, ensure_ascii=False, indent=2)
            print(f"{Fore.GREEN}تم حفظ النتائج في ملف: {args.output}{Style.RESET_ALL}")

        # عرض النتائج
        analyzer.print_github_analysis_results(results)
        return

    # تحليل ملف محلي
    if args.file:
        if not os.path.exists(args.file):
            print(f"{Fore.RED}خطأ: ملف الكود '{args.file}' غير موجود.{Style.RESET_ALL}")
            return

        # الحصول على امتداد الملف
        file_extension = os.path.splitext(args.file)[1]

        # تحليل الكود
        print(f"جاري تحليل الكود من ملف '{args.file}' (الفئة: {args.category})...")

        # استخدام واجهة API الملفات إذا كانت متاحة
        try:
            results = analyzer.analyze_file(args.file, args.category, args.context)
            if not results:
                # إذا فشل تحليل الملف، نرجع إلى الطريقة التقليدية
                with open(args.file, 'r', encoding='utf-8') as f:
                    code = f.read()
                results = analyzer.analyze_code(code, args.category, args.context, file_extension)
        except Exception as e:
            print(f"{Fore.YELLOW}تعذر استخدام واجهة تحليل الملفات: {e}. سيتم استخدام الطريقة التقليدية.{Style.RESET_ALL}")
            # قراءة محتوى ملف الكود
            with open(args.file, 'r', encoding='utf-8') as f:
                code = f.read()
            results = analyzer.analyze_code(code, args.category, args.context, file_extension)

        # حفظ النتائج في ملف إذا تم تحديد ذلك
        if args.output and results:
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(results, f, ensure_ascii=False, indent=2)
            print(f"{Fore.GREEN}تم حفظ النتائج في ملف: {args.output}{Style.RESET_ALL}")

        # عرض النتائج
        analyzer.print_analysis_results(results)
    else:
        print(f"{Fore.YELLOW}الرجاء تحديد ملف الكود باستخدام '--file' أو مستودع GitHub باستخدام '--github'{Style.RESET_ALL}")
        print("مثال: python client_example.py --file app.js --category Finance")
        print("مثال: python client_example.py --github https://github.com/username/repository --category Finance")
        print("استخدم --help للحصول على قائمة كاملة بالخيارات المتاحة")

if __name__ == "__main__":
    main()