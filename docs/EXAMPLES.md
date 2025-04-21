# أمثلة على استخدام محلل أمان التطبيقات المحمولة

هذا المستند يوفر أمثلة عملية لاستخدام نظام تحليل أمان التطبيقات المحمولة في سيناريوهات مختلفة.

## جدول المحتويات

1. [استخدام العميل النموذجي](#استخدام-العميل-النموذجي)
2. [استخدام API مباشرة](#استخدام-api-مباشرة)
3. [سيناريوهات تحليل شائعة](#سيناريوهات-تحليل-شائعة)
4. [دمج النظام مع أدوات أخرى](#دمج-النظام-مع-أدوات-أخرى)
5. [نصائح متقدمة](#نصائح-متقدمة)

## استخدام العميل النموذجي

العميل النموذجي `client_example.py` هو أداة سطر أوامر بسيطة لتفاعل المستخدم مع نظام التحليل.

### التحقق من حالة الخدمة

```bash
python client_example.py --status
```

سترى مخرجات مشابهة لما يلي:

```
حالة API تحليل الأمان:
حالة الخدمة: online
النموذج محمّل: نعم
مجموعة البيانات محمّلة: نعم
الفئات المدعومة: Finance, Health, Social, Productivity, Travel, Education
```

### تحليل ملف كود

```bash
python client_example.py --file examples/login.js --category Finance
```

سيعرض النظام تحليلاً مفصلاً يتضمن:
- الثغرات الأمنية المكتشفة
- استراتيجيات التخفيف المقترحة
- توصيات تحسين الأمان
- أدوات التقييم الموصى بها

### حفظ نتائج التحليل

```bash
python client_example.py --file examples/payment.js --category Finance --output results.json
```

سيتم تحليل الكود وحفظ النتائج في ملف JSON يمكن معالجته لاحقاً.

## استخدام API مباشرة

### تحليل الكود باستخدام Python

```python
import requests
import json

# رابط الخدمة
api_url = "http://localhost:8000/analyze"

# الكود المراد تحليله
code = """
function processPayment(cardNumber, cvv) {
  // إرسال بيانات البطاقة بدون تشفير
  fetch('https://api.example.com/payment', {
    method: 'POST',
    body: JSON.stringify({ cardNumber, cvv })
  });
}
"""

# إرسال طلب التحليل
response = requests.post(
    api_url,
    json={
        "code": code,
        "category": "Finance"
    }
)

# عرض النتائج
if response.status_code == 200:
    results = response.json()
    
    print("الثغرات الأمنية:")
    for vuln in results["vulnerabilities"]:
        print(f"- {vuln['name']} ({vuln['severity']}): {vuln['description']}")
    
    print("\nاستراتيجيات التخفيف:")
    for strategy in results["mitigation_strategies"]:
        print(f"- {strategy['name']}: {strategy['description']}")
else:
    print(f"حدث خطأ: {response.status_code}")
    print(response.text)
```

### تحليل الكود باستخدام JavaScript

```javascript
// رابط الخدمة
const apiUrl = 'http://localhost:8000/analyze';

// الكود المراد تحليله
const code = `
function storeUserData(userData) {
  localStorage.setItem('userData', JSON.stringify({
    name: userData.name,
    creditCard: userData.cardNumber,
    ssn: userData.socialSecurityNumber
  }));
}
`;

// إرسال طلب التحليل
async function analyzeSecurity() {
  try {
    const response = await fetch(apiUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        code: code,
        category: 'Finance'
      }),
    });
    
    if (!response.ok) {
      throw new Error(`خطأ: ${response.status}`);
    }
    
    const results = await response.json();
    
    console.log('الثغرات الأمنية:');
    results.vulnerabilities.forEach(vuln => {
      console.log(`- ${vuln.name} (${vuln.severity}): ${vuln.description}`);
    });
    
    console.log('\nاستراتيجيات التخفيف:');
    results.mitigation_strategies.forEach(strategy => {
      console.log(`- ${strategy.name}: ${strategy.description}`);
    });
  } catch (error) {
    console.error('حدث خطأ:', error);
  }
}

analyzeSecurity();
```

## سيناريوهات تحليل شائعة

### تحليل ملف تسجيل الدخول

يعد تحليل شاشات تسجيل الدخول أمراً مهماً نظراً لحساسيتها من الناحية الأمنية.

```javascript
// login.js
function login(username, password) {
  // ثغرة حقن SQL محتملة
  const query = `SELECT * FROM users WHERE username='${username}' AND password='${password}'`;
  
  // خطر: تخزين كلمة المرور بدون تشفير
  localStorage.setItem('credentials', JSON.stringify({ username, password }));
  
  // خطر: عدم استخدام HTTPS
  fetch('http://api.example.com/login', {
    method: 'POST',
    body: JSON.stringify({ username, password })
  });
}
```

تحليل هذا الكود:

```bash
python client_example.py --file login.js --category Finance
```

ستظهر تحذيرات حول:
- حقن SQL (SQL Injection)
- تخزين بيانات حساسة بدون تشفير
- استخدام HTTP بدلاً من HTTPS

### تحليل معالجة الدفع

معالجة المدفوعات تحتاج إلى مستوى عالٍ من الأمان:

```javascript
// payment.js
function processPayment(cardDetails) {
  // خطر: عدم التحقق من المدخلات
  const { cardNumber, cvv, expiry } = cardDetails;
  
  // خطر: تخزين بيانات البطاقة بشكل مباشر
  const transaction = {
    card: cardNumber,
    verification: cvv,
    expires: expiry,
    amount: document.getElementById('amount').value
  };
  
  // خطر: عدم استخدام استراتيجيات أمان PCI DSS
  sendPaymentData('https://api.example.com/payment', transaction);
}
```

تحليل هذا الكود:

```bash
python client_example.py --file payment.js --category Finance
```

### تحليل تخزين البيانات الصحية

تطبيقات الرعاية الصحية تخضع لمتطلبات أمان خاصة:

```javascript
// health_data.js
function storePatientData(patientInfo) {
  // خطر: عدم الامتثال لـ HIPAA
  const medicalRecord = {
    name: patientInfo.name,
    ssn: patientInfo.socialSecurityNumber,
    diagnosis: patientInfo.diagnosis,
    treatment: patientInfo.treatment
  };
  
  // خطر: عدم تشفير البيانات الصحية
  localStorage.setItem('patientData', JSON.stringify(medicalRecord));
  
  // خطر: عدم استخدام الوصول المستند إلى الأدوار
  uploadMedicalRecord(medicalRecord);
}
```

تحليل هذا الكود مع تحديد الفئة المناسبة:

```bash
python client_example.py --file health_data.js --category Health
```

## دمج النظام مع أدوات أخرى

### دمج مع عملية CI/CD

يمكن إضافة تحليل الأمان كخطوة في عملية CI/CD الخاصة بك:

#### باستخدام GitHub Actions

```yaml
# .github/workflows/security.yml
name: Security Analysis

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - name: Set up Python
      uses: actions/setup-python@v2
      with:
        python-version: '3.9'
    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install requests
    - name: Analyze Security
      run: |
        # قم بتحليل كل ملفات JavaScript
        for file in $(find . -name "*.js"); do
          echo "تحليل $file..."
          python security_scan.py --file "$file" --category Finance --output "${file}_analysis.json"
        done
    - name: Check for High Severity Issues
      run: |
        # فشل الاختبار إذا تم العثور على ثغرات خطيرة
        if grep -q "\"severity\":\"High\"" *_analysis.json; then
          echo "تم اكتشاف ثغرات أمنية خطيرة!"
          exit 1
        fi
```

### دمج مع أدوات تحليل الشفرة المصدرية

يمكن دمج محلل الأمان مع أدوات تحليل الشفرة المصدرية مثل ESLint لـ JavaScript:

#### ESLint مع محلل الأمان

أنشئ ملفاً بسيطاً `security-lint.js`:

```javascript
const { exec } = require('child_process');
const fs = require('fs');

module.exports = {
  processors: {
    '.js': {
      preprocess: function(text, filename) {
        // تحليل الملف باستخدام محلل أمان التطبيقات المحمولة
        exec(`python client_example.py --file "${filename}" --category Finance --output "${filename}.analysis.json"`);
        return [text];
      },
      postprocess: function(messages, filename) {
        try {
          // قراءة نتائج التحليل
          const analysis = JSON.parse(fs.readFileSync(`${filename}.analysis.json`, 'utf8'));
          
          // تحويل الثغرات إلى تحذيرات ESLint
          const securityMessages = analysis.vulnerabilities.map(vuln => ({
            ruleId: `security/${vuln.name.toLowerCase().replace(/\s+/g, '-')}`,
            severity: 2,
            message: `${vuln.name}: ${vuln.description}`,
            line: 1,
            column: 1
          }));
          
          return messages[0].concat(securityMessages);
        } catch (error) {
          console.error(`Error processing security analysis for ${filename}:`, error);
          return messages[0];
        }
      }
    }
  }
};
```

## نصائح متقدمة

### تخصيص النتائج حسب فئة التطبيق

لتحسين دقة التحليل، تأكد من اختيار الفئة المناسبة:

- **Finance**: للتطبيقات المالية، المصرفية، الدفع، العملات المشفرة
- **Health**: للتطبيقات الصحية، السجلات الطبية، اللياقة البدنية
- **Social**: لمنصات التواصل الاجتماعي، الدردشة، المراسلة
- **Productivity**: لتطبيقات العمل، إدارة المهام، التقويم
- **Travel**: لتطبيقات السفر، الحجز، الخرائط
- **Education**: للتطبيقات التعليمية، منصات التعلم

### تحليل قاعدة الشفرة بالكامل

يمكنك تحليل مشروع كامل باستخدام سكريبت بسيط:

```python
#!/usr/bin/env python3
import os
import requests
import json
import argparse

def analyze_project(project_dir, category, output_dir):
    # إنشاء مجلد للنتائج
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # البحث عن ملفات الكود
    extensions = ['.js', '.java', '.py', '.php']
    security_issues = []
    
    for root, _, files in os.walk(project_dir):
        for file in files:
            if any(file.endswith(ext) for ext in extensions):
                file_path = os.path.join(root, file)
                
                # قراءة الملف
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    code = f.read()
                
                # تحليل الملف
                try:
                    response = requests.post(
                        "http://localhost:8000/analyze",
                        json={"code": code, "category": category}
                    )
                    
                    if response.status_code == 200:
                        result = response.json()
                        
                        # حفظ النتائج
                        output_file = os.path.join(output_dir, f"{os.path.basename(file_path)}.analysis.json")
                        with open(output_file, 'w') as f:
                            json.dump(result, f, indent=2)
                        
                        # جمع القضايا
                        if result["vulnerabilities"]:
                            for vuln in result["vulnerabilities"]:
                                security_issues.append({
                                    "file": file_path,
                                    "vulnerability": vuln["name"],
                                    "severity": vuln["severity"]
                                })
                except Exception as e:
                    print(f"خطأ في تحليل {file_path}: {e}")
    
    # حفظ تقرير ملخص
    summary_file = os.path.join(output_dir, "security_summary.json")
    with open(summary_file, 'w') as f:
        json.dump({
            "total_issues": len(security_issues),
            "issues": security_issues
        }, f, indent=2)
    
    print(f"تم العثور على {len(security_issues)} مشكلة أمنية. راجع التقرير في {summary_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="تحليل أمان مشروع كامل")
    parser.add_argument("--dir", required=True, help="مسار مجلد المشروع")
    parser.add_argument("--category", default="Finance", help="فئة التطبيق")
    parser.add_argument("--output", default="security_analysis", help="مجلد النتائج")
    
    args = parser.parse_args()
    analyze_project(args.dir, args.category, args.output)
```

استخدام السكريبت:

```bash
python analyze_project.py --dir /path/to/your/project --category Finance --output security_results
```