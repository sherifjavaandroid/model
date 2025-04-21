# محلل أمان التطبيقات المحمولة

نظام ذكاء اصطناعي لتحليل أمان التطبيقات المحمولة استناداً إلى مجموعة بيانات Mobile Security Dataset.

## نظرة عامة

هذا المشروع يقدم نظاماً متكاملاً لتحليل الكود المصدري للتطبيقات المحمولة واكتشاف الثغرات الأمنية المحتملة استناداً إلى أنماط معروفة من الثغرات. يستخدم النظام نموذج تعلم آلي مدرب على مجموعة بيانات Mobile Security Dataset التي تحتوي على معلومات أمنية متنوعة عبر مختلف فئات التطبيقات.

## المميزات

- تحليل الكود للكشف عن الثغرات الأمنية المحتملة
- تقديم استراتيجيات تخفيف مناسبة للثغرات المكتشفة
- اقتراح أدوات تقييم أمنية مناسبة لمختلف أنواع التطبيقات
- توصيات لتحسين أمان الكود
- واجهة برمجة تطبيقات (API) سهلة الاستخدام
- تحليل مخصص بناءً على فئة التطبيق (مالية، صحية، اجتماعية، إلخ)

## الوثائق

- [تعليمات الإعداد](SETUP.md) - دليل تثبيت وإعداد النظام
- [وثائق API](API.md) - توثيق تفصيلي لواجهة برمجة التطبيقات
- [أمثلة](EXAMPLES.md) - أمثلة على استخدام النظام

## هيكل المشروع

```
mobile-security-analyzer/
│
├── app.py                    # الملف الرئيسي للتطبيق والـ API
├── train_model.py            # سكريبت لتدريب النموذج وحفظه
├── client_example.py         # عميل نموذجي لاستخدام الـ API
├── requirements.txt          # قائمة المكتبات المطلوبة
├── Dockerfile                # إعدادات Docker لبناء الصورة
├── docker-compose.yml        # إعدادات لتشغيل الخدمات باستخدام Docker
│
├── data/                     # مجلد لحفظ البيانات
│   └── Mobile_Security_Dataset.csv  # ملف البيانات الرئيسي
│
├── models/                   # مجلد لحفظ النماذج المدربة
│   ├── security_model.joblib # النموذج المدرب
│   ├── vectorizer.joblib     # محول النصوص إلى متجهات رقمية
│   └── category_map.txt      # خريطة ربط الفئات بالأرقام
│
├── utils/                    # مجلد للوظائف المساعدة
│   ├── __init__.py
│   ├── code_analyzer.py      # محلل الكود
│   ├── security_knowledge.py # قاعدة المعرفة الأمنية
│   └── data_utils.py         # وظائف معالجة البيانات
│
├── tests/                    # اختبارات وحدة للنظام
│   ├── __init__.py
│   ├── test_api.py           # اختبار الـ API
│   ├── test_model.py         # اختبار النموذج
│   └── test_code_analyzer.py # اختبار محلل الكود
│
└── docs/                     # الوثائق
    ├── README.md             # ملف القراءة الرئيسي
    ├── API.md                # وثائق الـ API
    ├── SETUP.md              # تعليمات الإعداد
    └── EXAMPLES.md           # أمثلة على الاستخدام
```

## التثبيت السريع

### باستخدام Python مباشرة

1. استنساخ المستودع
```bash
git clone https://github.com/yourusername/mobile-security-analyzer.git
cd mobile-security-analyzer
```

2. تثبيت المكتبات
```bash
pip install -r requirements.txt
```

3. وضع ملف البيانات
```bash
# نسخ ملف Mobile_Security_Dataset.csv إلى مجلد data/
```

4. تدريب النموذج
```bash
python train_model.py
```

5. تشغيل الخدمة
```bash
python app.py
```

### باستخدام Docker

```bash
docker-compose up -d
```

## استخدام النظام

### استخدام العميل النموذجي

```bash
# تحليل ملف كود
python client_example.py --file yourcode.js --category Finance

# التحقق من حالة الخدمة
python client_example.py --status

# حفظ نتائج التحليل في ملف
python client_example.py --file yourcode.js --category Health --output results.json
```

### استخدام API مباشرة

```bash
curl -X POST "http://localhost:8000/analyze" \
     -H "Content-Type: application/json" \
     -d '{"code": "function login(user, pass) { var query = \"SELECT * FROM users WHERE username=\'" + user + \"\' AND password=\'" + pass + \"\'\"; }", "category": "Finance"}'
```

## المساهمة

نرحب بالمساهمات! إذا كنت ترغب في المساهمة، يرجى اتباع الخطوات التالية:

1. إنشاء فرع (Fork) للمشروع
2. إنشاء فرع جديد (`git checkout -b feature/your-feature`)
3. الالتزام بالتغييرات (`git commit -am 'Add new feature'`)
4. دفع التغييرات إلى الفرع (`git push origin feature/your-feature`)
5. إنشاء طلب سحب (Pull Request)

## المساهمون

- اسمك هنا

## الترخيص

هذا المشروع مرخص تحت رخصة MIT - انظر ملف [LICENSE](LICENSE) للتفاصيل.