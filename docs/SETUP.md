# إعداد محلل أمان التطبيقات المحمولة

هذا الدليل سيرشدك خلال عملية إعداد وتشغيل نظام تحليل أمان التطبيقات المحمولة.

## المتطلبات الأساسية

### متطلبات النظام
- Python 3.9 أو أحدث
- ذاكرة RAM: 4GB على الأقل (يُوصى بـ 8GB)
- مساحة قرص: 1GB على الأقل (للتطبيق والنموذج والبيانات)

### المكتبات المطلوبة
جميع المكتبات المطلوبة مدرجة في ملف `requirements.txt` وتتضمن:
- FastAPI
- Uvicorn
- Scikit-learn
- Pandas
- NumPy
- Joblib
- Requests (للعميل)
- Colorama (للعميل)
- Tabulate (للعميل)

## التثبيت

### الطريقة 1: التثبيت المباشر

1. استنساخ المستودع:
   ```bash
   git clone https://github.com/yourusername/mobile-security-analyzer.git
   cd mobile-security-analyzer
   ```

2. إنشاء بيئة افتراضية (اختياري ولكن يُنصح به):
   ```bash
   python -m venv venv
   
   # في أنظمة Windows
   venv\Scripts\activate
   
   # في أنظمة Linux/Mac
   source venv/bin/activate
   ```

3. تثبيت المكتبات المطلوبة:
   ```bash
   pip install -r requirements.txt
   ```

4. إنشاء هيكل المجلدات:
   ```bash
   mkdir -p data models
   ```

5. وضع ملف البيانات:
   - قم بتنزيل ملف `Mobile_Security_Dataset.csv` من مصدره الأصلي أو استخدم البيانات المقدمة.
   - ضع الملف في مجلد `data/`.

### الطريقة 2: استخدام Docker

1. استنساخ المستودع:
   ```bash
   git clone https://github.com/yourusername/mobile-security-analyzer.git
   cd mobile-security-analyzer
   ```

2. وضع ملف البيانات:
   - قم بوضع ملف `Mobile_Security_Dataset.csv` في مجلد `data/`.

3. بناء وتشغيل الحاويات:
   ```bash
   docker-compose up -d
   ```

   هذا سيقوم بإنشاء وتشغيل حاويتين:
   - حاوية API الرئيسية
   - حاوية MongoDB (اختيارية لتخزين نتائج التحليل)

## تدريب النموذج

يجب تدريب النموذج قبل استخدامه:

```bash
python train_model.py
```

خيارات إضافية:
```bash
# تخصيص عدد الأشجار في الغابة العشوائية
python train_model.py --trees 200

# تخصيص عدد الميزات في محول TF-IDF
python train_model.py --features 10000

# تخصيص مجلد الإخراج
python train_model.py --output custom_models

# اختبار النموذج بعد التدريب
python train_model.py --test
```

## تشغيل الخدمة

### تشغيل الخدمة مباشرة
```bash
python app.py
```

الخدمة ستكون متاحة على `http://localhost:8000`.

### تشغيل الخدمة باستخدام Uvicorn مباشرة
```bash
uvicorn app:app --host 0.0.0.0 --port 8000 --reload
```

## التحقق من التثبيت

1. افتح المتصفح وانتقل إلى `http://localhost:8000/docs` للوصول إلى واجهة Swagger API.

2. استخدم العميل النموذجي للتحقق من حالة الخدمة:
   ```bash
   python client_example.py --status
   ```

3. قم بتحليل ملف كود للتأكد من أن كل شيء يعمل:
   ```bash
   python client_example.py --file examples/sample_code.js --category Finance
   ```

## إعداد بيئة الإنتاج

للإعداد في بيئة الإنتاج، يُوصى بما يلي:

1. استخدام خادم WSGI مثل Gunicorn:
   ```bash
   pip install gunicorn
   gunicorn -w 4 -k uvicorn.workers.UvicornWorker app:app
   ```

2. إعداد Nginx كوسيط عكسي:
   ```nginx
   server {
       listen 80;
       server_name your_domain.com;

       location / {
           proxy_pass http://localhost:8000;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
       }
   }
   ```

3. إعداد HTTPS باستخدام Let's Encrypt.

4. تعديل متغيرات البيئة في Docker Compose:
   ```yaml
   environment:
     - ENVIRONMENT=production
     - MODEL_DIR=/app/models
     - DATA_PATH=/app/data/Mobile_Security_Dataset.csv
   ```

## استكشاف الأخطاء وإصلاحها

### مشكلة: الخدمة لا تبدأ

تحقق من:
- وجود ملفات النموذج المدربة في المجلد الصحيح
- تثبيت جميع المكتبات المطلوبة
- عدم استخدام المنفذ 8000 من قبل تطبيق آخر

### مشكلة: النموذج يعطي تحذيرات أو أخطاء

- تأكد من أن النموذج تم تدريبه بشكل صحيح
- تحقق من وجود ملف البيانات وصحة تنسيقه
- حاول تدريب النموذج مع عدد أقل من الميزات أو الأشجار

### مشكلة: Docker Compose يفشل في البدء

- تحقق من تثبيت Docker و Docker Compose بشكل صحيح
- تأكد من أن المستخدم لديه صلاحيات كافية
- تحقق من سجلات Docker باستخدام `docker-compose logs`

## التحديثات والصيانة

للحفاظ على النظام محدثاً:

1. تحديث المكتبات بشكل دوري:
   ```bash
   pip install -r requirements.txt --upgrade
   ```

2. إعادة تدريب النموذج مع بيانات جديدة:
   ```bash
   python train_model.py
   ```

3. اختبار الخدمة بعد التحديثات:
   ```bash
   pytest tests/
   ```

## الخطوات التالية

بعد إعداد النظام بنجاح، يمكنك:

- الاطلاع على [وثائق API](API.md) للتعرف على طرق استخدام واجهة برمجة التطبيقات
- مراجعة [أمثلة الاستخدام](EXAMPLES.md) لفهم كيفية استخدام النظام في سيناريوهات مختلفة
- استكشاف الكود المصدري لفهم كيفية عمل النظام وتخصيصه حسب احتياجاتك