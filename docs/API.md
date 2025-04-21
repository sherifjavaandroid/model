# وثائق واجهة برمجة التطبيقات (API)

هذا المستند يوفر توثيقاً تفصيلياً لواجهة برمجة التطبيقات الخاصة بمحلل أمان التطبيقات المحمولة.

## نظرة عامة

محلل أمان التطبيقات المحمولة يوفر واجهة برمجة تطبيقات RESTful تسمح بتحليل الكود للكشف عن الثغرات الأمنية المحتملة. تستند الخدمة إلى FastAPI وتقدم نقاط نهاية بسيطة وفعالة.

### عنوان القاعدة
```
http://localhost:8000
```

يمكن تغيير المضيف والمنفذ حسب إعدادات التثبيت الخاصة بك.

## نقاط النهاية

### 1. الصفحة الرئيسية

```
GET /
```

توفر معلومات أساسية حول الخدمة.

#### الاستجابة

```json
{
  "message": "مرحباً بك في واجهة برمجة تطبيقات محلل أمان التطبيقات المحمولة",
  "documentation": "/docs",
  "analyze_endpoint": "/analyze"
}
```

### 2. التحقق من حالة الخدمة

```
GET /status
```

يوفر معلومات حول حالة الخدمة والنموذج.

#### الاستجابة

```json
{
  "api_status": "online",
  "model_loaded": true,
  "dataset_loaded": true,
  "num_records": 10000,
  "environment": "development",
  "version": "1.0.0"
}
```

### 3. الحصول على فئات التطبيقات

```
GET /categories
```

يوفر قائمة بجميع فئات التطبيقات المدعومة.

#### الاستجابة

```json
{
  "categories": [
    "Finance",
    "Health",
    "Social",
    "Productivity",
    "Travel",
    "Education",
    "Lifestyle",
    "Entertainment",
    "Food & Drink",
    "Shopping"
  ]
}
```

### 4. تحليل الكود

```
POST /analyze
```

تحليل الكود للكشف عن الثغرات الأمنية المحتملة.

#### معاملات الطلب

| المعامل | النوع | الوصف |
|---------|------|---------|
| code    | string | الكود المصدري للتحليل (إلزامي) |
| category | string | فئة التطبيق مثل "Finance", "Health", إلخ. (القيمة الافتراضية: "Finance") |

#### مثال على الطلب

```json
{
  "code": "function login(username, password) { var query = \"SELECT * FROM users WHERE username='\" + username + \"' AND password='\" + password + \"'\"; connection.query(query); }",
  "category": "Finance"
}
```

#### مثال على الاستجابة

```json
{
  "vulnerabilities": [
    {
      "name": "SQL Injection",
      "description": "A code injection technique that can destroy your database by inserting malicious SQL statements.",
      "severity": "High"
    },
    {
      "name": "Insecure Authentication",
      "description": "Implementation flaws in authentication that allow attackers to compromise passwords or session tokens.",
      "severity": "High"
    }
  ],
  "mitigation_strategies": [
    {
      "name": "Parameterized Queries