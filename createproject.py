import os

# تعريف المجلدات
dirs = [
    "mobile-security-analyzer",
    "mobile-security-analyzer/data",
    "mobile-security-analyzer/models",
    "mobile-security-analyzer/utils",
    "mobile-security-analyzer/tests",
    "mobile-security-analyzer/docs",
]

# تعريف الملفات الفارغة داخل كل مجلد
files = {
    "mobile-security-analyzer": [
        "app.py",
        "train_model.py",
        "client_example.py",
        "requirements.txt",
        "Dockerfile",
        "docker-compose.yml",
    ],
    "mobile-security-analyzer/data": [
        "Mobile_Security_Dataset.csv",
    ],
    "mobile-security-analyzer/models": [
        "security_model.joblib",
        "vectorizer.joblib",
        "category_map.txt",
    ],
    "mobile-security-analyzer/utils": [
        "__init__.py",
        "code_analyzer.py",
        "security_knowledge.py",
        "data_utils.py",
    ],
    "mobile-security-analyzer/tests": [
        "__init__.py",
        "test_api.py",
        "test_model.py",
        "test_code_analyzer.py",
    ],
    "mobile-security-analyzer/docs": [
        "README.md",
        "API.md",
        "SETUP.md",
        "EXAMPLES.md",
    ],
}

# إنشاء المجلدات
for d in dirs:
    os.makedirs(d, exist_ok=True)
    print(f"Created directory: {d}")

# إنشاء الملفات
for folder, file_list in files.items():
    for filename in file_list:
        path = os.path.join(folder, filename)
        # إذا كان الملف غير موجود، ننشئه
        if not os.path.exists(path):
            with open(path, "w", encoding="utf-8") as f:
                # يمكنك إضافة محتوى مبدئي هنا إذا أردت
                pass
            print(f"Created file: {path}")
        else:
            print(f"File already exists: {path}")
