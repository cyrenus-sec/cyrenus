# Cyrenus
بسم الله الرحمن الرحيم والصلاه علي رسوله الكريم 
![Cyrenus CE](readme.png)

Cyrenus هو نظام عالي الأداء لمراقبة حركة مرور الشبكة والحماية من هجمات DDoS يعتمد على تقنية eBPF، مع تكامل سلس مع Tetragon لأمان وقت التشغيل.

## التثبيت

اختر طريقة التثبيت التي تناسب احتياجاتك:

### الخيار 1: التثبيت السريع (ثنائي) - **مُوصى به** ⚡

قم بتشغيل هذا الأمر في سطر الأوامر لتثبيت Cyrenus فوراً:

```bash
curl -fsSL https://raw.githubusercontent.com/cyrenus-sec/cyrenus/main/install-binary.sh | sudo bash
```

تثبيت سريع باستخدام ملفات ثنائية مُعدة مسبقاً. لا يتطلب عملية بناء!

**المعماريات المدعومة:**
- x86_64 (amd64)
- ARM64 (aarch64)

**وقت التثبيت:** ~30 ثانية

---

### الخيار 2: البناء من المصدر

للتطوير أو التخصيص، قم بالبناء من المصدر:

```bash
sudo ./install.sh
```

يقوم هذا بتثبيت الاعتماديات وبناء Cyrenus وتكوين كل شيء تلقائياً.

**التوزيعات المدعومة:**
- Ubuntu/Debian  
- RHEL/CentOS/Fedora
- Arch Linux

**وقت التثبيت:** ~5-10 دقائق

---

### الخيار 3: حاوية Docker

تشغيل Cyrenus في حاوية:

**البناء:**
```bash
docker build -t cyrenus .
```

**التشغيل:**
```bash
docker run -d --name cyrenus \
  --cap-add SYS_ADMIN \
  --cap-add NET_ADMIN \
  --network host \
  -v /sys/kernel/btf:/sys/kernel/btf:ro \
  cyrenus
```

## ما بعد التثبيت

### 1. تكوين سياسات Tetragon

إذا قمت بالتثبيت عبر `install.sh` أو Docker، قد تكون السياسات مطبقة بالفعل. للتطبيق يدوياً:

```bash
# عرض السياسات النشطة
sudo tetra tracingpolicy list

# إضافة السياسات
sudo tetra tracingpolicy add config/tetragon/policies/anti-rce.yaml
sudo tetra tracingpolicy add config/tetragon/policies/file-integrity.yaml
```

### 2. التحقق من التثبيت

قم بتشغيل سكريبت التحقق لاختبار سياسات الأمان:

```bash
sudo bash tests/verify_policies.sh
```

## الميزات

- **الحماية من DDoS**: تصفية الحزم المعتمدة على XDP
- **تكامل Tetragon**: أمان وقت التشغيل للحماية من RCE ومراقبة العمليات
- **لوحة تحكم ويب**: تحليل وتحكم في حركة المرور في الوقت الفعلي

## التوثيق

راجع مجلد `docs/` للحصول على وثائق المعمارية وواجهة برمجة التطبيقات.

## الترخيص

MIT

---

## روابط مفيدة

- [README الإنجليزية](readme.md)
- [التوثيق](docs/)
- [المشاكل والدعم](https://github.com/cyrenus-sec/cyrenus/issues)
