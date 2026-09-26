const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

// الاتصال بقاعدة البيانات السحابية
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/smart_accounting_saas';
mongoose.connect(MONGO_URI)
.then(() => console.log('✅ تم الاتصال بقاعدة البيانات بنجاح'))
.catch(err => console.log('❌ خطأ في الاتصال:', err));

const JWT_SECRET = process.env.JWT_SECRET || 'Hussein_Elsanhoty_Secret_Key_2026';

// 1. جدول الشركات مع فترة تجريبية مجانية 3 أشهر (90 يوم) أوتوماتيكياً
const CompanySchema = new mongoose.Schema({
    companyName: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    subscriptionStatus: { type: String, default: 'active' }, 
    expiresAt: { type: Date, default: () => new Date(Date.now() + 90*24*60*60*1000) }, 
    createdAt: { type: Date, default: Date.now }
});
const Company = mongoose.model('Company', CompanySchema);

// 2. جدول المنتجات والفواتير لكل شركة
const ProductSchema = new mongoose.Schema({
    companyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Company', required: true },
    code: String,
    name: String,
    buy: Number,
    sell: Number,
    qty: Number
});
const Product = mongoose.model('Product', ProductSchema);

// Middleware للتحقق من التوكن وصلاحية اشتراك الـ 3 أشهر للشركة
const verifyTokenAndSubscription = async (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(401).json({ error: 'ممنوع الدخول، يرجى تسجيل الدخول أولاً' });

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const company = await Company.findById(decoded.companyId);
        
        if (!company) return res.status(404).json({ error: 'الشركة غير موجودة' });
        if (company.subscriptionStatus !== 'active' || new Date() > new Date(company.expiresAt)) {
            return res.status(403).json({ error: 'انتهت صلاحية اشتراك الـ 3 أشهر للشركة' });
        }

        req.companyId = company._id;
        next();
    } catch (err) {
        res.status(401).json({ error: 'التوكن غير صالح' });
    }
};

// --- مسارات الـ API الأساسية ---
app.get('/', (req, res) => {
    res.send('🚀 Smart Accounting API is running successfully with 3-months free trial!');
});

// تسجيل شركة جديدة (مع منح 3 أشهر تجربة مجانية فوراً)
app.post('/api/register', async (req, res) => {
    try {
        const { companyName, email, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        
        const newCompany = new Company({ companyName, email, password: hashedPassword });
        await newCompany.save();
        
        res.status(201).json({ message: 'تم تسجيل الشركة بنجاح وتم تفعيل الـ 3 أشهر المجانية!' });
    } catch (err) {
        res.status(400).json({ error: 'البريد الإلكتروني مسجل مسبقاً' });
    }
});

// تسجيل الدخول للشركات
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const company = await Company.findOne({ email });
        if (!company) return res.status(404).json({ error: 'البيانات غير صحيحة' });

        const isMatch = await bcrypt.compare(password, company.password);
        if (!isMatch) return res.status(400).json({ error: 'كلمة المرور غير صحيحة' });

        const token = jwt.sign({ companyId: company._id }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ token, companyName: company.companyName, expiresAt: company.expiresAt });
    } catch (err) {
        res.status(500).json({ error: 'خطأ في السيرفر' });
    }
});

// جلب المنتجات الخاصة بالشركة فقط (عزل تام للبيانات)
app.get('/api/products', verifyTokenAndSubscription, async (req, res) => {
    const products = await Product.find({ companyId: req.companyId });
    res.json(products);
});

// إضافة منتج جديد لمخزن الشركة
app.post('/api/products', verifyTokenAndSubscription, async (req, res) => {
    const { code, name, buy, sell, qty } = req.body;
    const newProduct = new Product({ companyId: req.companyId, code, name, buy, sell, qty });
    await newProduct.save();
    res.json({ message: 'تم إضافة المنتج بنجاح' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 السيرفر شغال على البورت ${PORT}`);
});
