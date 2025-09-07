// Complete server.js with Fee Management System

require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'fallback-secret-key';

// CORS Configuration
const corsOptions = {
    origin: [
        'https://tmtshashi.onrender.com',
        'https://eduplatform-backend-k9fr.onrender.com',
        'http://localhost:3000',
        'http://localhost:8080',
        'http://127.0.0.1:5500',
        'http://localhost:5173'
    ],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    preflightContinue: false,
    optionsSuccessStatus: 204
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Create uploads directories if they don't exist
if (!fs.existsSync('uploads')) {
    fs.mkdirSync('uploads');
}

if (!fs.existsSync('uploads/profiles')) {
    fs.mkdirSync('uploads/profiles');
}

app.use('/uploads', express.static('uploads'));

// Health check endpoint for Render
app.get('/health', (req, res) => {
    res.status(200).json({
        status: 'OK',
        timestamp: new Date().toISOString(),
        service: 'Educational Platform API',
        version: '1.0.0'
    });
});

// Root endpoint
app.get('/', (req, res) => {
    res.json({
        message: 'Educational Platform API is running',
        version: '1.0.0',
        health: '/health',
        endpoints: {
            auth: '/api/auth/*',
            resources: '/api/resources/*',
            schedules: '/api/schedules/*',
            users: '/api/user/*',
            students: '/api/students/*',
            fees: '/api/fees/*'
        }
    });
});

// MongoDB Connection
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/eduplatform';

mongoose.connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
.then(() => {
    console.log('✅ Connected to MongoDB');
})
.catch((error) => {
    console.error('❌ MongoDB connection error:', error);
    process.exit(1);
});

// Keep service alive on Render
if (process.env.NODE_ENV === 'production') {
    const keepAliveUrl = process.env.RENDER_SERVICE_URL || `http://localhost:${PORT}`;
    setInterval(async () => {
        try {
            const response = await fetch(`${keepAliveUrl}/health`);
            if (response.ok) {
                console.log('🏓 Keep-alive ping successful');
            }
        } catch (error) {
            console.log('⚠️ Keep-alive ping failed (this is normal during development)');
        }
    }, 14 * 60 * 1000);
}

// User Schema
const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    name: { type: String, required: true },
    role: { type: String, enum: ['teacher', 'student'], required: true },
    profileImage: { type: String, default: '' },
    bio: { type: String, default: '' },
    phone: { type: String, default: '' },
    dateOfBirth: { type: String, default: '' },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// Resource Schema
const resourceSchema = new mongoose.Schema({
    title: { type: String, required: true },
    description: { type: String, default: '' },
    type: { type: String, enum: ['note', 'question', 'book'], required: true },
    fileName: { type: String, required: true },
    filePath: { type: String, required: true },
    fileSize: { type: Number, required: true },
    uploadedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

const Resource = mongoose.model('Resource', resourceSchema);

// Schedule Schema
const scheduleSchema = new mongoose.Schema({
    title: { type: String, required: true },
    description: { type: String, default: '' },
    date: { type: String, required: true },
    time: { type: String, required: true },
    meetingLink: { type: String, default: '' },
    password: { type: String, default: '' },
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    createdAt: { type: Date, default: Date.now }
});

const Schedule = mongoose.model('Schedule', scheduleSchema);

// Fee Schema
const feeSchema = new mongoose.Schema({
    studentId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    month: { type: String, required: true },
    year: { type: Number, required: true },
    amount: { type: Number, required: true },
    status: { type: String, enum: ['paid', 'pending', 'overdue'], default: 'pending' },
    paymentDate: { type: Date },
    notes: { type: String, default: '' },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

// Create compound index to prevent duplicate fees for same student/month/year
feeSchema.index({ studentId: 1, month: 1, year: 1 }, { unique: true });

const Fee = mongoose.model('Fee', feeSchema);

// Authentication Middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
};

// Teacher Role Middleware
const requireTeacher = (req, res, next) => {
    if (req.user.role !== 'teacher') {
        return res.status(403).json({ error: 'Teacher access required' });
    }
    next();
};

// File Upload Configuration for Resources
const resourceStorage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});

// File Upload Configuration for Profile Images
const profileStorage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/profiles/');
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, 'profile-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const uploadResource = multer({
    storage: resourceStorage,
    limits: { fileSize: 50 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        const allowedTypes = /jpeg|jpg|png|gif|pdf|doc|docx|txt|zip|rar/;
        const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = allowedTypes.test(file.mimetype);

        if (mimetype && extname) {
            return cb(null, true);
        } else {
            cb(new Error('File type not supported'));
        }
    }
});

const uploadProfile = multer({
    storage: profileStorage,
    limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit for profile images
    fileFilter: (req, file, cb) => {
        const allowedTypes = /jpeg|jpg|png|gif/;
        const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = allowedTypes.test(file.mimetype);

        if (mimetype && extname) {
            return cb(null, true);
        } else {
            cb(new Error('Only image files (JPEG, JPG, PNG, GIF) are allowed'));
        }
    }
});

// Initialize Default Users and Sample Fees
const initializeDefaultData = async () => {
    try {
        const userCount = await User.countDocuments();
        if (userCount === 0) {
            const defaultUsers = [
                {
                    email: 'teachshashi@tmt.com',
                    password: await bcrypt.hash('shashi12@tmt', 10),
                    name: 'Dr. Shashi Kant',
                    role: 'teacher',
                    profileImage: 'uploads/profiles/shashi.png',
                    bio: 'Experienced Mathematics teacher with 10+ years of teaching experience.',
                    phone: '+91-9876543210'
                },
                {
                    email: 'student1@math.com',
                    password: await bcrypt.hash('studentpass1', 10),
                    name: 'Sameer Kumar',
                    role: 'student',
                    profileImage: 'https://images.unsplash.com/photo-1539571696357-5a69c17a67c6?w=150&h=150&fit=crop&crop=face',
                    bio: 'Class 10 student preparing for board exams.',
                    phone: '+91-9876543211'
                },
                {
                    email: 'student2@math.com',
                    password: await bcrypt.hash('studentpass2', 10),
                    name: 'Priya Sharma',
                    role: 'student',
                    profileImage: 'https://images.unsplash.com/photo-1494790108755-2616b6b2ad0a?w=150&h=150&fit=crop&crop=face',
                    bio: 'Aspiring engineer, loves mathematics and science.',
                    phone: '+91-9876543212'
                }
            ];

            const createdUsers = await User.insertMany(defaultUsers);
            console.log('✅ Default users created');

            // Create sample fee records
            const students = createdUsers.filter(user => user.role === 'student');
            const currentYear = new Date().getFullYear();
            const months = ['January', 'February', 'March', 'April', 'May', 'June', 
                           'July', 'August', 'September', 'October', 'November', 'December'];

            const sampleFees = [];
            
            for (const student of students) {
                // Create fees for the last 6 months
                for (let i = 0; i < 6; i++) {
                    const monthIndex = (new Date().getMonth() - i + 12) % 12;
                    const year = monthIndex > new Date().getMonth() ? currentYear - 1 : currentYear;
                    
                    let status = 'paid';
                    let paymentDate = new Date(year, monthIndex + 1, Math.floor(Math.random() * 28) + 1);
                    
                    // Make some fees pending/overdue for demo
                    if (i === 0 && student.name === 'Sameer Kumar') {
                        status = 'pending';
                        paymentDate = null;
                    } else if (i === 1 && student.name === 'Priya Sharma') {
                        status = 'overdue';
                        paymentDate = null;
                    }

                    sampleFees.push({
                        studentId: student._id,
                        month: months[monthIndex],
                        year: year,
                        amount: 1500,
                        status: status,
                        paymentDate: paymentDate,
                        notes: status === 'paid' ? 'Paid online' : ''
                    });
                }
            }

            await Fee.insertMany(sampleFees);
            console.log('✅ Sample fee records created');
        }
    } catch (error) {
        console.error('❌ Error creating default data:', error);
    }
};

// Routes

// Authentication Routes
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign(
            { userId: user._id, email: user.email, role: user.role },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            token,
            user: {
                id: user._id,
                email: user.email,
                name: user.name,
                role: user.role,
                profileImage: user.profileImage,
                bio: user.bio,
                phone: user.phone,
                dateOfBirth: user.dateOfBirth
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/auth/register', async (req, res) => {
    try {
        const { email, password, name, role } = req.body;

        if (!email || !password || !name || !role) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ error: 'User already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({
            email,
            password: hashedPassword,
            name,
            role
        });

        await user.save();

        const token = jwt.sign(
            { userId: user._id, email: user.email, role: user.role },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.status(201).json({
            token,
            user: {
                id: user._id,
                email: user.email,
                name: user.name,
                role: user.role,
                profileImage: user.profileImage
            }
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// User Profile Routes
app.get('/api/user/profile', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId).select('-password');
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        res.json(user);
    } catch (error) {
        console.error('Get profile error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.put('/api/user/profile', authenticateToken, async (req, res) => {
    try {
        const { name, bio, phone, dateOfBirth } = req.body;
        const user = await User.findByIdAndUpdate(
            req.user.userId,
            { name, bio, phone, dateOfBirth, updatedAt: new Date() },
            { new: true }
        ).select('-password');

        res.json(user);
    } catch (error) {
        console.error('Update profile error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Profile Image Upload
app.post('/api/user/profile/image', authenticateToken, uploadProfile.single('profileImage'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No image file provided' });
        }

        const user = await User.findById(req.user.userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Delete old profile image if it exists and is a local file
        if (user.profileImage && user.profileImage.startsWith('uploads/')) {
            const oldImagePath = user.profileImage;
            if (fs.existsSync(oldImagePath)) {
                fs.unlinkSync(oldImagePath);
            }
        }

        // Update user with new profile image path
        const imagePath = req.file.path.replace(/\\/g, '/'); // Normalize path separators
        user.profileImage = imagePath;
        user.updatedAt = new Date();
        await user.save();

        res.json({
            message: 'Profile image updated successfully',
            profileImage: imagePath,
            user: {
                id: user._id,
                email: user.email,
                name: user.name,
                role: user.role,
                profileImage: user.profileImage,
                bio: user.bio,
                phone: user.phone,
                dateOfBirth: user.dateOfBirth
            }
        });
    } catch (error) {
        console.error('Upload profile image error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Teacher can update student profile image
app.post('/api/students/:id/profile/image', authenticateToken, requireTeacher, uploadProfile.single('profileImage'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No image file provided' });
        }

        const student = await User.findById(req.params.id);
        if (!student || student.role !== 'student') {
            return res.status(404).json({ error: 'Student not found' });
        }

        // Delete old profile image if it exists and is a local file
        if (student.profileImage && student.profileImage.startsWith('uploads/')) {
            const oldImagePath = student.profileImage;
            if (fs.existsSync(oldImagePath)) {
                fs.unlinkSync(oldImagePath);
            }
        }

        // Update student with new profile image path
        const imagePath = req.file.path.replace(/\\/g, '/');
        student.profileImage = imagePath;
        student.updatedAt = new Date();
        await student.save();

        res.json({
            message: 'Student profile image updated successfully',
            profileImage: imagePath,
            student: {
                id: student._id,
                email: student.email,
                name: student.name,
                role: student.role,
                profileImage: student.profileImage,
                bio: student.bio,
                phone: student.phone,
                dateOfBirth: student.dateOfBirth
            }
        });
    } catch (error) {
        console.error('Upload student profile image error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Teacher can update student profile
app.put('/api/students/:id/profile', authenticateToken, requireTeacher, async (req, res) => {
    try {
        const { name, email, bio, phone, dateOfBirth } = req.body;
        const student = await User.findById(req.params.id);

        if (!student || student.role !== 'student') {
            return res.status(404).json({ error: 'Student not found' });
        }

        // Check if email is being changed and if it already exists
        if (email && email !== student.email) {
            const existingUser = await User.findOne({ email, _id: { $ne: req.params.id } });
            if (existingUser) {
                return res.status(400).json({ error: 'Email already exists' });
            }
        }

        const updatedStudent = await User.findByIdAndUpdate(
            req.params.id,
            { name, email, bio, phone, dateOfBirth, updatedAt: new Date() },
            { new: true }
        ).select('-password');

        res.json({
            message: 'Student profile updated successfully',
            student: updatedStudent
        });
    } catch (error) {
        console.error('Update student profile error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Dashboard Routes
app.get('/api/dashboard/stats', authenticateToken, async (req, res) => {
    try {
        if (req.user.role === 'teacher') {
            const notesCount = await Resource.countDocuments({ type: 'note' });
            const questionsCount = await Resource.countDocuments({ type: 'question' });
            const booksCount = await Resource.countDocuments({ type: 'book' });
            const studentsCount = await User.countDocuments({ role: 'student' });
            const schedulesCount = await Schedule.countDocuments();

            res.json({
                notes: notesCount,
                questions: questionsCount,
                books: booksCount,
                students: studentsCount,
                schedules: schedulesCount
            });
        } else {
            const totalResources = await Resource.countDocuments();
            const upcomingSchedules = await Schedule.countDocuments({
                date: { $gte: new Date().toISOString().split('T')[0] }
            });

            res.json({
                totalResources,
                upcomingSchedules
            });
        }
    } catch (error) {
        console.error('Dashboard stats error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Resource Routes
app.get('/api/resources', authenticateToken, async (req, res) => {
    try {
        const { type, search } = req.query;
        let query = {};

        if (type) {
            query.type = type;
        }

        if (search) {
            query.$or = [
                { title: { $regex: search, $options: 'i' } },
                { description: { $regex: search, $options: 'i' } }
            ];
        }

        const resources = await Resource.find(query)
            .populate('uploadedBy', 'name email')
            .sort({ createdAt: -1 });

        res.json(resources);
    } catch (error) {
        console.error('Get resources error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get single resource
app.get('/api/resources/:id', authenticateToken, async (req, res) => {
    try {
        const resource = await Resource.findById(req.params.id)
            .populate('uploadedBy', 'name email');
        
        if (!resource) {
            return res.status(404).json({ error: 'Resource not found' });
        }

        res.json(resource);
    } catch (error) {
        console.error('Get resource error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/resources', authenticateToken, requireTeacher, uploadResource.single('file'), async (req, res) => {
    try {
        const { title, description, type } = req.body;

        if (!title || !type || !req.file) {
            return res.status(400).json({ error: 'Title, type, and file are required' });
        }

        const resource = new Resource({
            title,
            description,
            type,
            fileName: req.file.originalname,
            filePath: req.file.path,
            fileSize: req.file.size,
            uploadedBy: req.user.userId
        });

        await resource.save();
        await resource.populate('uploadedBy', 'name email');

        res.status(201).json(resource);
    } catch (error) {
        console.error('Create resource error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.delete('/api/resources/:id', authenticateToken, requireTeacher, async (req, res) => {
    try {
        const resource = await Resource.findById(req.params.id);
        if (!resource) {
            return res.status(404).json({ error: 'Resource not found' });
        }

        // Delete the actual file
        if (fs.existsSync(resource.filePath)) {
            fs.unlinkSync(resource.filePath);
        }

        await Resource.findByIdAndDelete(req.params.id);
        res.json({ message: 'Resource deleted successfully' });
    } catch (error) {
        console.error('Delete resource error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Fixed download resource endpoint
app.get('/api/resources/:id/download', authenticateToken, async (req, res) => {
    try {
        console.log('📥 Download request for resource:', req.params.id);
        
        const resource = await Resource.findById(req.params.id);
        if (!resource) {
            console.error('❌ Resource not found:', req.params.id);
            return res.status(404).json({ error: 'Resource not found' });
        }

        console.log('📁 Resource found:', {
            title: resource.title,
            fileName: resource.fileName,
            filePath: resource.filePath
        });

        // Check if file exists
        if (!fs.existsSync(resource.filePath)) {
            console.error('❌ File not found on disk:', resource.filePath);
            return res.status(404).json({ error: 'File not found on server' });
        }

        // Get file stats
        const stat = fs.statSync(resource.filePath);
        console.log('📊 File stats:', {
            size: stat.size,
            path: resource.filePath
        });

        // Set proper headers for download
        res.setHeader('Content-Type', 'application/octet-stream');
        res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(resource.fileName)}"`);
        res.setHeader('Content-Length', stat.size);
        res.setHeader('Cache-Control', 'no-cache');

        // Send file
        const fileStream = fs.createReadStream(resource.filePath);
        
        fileStream.on('error', (error) => {
            console.error('❌ File stream error:', error);
            if (!res.headersSent) {
                res.status(500).json({ error: 'Error reading file' });
            }
        });

        fileStream.on('end', () => {
            console.log('✅ File download completed:', resource.fileName);
        });

        fileStream.pipe(res);

    } catch (error) {
        console.error('❌ Download resource error:', error);
        if (!res.headersSent) {
            res.status(500).json({ error: 'Internal server error' });
        }
    }
});

// Schedule Routes
app.get('/api/schedules', authenticateToken, async (req, res) => {
    try {
        const schedules = await Schedule.find()
            .populate('createdBy', 'name email')
            .sort({ date: -1, time: -1 });

        res.json(schedules);
    } catch (error) {
        console.error('Get schedules error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/schedules', authenticateToken, requireTeacher, async (req, res) => {
    try {
        const { title, description, date, time, meetingLink, password } = req.body;

        if (!title || !date || !time) {
            return res.status(400).json({ error: 'Title, date, and time are required' });
        }

        const schedule = new Schedule({
            title,
            description,
            date,
            time,
            meetingLink,
            password,
            createdBy: req.user.userId
        });

        await schedule.save();
        await schedule.populate('createdBy', 'name email');

        res.status(201).json(schedule);
    } catch (error) {
        console.error('Create schedule error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.delete('/api/schedules/:id', authenticateToken, requireTeacher, async (req, res) => {
    try {
        await Schedule.findByIdAndDelete(req.params.id);
        res.json({ message: 'Schedule deleted successfully' });
    } catch (error) {
        console.error('Delete schedule error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Student Management Routes
app.get('/api/students', authenticateToken, requireTeacher, async (req, res) => {
    try {
        const students = await User.find({ role: 'student' }).select('-password');
        res.json(students);
    } catch (error) {
        console.error('Get students error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/students', authenticateToken, requireTeacher, async (req, res) => {
    try {
        const { email, password, name, bio, phone, dateOfBirth } = req.body;

        if (!email || !password || !name) {
            return res.status(400).json({ error: 'Email, password, and name are required' });
        }

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ error: 'User already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const student = new User({
            email,
            password: hashedPassword,
            name,
            role: 'student',
            bio,
            phone,
            dateOfBirth
        });

        await student.save();

        res.status(201).json({
            id: student._id,
            email: student.email,
            name: student.name,
            role: student.role,
            bio: student.bio,
            phone: student.phone,
            dateOfBirth: student.dateOfBirth,
            createdAt: student.createdAt
        });
    } catch (error) {
        console.error('Create student error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.delete('/api/students/:id', authenticateToken, requireTeacher, async (req, res) => {
    try {
        const student = await User.findById(req.params.id);

        // Delete profile image if it exists and is a local file
        if (student && student.profileImage && student.profileImage.startsWith('uploads/')) {
            if (fs.existsSync(student.profileImage)) {
                fs.unlinkSync(student.profileImage);
            }
        }

        // Delete all fee records for this student
        await Fee.deleteMany({ studentId: req.params.id });

        await User.findByIdAndDelete(req.params.id);
        res.json({ message: 'Student deleted successfully' });
    } catch (error) {
        console.error('Delete student error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Fee Management Routes

// Get all students with their fee status (Teacher only)
app.get('/api/fees', authenticateToken, requireTeacher, async (req, res) => {
    try {
        const students = await User.find({ role: 'student' }).select('-password');
        
        const studentsWithFees = await Promise.all(
            students.map(async (student) => {
                const fees = await Fee.find({ studentId: student._id })
                    .sort({ year: -1, createdAt: -1 });
                
                return {
                    ...student.toObject(),
                    fees: fees
                };
            })
        );

        res.json(studentsWithFees);
    } catch (error) {
        console.error('Get student fees error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get fee statistics (Teacher only)
app.get('/api/fees/stats', authenticateToken, requireTeacher, async (req, res) => {
    try {
        const totalStudents = await User.countDocuments({ role: 'student' });
        
        const feeStats = await Fee.aggregate([
            {
                $group: {
                    _id: '$status',
                    count: { $sum: 1 },
                    totalAmount: { $sum: '$amount' }
                }
            }
        ]);

        // Get unique students with different statuses
        const studentsWithPaidFees = await Fee.distinct('studentId', { status: 'paid' });
        const studentsWithPendingFees = await Fee.distinct('studentId', { status: 'pending' });
        const studentsWithOverdueFees = await Fee.distinct('studentId', { status: 'overdue' });

        const stats = {
            totalStudents,
            paidStudents: studentsWithPaidFees.length,
            pendingStudents: studentsWithPendingFees.length,
            overdueStudents: studentsWithOverdueFees.length,
            totalAmount: feeStats.reduce((sum, stat) => sum + stat.totalAmount, 0)
        };

        res.json(stats);
    } catch (error) {
        console.error('Get fee stats error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Update or create fee status (Teacher only)
app.post('/api/fees', authenticateToken, requireTeacher, async (req, res) => {
    try {
        const { studentId, month, year, amount, status, paymentDate, notes } = req.body;

        if (!studentId || !month || !year || !amount || !status) {
            return res.status(400).json({ error: 'Student ID, month, year, amount, and status are required' });
        }

        // Check if student exists
        const student = await User.findById(studentId);
        if (!student || student.role !== 'student') {
            return res.status(404).json({ error: 'Student not found' });
        }

        // Update or create fee record
        const feeData = {
            studentId,
            month,
            year: parseInt(year),
            amount: parseFloat(amount),
            status,
            paymentDate: status === 'paid' && paymentDate ? new Date(paymentDate) : null,
            notes: notes || '',
            updatedAt: new Date()
        };

        const fee = await Fee.findOneAndUpdate(
            { studentId, month, year: parseInt(year) },
            feeData,
            { new: true, upsert: true }
        );

        res.json({
            message: 'Fee status updated successfully',
            fee
        });
    } catch (error) {
        console.error('Update fee status error:', error);
        if (error.code === 11000) {
            res.status(400).json({ error: 'Fee record for this month already exists' });
        } else {
            res.status(500).json({ error: 'Internal server error' });
        }
    }
});

// Get student's own fee status (Student only)
app.get('/api/fees/status', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'student') {
            return res.status(403).json({ error: 'Student access only' });
        }

        const fees = await Fee.find({ studentId: req.user.userId })
            .sort({ year: -1, createdAt: -1 });

        res.json(fees);
    } catch (error) {
        console.error('Get student fee status error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Delete fee record (Teacher only)
app.delete('/api/fees/:id', authenticateToken, requireTeacher, async (req, res) => {
    try {
        await Fee.findByIdAndDelete(req.params.id);
        res.json({ message: 'Fee record deleted successfully' });
    } catch (error) {
        console.error('Delete fee error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('❌ Server Error:', err.stack);
    res.status(500).json({ error: 'Something went wrong!' });
});

// 404 handler
app.use('*', (req, res) => {
    res.status(404).json({ error: 'Route not found' });
});

// Start server
const startServer = async () => {
    try {
        await initializeDefaultData();
        app.listen(PORT, '0.0.0.0', () => {
            console.log(`🚀 Server running on port ${PORT}`);
            console.log(`🌐 Environment: ${process.env.NODE_ENV || 'development'}`);
            console.log(`📊 Health check: http://localhost:${PORT}/health`);
            console.log(`🎓 Educational Platform API Ready!`);
            console.log(`💰 Fee Management System Enabled!`);
        });
    } catch (error) {
        console.error('❌ Failed to start server:', error);
        process.exit(1);
    }
};

startServer();

module.exports = app;