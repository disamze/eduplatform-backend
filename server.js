


// Complete server.js with Fee Management System, Results/Leaderboard, and Announcements/Notice Board

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

// FIXED: Serve static files with proper MIME types
app.use('/uploads', express.static('uploads'));

// Serve static files (HTML, CSS, JS) with proper MIME types
app.use(express.static('.', {
    setHeaders: (res, path) => {
        if (path.endsWith('.js')) {
            res.setHeader('Content-Type', 'application/javascript');
        } else if (path.endsWith('.css')) {
            res.setHeader('Content-Type', 'text/css');
        } else if (path.endsWith('.html')) {
            res.setHeader('Content-Type', 'text/html');
        }
    }
}));

// Health check endpoint for Render
app.get('/health', (req, res) => {
    res.status(200).json({
        status: 'OK',
        timestamp: new Date().toISOString(),
        service: 'Educational Platform API',
        version: '1.0.0'
    });
});

// Root endpoint - serve index.html for the main app
app.get('/', (req, res) => {
    // Check if it's an API request
    if (req.headers.accept && req.headers.accept.includes('application/json')) {
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
                fees: '/api/fees/*',
                results: '/api/results/*',
                announcements: '/api/announcements/*'
            }
        });
    } else {
        // Serve the HTML file
        res.sendFile(path.join(__dirname, 'index.html'));
    }
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

// Database Schemas

// User Schema
// User Schema with indexes
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, index: true },
  password: { type: String, required: true },
  name: { type: String, required: true, index: true },
  role: { type: String, enum: ['teacher', 'student'], required: true, index: true },
  profileImage: { type: String, default: '' },
  bio: { type: String, default: '' },
  phone: { type: String, default: '' },
  dateOfBirth: { type: String, default: '' },
  createdAt: { type: Date, default: Date.now, index: true },
  updatedAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// Resource Schema
const resourceSchema = new mongoose.Schema({
  title: { type: String, required: true, index: true },
  description: { type: String, default: '' },
  type: { type: String, enum: ['note', 'question', 'book'], required: true, index: true },
  fileName: { type: String, required: true },
  filePath: { type: String, required: true },
  fileSize: { type: Number, required: true },
  uploadedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  createdAt: { type: Date, default: Date.now, index: true },
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

// Result Schema
const resultSchema = new mongoose.Schema({
    studentId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    examName: { type: String, required: true },
    subject: { type: String, required: true },
    class: { type: String, required: true },
    examDate: { type: Date, required: true },
    totalMarks: { type: Number, required: true },
    marksObtained: { type: Number, required: true },
    percentage: { type: Number, required: true },
    grade: { type: String, required: true },
    remarks: { type: String, default: '' },
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

const Result = mongoose.model('Result', resultSchema);

// NEW: Announcement Schema
const announcementSchema = new mongoose.Schema({
  title: { type: String, required: true, index: true },
  content: { type: String, required: true },
  priority: { type: String, enum: ['low', 'normal', 'high'], default: 'normal', index: true },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  readBy: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  createdAt: { type: Date, default: Date.now, index: true },
  updatedAt: { type: Date, default: Date.now }
});


const Announcement = mongoose.model('Announcement', announcementSchema);

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

// Helper function to calculate grade
function calculateGrade(percentage) {
    if (percentage >= 90) return 'A+';
    if (percentage >= 80) return 'A';
    if (percentage >= 70) return 'B+';
    if (percentage >= 60) return 'B';
    if (percentage >= 50) return 'C+';
    if (percentage >= 40) return 'C';
    if (percentage >= 33) return 'D';
    return 'F';
}

// Initialize Default Users, Sample Data, and Announcements
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
                },
                {
                    email: 'student3@math.com',
                    password: await bcrypt.hash('studentpass3', 10),
                    name: 'Arjun Patel',
                    role: 'student',
                    profileImage: 'https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?w=150&h=150&fit=crop&crop=face',
                    bio: 'Mathematics enthusiast and problem solver.',
                    phone: '+91-9876543213'
                }
            ];

            const createdUsers = await User.insertMany(defaultUsers);
            console.log('✅ Default users created');

            // Get teacher and students
            const teacher = createdUsers.find(user => user.role === 'teacher');
            const students = createdUsers.filter(user => user.role === 'student');

            // Create sample fee records
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

            // Create sample results
            const sampleResults = [];
            const subjects = ['Mathematics', 'Physics', 'Chemistry'];
            const classes = ['Class 9', 'Class 10', 'Class 11'];
            const examNames = ['Monthly Test', 'Mid Term', 'Final Exam'];

            for (const student of students) {
                for (let i = 0; i < 3; i++) {
                    const totalMarks = 100;
                    const marksObtained = Math.floor(Math.random() * 40) + 60; // 60-100 marks
                    const percentage = (marksObtained / totalMarks) * 100;
                    const grade = calculateGrade(percentage);

                    sampleResults.push({
                        studentId: student._id,
                        examName: examNames[i],
                        subject: subjects[Math.floor(Math.random() * subjects.length)],
                        class: classes[Math.floor(Math.random() * classes.length)],
                        examDate: new Date(2024, Math.floor(Math.random() * 12), Math.floor(Math.random() * 28) + 1),
                        totalMarks: totalMarks,
                        marksObtained: marksObtained,
                        percentage: Math.round(percentage * 100) / 100,
                        grade: grade,
                        remarks: percentage >= 80 ? 'Excellent performance' : percentage >= 60 ? 'Good work' : 'Needs improvement',
                        createdBy: teacher._id
                    });
                }
            }

            await Result.insertMany(sampleResults);
            console.log('✅ Sample result records created');

            // Create sample announcements
            const sampleAnnouncements = [
                {
                    title: 'Welcome to New Academic Year 2025!',
                    content: 'Dear students, welcome to the new academic year! We are excited to begin this journey with you. Please make sure to check your schedules and prepare for the upcoming classes. Best of luck!',
                    priority: 'high',
                    createdBy: teacher._id,
                    readBy: []
                },
                {
                    title: 'Mathematics Olympiad Registration Open',
                    content: 'Students interested in participating in the Mathematics Olympiad can now register. The registration deadline is next month. This is a great opportunity to showcase your mathematical skills!',
                    priority: 'normal',
                    createdBy: teacher._id,
                    readBy: [students[0]._id] // Sameer has read it
                },
                {
                    title: 'Holiday Notice - Republic Day',
                    content: 'Please note that classes will remain closed on 26th January 2025 in observance of Republic Day. Regular classes will resume from 27th January. Happy Republic Day in advance!',
                    priority: 'low',
                    createdBy: teacher._id,
                    readBy: [students[1]._id, students[2]._id] // Priya and Arjun have read it
                }
            ];

            await Announcement.insertMany(sampleAnnouncements);
            console.log('✅ Sample announcement records created');
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

// FIXED download resource endpoint
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

        // Delete all related records for this student
        await Fee.deleteMany({ studentId: req.params.id });
        await Result.deleteMany({ studentId: req.params.id });
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

// Results Management Routes
app.get('/api/results', authenticateToken, async (req, res) => {
    try {
        let results;

        if (req.user.role === 'teacher') {
            results = await Result.find()
                .populate('studentId', 'name email')
                .populate('createdBy', 'name')
                .sort({ examDate: -1 });
        } else {
            results = await Result.find({ studentId: req.user.userId })
                .populate('createdBy', 'name')
                .sort({ examDate: -1 });
        }

        res.json(results);
    } catch (error) {
        console.error('Get results error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/results', authenticateToken, requireTeacher, async (req, res) => {
    try {
        const { studentId, examName, subject, class: className, examDate, totalMarks, marksObtained, remarks } = req.body;

        if (!studentId || !examName || !subject || !className || !examDate || !totalMarks || marksObtained === undefined) {
            return res.status(400).json({ error: 'All required fields must be provided' });
        }

        // Check if student exists
        const student = await User.findById(studentId);
        if (!student || student.role !== 'student') {
            return res.status(404).json({ error: 'Student not found' });
        }

        const percentage = (marksObtained / totalMarks) * 100;
        const grade = calculateGrade(percentage);

        const result = new Result({
            studentId,
            examName,
            subject,
            class: className,
            examDate: new Date(examDate),
            totalMarks: parseInt(totalMarks),
            marksObtained: parseInt(marksObtained),
            percentage: Math.round(percentage * 100) / 100,
            grade,
            remarks: remarks || '',
            createdBy: req.user.userId
        });

        await result.save();
        await result.populate('studentId', 'name email');
        await result.populate('createdBy', 'name');

        res.status(201).json(result);
    } catch (error) {
        console.error('Create result error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.put('/api/results/:id', authenticateToken, requireTeacher, async (req, res) => {
    try {
        const { examName, subject, class: className, examDate, totalMarks, marksObtained, remarks } = req.body;

        const result = await Result.findById(req.params.id);
        if (!result) {
            return res.status(404).json({ error: 'Result not found' });
        }

        const percentage = (marksObtained / totalMarks) * 100;
        const grade = calculateGrade(percentage);

        const updatedResult = await Result.findByIdAndUpdate(
            req.params.id,
            {
                examName,
                subject,
                class: className,
                examDate: new Date(examDate),
                totalMarks: parseInt(totalMarks),
                marksObtained: parseInt(marksObtained),
                percentage: Math.round(percentage * 100) / 100,
                grade,
                remarks: remarks || '',
                updatedAt: new Date()
            },
            { new: true }
        ).populate('studentId', 'name email').populate('createdBy', 'name');

        res.json(updatedResult);
    } catch (error) {
        console.error('Update result error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.delete('/api/results/:id', authenticateToken, requireTeacher, async (req, res) => {
    try {
        await Result.findByIdAndDelete(req.params.id);
        res.json({ message: 'Result deleted successfully' });
    } catch (error) {
        console.error('Delete result error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/api/results/leaderboard', authenticateToken, async (req, res) => {
    try {
        const leaderboard = await Result.aggregate([
            {
                $group: {
                    _id: '$studentId',
                    averagePercentage: { $avg: '$percentage' },
                    totalExams: { $sum: 1 },
                    highestScore: { $max: '$percentage' },
                    lastExamDate: { $max: '$examDate' }
                }
            },
            {
                $lookup: {
                    from: 'users',
                    localField: '_id',
                    foreignField: '_id',
                    as: 'student'
                }
            },
            {
                $unwind: '$student'
            },
            {
                $project: {
                    _id: 1,
                    averagePercentage: { $round: ['$averagePercentage', 2] },
                    totalExams: 1,
                    highestScore: { $round: ['$highestScore', 2] },
                    lastExamDate: 1,
                    name: '$student.name',
                    email: '$student.email',
                    profileImage: '$student.profileImage'
                }
            },
            {
                $sort: { averagePercentage: -1 }
            },
            {
                $limit: 50
            }
        ]);

        // Add rank to each student
        const rankedLeaderboard = leaderboard.map((student, index) => ({
            ...student,
            rank: index + 1
        }));

        res.json(rankedLeaderboard);
    } catch (error) {
        console.error('Get leaderboard error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// NEW: Announcement Routes
app.get('/api/announcements', authenticateToken, async (req, res) => {
    try {
        const announcements = await Announcement.find()
            .populate('createdBy', 'name email')
            .sort({ createdAt: -1 });

        res.json(announcements);
    } catch (error) {
        console.error('Get announcements error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/announcements', authenticateToken, requireTeacher, async (req, res) => {
    try {
        const { title, content, priority } = req.body;

        if (!title || !content) {
            return res.status(400).json({ error: 'Title and content are required' });
        }

        const announcement = new Announcement({
            title,
            content,
            priority: priority || 'normal',
            createdBy: req.user.userId,
            readBy: []
        });

        await announcement.save();
        await announcement.populate('createdBy', 'name email');

        res.status(201).json(announcement);
    } catch (error) {
        console.error('Create announcement error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.put('/api/announcements/:id', authenticateToken, requireTeacher, async (req, res) => {
    try {
        const { title, content, priority } = req.body;

        const announcement = await Announcement.findById(req.params.id);
        if (!announcement) {
            return res.status(404).json({ error: 'Announcement not found' });
        }

        const updatedAnnouncement = await Announcement.findByIdAndUpdate(
            req.params.id,
            {
                title,
                content,
                priority: priority || 'normal',
                updatedAt: new Date()
            },
            { new: true }
        ).populate('createdBy', 'name email');

        res.json(updatedAnnouncement);
    } catch (error) {
        console.error('Update announcement error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.delete('/api/announcements/:id', authenticateToken, requireTeacher, async (req, res) => {
    try {
        const announcement = await Announcement.findById(req.params.id);
        if (!announcement) {
            return res.status(404).json({ error: 'Announcement not found' });
        }

        await Announcement.findByIdAndDelete(req.params.id);
        res.json({ message: 'Announcement deleted successfully' });
    } catch (error) {
        console.error('Delete announcement error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// NEW: Mark announcement as read (Student only)
app.post('/api/announcements/:id/read', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'student') {
            return res.status(403).json({ error: 'Student access only' });
        }

        const announcement = await Announcement.findById(req.params.id);
        if (!announcement) {
            return res.status(404).json({ error: 'Announcement not found' });
        }

        // Add student to readBy array if not already present
        if (!announcement.readBy.includes(req.user.userId)) {
            announcement.readBy.push(req.user.userId);
            await announcement.save();
        }

        res.json({ message: 'Announcement marked as read' });
    } catch (error) {
        console.error('Mark announcement as read error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// NEW: Get unread announcements count (Student only)
app.get('/api/announcements/unread/count', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'student') {
            return res.json({ count: 0 });
        }

        const count = await Announcement.countDocuments({
            readBy: { $ne: req.user.userId }
        });

        res.json({ count });
    } catch (error) {
        console.error('Get unread announcements count error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('❌ Server Error:', err.stack);
    res.status(500).json({ error: 'Something went wrong!' });
});

// 404 handler for API routes only
app.use('/api/*', (req, res) => {
    res.status(404).json({ error: 'API route not found' });
});

// Catch-all handler - serve index.html for any other route (SPA routing)
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
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
            console.log(`🏆 Results & Leaderboard System Enabled!`);
            console.log(`📢 Announcements & Notice Board System Enabled!`);
        });
    } catch (error) {
        console.error('❌ Failed to start server:', error);
        process.exit(1);
    }
};
// Optimized server.js with performance improvements

require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');


// CORS Configuration


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

// FIXED: Serve static files with proper MIME types
app.use('/uploads', express.static('uploads'));
app.use(express.static('.', {
  setHeaders: (res, path) => {
    if (path.endsWith('.js')) {
      res.setHeader('Content-Type', 'application/javascript');
    } else if (path.endsWith('.css')) {
      res.setHeader('Content-Type', 'text/css');
    } else if (path.endsWith('.html')) {
      res.setHeader('Content-Type', 'text/html');
    }
  }
}));

// Health check endpoint for Render
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    service: 'Educational Platform API',
    version: '1.0.0'
  });
});

// Root endpoint - serve index.html for the main app
app.get('/', (req, res) => {
  if (req.headers.accept && req.headers.accept.includes('application/json')) {
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
        fees: '/api/fees/*',
        results: '/api/results/*',
        announcements: '/api/announcements/*'
      }
    });
  } else {
    res.sendFile(path.join(__dirname, 'index.html'));
  }
});

// MongoDB Connection with optimized settings

mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  maxPoolSize: 10, // Maintain up to 10 socket connections
  serverSelectionTimeoutMS: 5000, // Keep trying to send operations for 5 seconds
  socketTimeoutMS: 45000, // Close sockets after 45 seconds of inactivity
  family: 4, // Use IPv4, skip trying IPv6
  bufferMaxEntries: 0, // Disable mongoose buffering
  bufferCommands: false, // Disable mongoose buffering
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

// OPTIMIZED Database Schemas with proper indexing

// User Schema with indexes


// Create compound indexes for better performance
userSchema.index({ role: 1, createdAt: -1 });

// Resource Schema with indexes


// Compound indexes for resources
resourceSchema.index({ type: 1, createdAt: -1 });
resourceSchema.index({ uploadedBy: 1, type: 1 });

// Schedule Schema with indexes

scheduleSchema.index({ date: 1, time: 1 });

// Fee Schema with optimized indexes


// Optimized compound indexes
feeSchema.index({ studentId: 1, month: 1, year: 1 }, { unique: true });
feeSchema.index({ studentId: 1, status: 1 });
feeSchema.index({ status: 1, year: -1 });

// Result Schema with indexes


// Compound indexes for results
resultSchema.index({ studentId: 1, examDate: -1 });
resultSchema.index({ studentId: 1, percentage: -1 });

// Announcement Schema with indexes


announcementSchema.index({ priority: 1, createdAt: -1 });

// PERFORMANCE: Add caching layer
const cache = new Map();
const CACHE_DURATION = 5 * 60 * 1000; // 5 minutes

function getCachedData(key) {
  const cached = cache.get(key);
  if (cached && Date.now() - cached.timestamp < CACHE_DURATION) {
    return cached.data;
  }
  return null;
}

function setCachedData(key, data) {
  cache.set(key, {
    data,
    timestamp: Date.now()
  });
}

// Clear old cache entries periodically
setInterval(() => {
  const now = Date.now();
  for (const [key, value] of cache.entries()) {
    if (now - value.timestamp > CACHE_DURATION) {
      cache.delete(key);
    }
  }
}, CACHE_DURATION);

// Authentication Middleware


// Teacher Role Middleware




// Helper function to calculate grade
function calculateGrade(percentage) {
  if (percentage >= 90) return 'A+';
  if (percentage >= 80) return 'A';
  if (percentage >= 70) return 'B+';
  if (percentage >= 60) return 'B';
  if (percentage >= 50) return 'C+';
  if (percentage >= 40) return 'C';
  if (percentage >= 33) return 'D';
  return 'F';
}

// OPTIMIZED: Initialize Default Users only if needed

// Routes

// Authentication Routes
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const user = await User.findOne({ email }).select('+password');
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
    
    // Clear cache
    cache.delete(`user_${req.user.userId}`);
    
    res.json(user);
  } catch (error) {
    console.error('Update profile error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// OPTIMIZED Dashboard Routes with caching
app.get('/api/dashboard/stats', authenticateToken, async (req, res) => {
  try {
    const cacheKey = `dashboard_stats_${req.user.role}`;
    let cachedStats = getCachedData(cacheKey);
    
    if (cachedStats) {
      return res.json(cachedStats);
    }

    if (req.user.role === 'teacher') {
      // Use parallel queries for better performance
      const [notesCount, questionsCount, booksCount, studentsCount, schedulesCount] = await Promise.all([
        Resource.countDocuments({ type: 'note' }),
        Resource.countDocuments({ type: 'question' }),
        Resource.countDocuments({ type: 'book' }),
        User.countDocuments({ role: 'student' }),
        Schedule.countDocuments()
      ]);

      const stats = {
        notes: notesCount,
        questions: questionsCount,
        books: booksCount,
        students: studentsCount,
        schedules: schedulesCount
      };

      setCachedData(cacheKey, stats);
      res.json(stats);
    } else {
      const [totalResources, upcomingSchedules] = await Promise.all([
        Resource.countDocuments(),
        Schedule.countDocuments({
          date: { $gte: new Date().toISOString().split('T')[0] }
        })
      ]);

      const stats = {
        totalResources,
        upcomingSchedules
      };

      setCachedData(cacheKey, stats);
      res.json(stats);
    }
  } catch (error) {
    console.error('Dashboard stats error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// OPTIMIZED Resource Routes
app.get('/api/resources', authenticateToken, async (req, res) => {
  try {
    const { type, search, limit = 20, page = 1 } = req.query;
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

    const skip = (page - 1) * limit;
    
    const resources = await Resource.find(query)
      .populate('uploadedBy', 'name email')
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .skip(skip)
      .lean(); // Use lean() for better performance

    res.json(resources);
  } catch (error) {
    console.error('Get resources error:', error);
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
    
    // Clear related cache
    cache.delete('dashboard_stats_teacher');
    
    res.status(201).json(resource);
  } catch (error) {
    console.error('Create resource error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// OPTIMIZED Schedule Routes
app.get('/api/schedules', authenticateToken, async (req, res) => {
  try {
    const { limit = 10 } = req.query;
    
    const schedules = await Schedule.find()
      .populate('createdBy', 'name email')
      .sort({ date: -1, time: -1 })
      .limit(parseInt(limit))
      .lean();
      
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
    
    // Clear related cache
    cache.delete('dashboard_stats_teacher');
    
    res.status(201).json(schedule);
  } catch (error) {
    console.error('Create schedule error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// OPTIMIZED Student Management Routes
app.get('/api/students', authenticateToken, requireTeacher, async (req, res) => {
  try {
    const { limit = 50 } = req.query;
    
    const students = await User.find({ role: 'student' })
      .select('-password')
      .limit(parseInt(limit))
      .lean();
      
    res.json(students);
  } catch (error) {
    console.error('Get students error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// OPTIMIZED Fee Management Routes
app.get('/api/fees', authenticateToken, requireTeacher, async (req, res) => {
  try {
    const cacheKey = 'fees_with_students';
    let cachedData = getCachedData(cacheKey);
    
    if (cachedData) {
      return res.json(cachedData);
    }

    const students = await User.find({ role: 'student' })
      .select('-password')
      .limit(50)
      .lean();
      
    const studentIds = students.map(s => s._id);
    const fees = await Fee.find({ studentId: { $in: studentIds } })
      .sort({ year: -1, createdAt: -1 })
      .lean();

    // Group fees by student
    const feesByStudent = fees.reduce((acc, fee) => {
      const studentId = fee.studentId.toString();
      if (!acc[studentId]) acc[studentId] = [];
      acc[studentId].push(fee);
      return acc;
    }, {});

    const studentsWithFees = students.map(student => ({
      ...student,
      fees: feesByStudent[student._id.toString()] || []
    }));

    setCachedData(cacheKey, studentsWithFees);
    res.json(studentsWithFees);
  } catch (error) {
    console.error('Get student fees error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// OPTIMIZED Results Routes
app.get('/api/results', authenticateToken, async (req, res) => {
  try {
    const { limit = 20, page = 1 } = req.query;
    const skip = (page - 1) * limit;
    
    let results;
    if (req.user.role === 'teacher') {
      results = await Result.find()
        .populate('studentId', 'name email')
        .populate('createdBy', 'name')
        .sort({ examDate: -1 })
        .limit(parseInt(limit))
        .skip(skip)
        .lean();
    } else {
      results = await Result.find({ studentId: req.user.userId })
        .populate('createdBy', 'name')
        .sort({ examDate: -1 })
        .limit(parseInt(limit))
        .skip(skip)
        .lean();
    }

    res.json(results);
  } catch (error) {
    console.error('Get results error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// OPTIMIZED Leaderboard with better aggregation
app.get('/api/results/leaderboard', authenticateToken, async (req, res) => {
  try {
    const cacheKey = 'leaderboard_top_20';
    let cachedLeaderboard = getCachedData(cacheKey);
    
    if (cachedLeaderboard) {
      return res.json(cachedLeaderboard);
    }

    const leaderboard = await Result.aggregate([
      {
        $group: {
          _id: '$studentId',
          averagePercentage: { $avg: '$percentage' },
          totalExams: { $sum: 1 },
          highestScore: { $max: '$percentage' },
          lastExamDate: { $max: '$examDate' }
        }
      },
      {
        $lookup: {
          from: 'users',
          localField: '_id',
          foreignField: '_id',
          as: 'student',
          pipeline: [
            { $project: { name: 1, email: 1, profileImage: 1 } }
          ]
        }
      },
      {
        $unwind: '$student'
      },
      {
        $project: {
          _id: 1,
          averagePercentage: { $round: ['$averagePercentage', 2] },
          totalExams: 1,
          highestScore: { $round: ['$highestScore', 2] },
          lastExamDate: 1,
          name: '$student.name',
          email: '$student.email',
          profileImage: '$student.profileImage'
        }
      },
      {
        $sort: { averagePercentage: -1 }
      },
      {
        $limit: 20
      }
    ]);

    const rankedLeaderboard = leaderboard.map((student, index) => ({
      ...student,
      rank: index + 1
    }));

    setCachedData(cacheKey, rankedLeaderboard);
    res.json(rankedLeaderboard);
  } catch (error) {
    console.error('Get leaderboard error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// OPTIMIZED Announcements Routes
app.get('/api/announcements', authenticateToken, async (req, res) => {
  try {
    const { limit = 10 } = req.query;
    
    const announcements = await Announcement.find()
      .populate('createdBy', 'name email')
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .lean();
      
    res.json(announcements);
  } catch (error) {
    console.error('Get announcements error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/announcements', authenticateToken, requireTeacher, async (req, res) => {
  try {
    const { title, content, priority } = req.body;

    if (!title || !content) {
      return res.status(400).json({ error: 'Title and content are required' });
    }

    const announcement = new Announcement({
      title,
      content,
      priority: priority || 'normal',
      createdBy: req.user.userId,
      readBy: []
    });

    await announcement.save();
    await announcement.populate('createdBy', 'name email');
    
    res.status(201).json(announcement);
  } catch (error) {
    console.error('Create announcement error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('❌ Server Error:', err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// 404 handler for API routes only
app.use('/api/*', (req, res) => {
  res.status(404).json({ error: 'API route not found' });
});

// Catch-all handler
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Start server


startServer();
module.exports = app;
