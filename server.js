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

// CORS Configuration - FIXED to include your frontend domain
const corsOptions = {
    origin: [
        'https://tmtshashi.onrender.com',  // Your frontend domain
        'https://eduplatform-backend-k9fr.onrender.com', // Your backend domain
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

// Apply CORS middleware
app.use(cors(corsOptions));

// Handle preflight OPTIONS requests
app.options('*', cors(corsOptions));

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Create uploads directory if it doesn't exist - FIXED missing closing brace
if (!fs.existsSync('uploads')) {
    fs.mkdirSync('uploads');
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
            students: '/api/students/*'
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

// Keep service alive on Render (prevents cold starts)
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
    }, 14 * 60 * 1000); // Every 14 minutes
}

// User Schema
const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    name: { type: String, required: true },
    role: { type: String, enum: ['teacher', 'student'], required: true },
    profileImage: { type: String, default: '' },
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

// File Upload Configuration
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 50 * 1024 * 1024 }, // 50MB limit
    fileFilter: (req, file, cb) => {
        const allowedTypes = /jpeg|jpg|png|gif|pdf|doc|docx|txt|zip|rar/;
        const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = allowedTypes.test(file.mimetype);
        
        if (mimetype && extname) {
            return cb(null, true);
        } else {
            cb('Error: File type not supported');
        }
    }
});

// Initialize Default Users
const initializeDefaultUsers = async () => {
    try {
        const userCount = await User.countDocuments();
        if (userCount === 0) {
            const defaultUsers = [
                {
                    email: 'teacher@math.com',
                    password: await bcrypt.hash('teacherpass', 10),
                    name: 'Dr. Shashi Kant',
                    role: 'teacher',
                    profileImage: 'https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?w=150&h=150&fit=crop&crop=face'
                },
                {
                    email: 'student1@math.com',
                    password: await bcrypt.hash('studentpass1', 10),
                    name: 'Sameer Kumar',
                    role: 'student',
                    profileImage: 'https://images.unsplash.com/photo-1539571696357-5a69c17a67c6?w=150&h=150&fit=crop&crop=face'
                },
                {
                    email: 'student2@math.com',
                    password: await bcrypt.hash('studentpass2', 10),
                    name: 'Priya Sharma',
                    role: 'student',
                    profileImage: 'https://images.unsplash.com/photo-1494790108755-2616b6b2ad0a?w=150&h=150&fit=crop&crop=face'
                }
            ];

            await User.insertMany(defaultUsers);
            console.log('✅ Default users created');
        }
    } catch (error) {
        console.error('❌ Error creating default users:', error);
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
                profileImage: user.profileImage
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

// User Routes
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
        const { name, profileImage } = req.body;
        const user = await User.findByIdAndUpdate(
            req.user.userId,
            { name, profileImage, updatedAt: new Date() },
            { new: true }
        ).select('-password');
        
        res.json(user);
    } catch (error) {
        console.error('Update profile error:', error);
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

app.post('/api/resources', authenticateToken, requireTeacher, upload.single('file'), async (req, res) => {
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

        // Delete file from filesystem
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

app.get('/api/resources/:id/download', authenticateToken, async (req, res) => {
    try {
        const resource = await Resource.findById(req.params.id);
        if (!resource) {
            return res.status(404).json({ error: 'Resource not found' });
        }

        if (!fs.existsSync(resource.filePath)) {
            return res.status(404).json({ error: 'File not found' });
        }

        res.download(resource.filePath, resource.fileName);
    } catch (error) {
        console.error('Download resource error:', error);
        res.status(500).json({ error: 'Internal server error' });
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

// Student Management Routes (Teacher Only)
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
        const { email, password, name } = req.body;

        if (!email || !password || !name) {
            return res.status(400).json({ error: 'All fields are required' });
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
            role: 'student'
        });

        await student.save();
        res.status(201).json({
            id: student._id,
            email: student.email,
            name: student.name,
            role: student.role,
            createdAt: student.createdAt
        });
    } catch (error) {
        console.error('Create student error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.delete('/api/students/:id', authenticateToken, requireTeacher, async (req, res) => {
    try {
        await User.findByIdAndDelete(req.params.id);
        res.json({ message: 'Student deleted successfully' });
    } catch (error) {
        console.error('Delete student error:', error);
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
        await initializeDefaultUsers();
        app.listen(PORT, '0.0.0.0', () => {
            console.log(`🚀 Server running on port ${PORT}`);
            console.log(`🌐 Environment: ${process.env.NODE_ENV || 'development'}`);
            console.log(`📊 Health check: http://localhost:${PORT}/health`);
            console.log(`🎓 Educational Platform API Ready!`);
        });
    } catch (error) {
        console.error('❌ Failed to start server:', error);
        process.exit(1);
    }
};

startServer();

module.exports = app;