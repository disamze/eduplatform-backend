// Educational Platform Backend API - Complete API-Only Version
// Fixed version without HTML serving to prevent ENOENT errors

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

// Serve static files for uploads only
app.use('/uploads', express.static('uploads'));

// Health check endpoint for monitoring
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    service: 'Educational Platform API',
    version: '1.0.0'
  });
});

// Root endpoint - API info only (no HTML serving)
app.get('/', (req, res) => {
  res.json({
    message: 'Educational Platform Backend API',
    version: '1.0.0',
    status: 'Running',
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
    },
    documentation: 'This is a backend API service. Connect your frontend to these endpoints.',
    note: 'All API endpoints require proper authentication tokens'
  });
});

// MongoDB Connection with fixed options
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/eduplatform';

mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  maxPoolSize: 10,
  serverSelectionTimeoutMS: 5000,
  socketTimeoutMS: 45000,
  bufferCommands: false
})
.then(() => {
  console.log('✅ Connected to MongoDB');
})
.catch((error) => {
  console.error('❌ MongoDB connection error:', error);
  process.exit(1);
});

// Database Schemas
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

feeSchema.index({ studentId: 1, month: 1, year: 1 }, { unique: true });
const Fee = mongoose.model('Fee', feeSchema);

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

const announcementSchema = new mongoose.Schema({
  title: { type: String, required: true },
  content: { type: String, required: true },
  priority: { type: String, enum: ['low', 'normal', 'high'], default: 'normal' },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  readBy: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  createdAt: { type: Date, default: Date.now },
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

const requireTeacher = (req, res, next) => {
  if (req.user.role !== 'teacher') {
    return res.status(403).json({ error: 'Teacher access required' });
  }
  next();
};

// File Upload Configuration
const resourceStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});

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
  limits: { fileSize: 5 * 1024 * 1024 },
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

// Initialize Default Data
const initializeDefaultData = async () => {
  try {
    const userCount = await User.countDocuments();
    if (userCount === 0) {
      console.log('🔄 Initializing default data...');
      
      const defaultUsers = [
        {
          email: 'teachshashi@tmt.com',
          password: await bcrypt.hash('shashi12@tmt', 10),
          name: 'Dr. Shashi Kant',
          role: 'teacher',
          bio: 'Experienced Mathematics teacher with 10+ years of teaching experience.',
          phone: '+91-9876543210'
        },
        {
          email: 'student1@math.com',
          password: await bcrypt.hash('studentpass1', 10),
          name: 'Sameer Kumar',
          role: 'student',
          bio: 'Class 10 student preparing for board exams.',
          phone: '+91-9876543211'
        },
        {
          email: 'student2@math.com',
          password: await bcrypt.hash('studentpass2', 10),
          name: 'Priya Sharma',
          role: 'student',
          bio: 'Aspiring engineer, loves mathematics and science.',
          phone: '+91-9876543212'
        }
      ];

      const createdUsers = await User.insertMany(defaultUsers);
      console.log('✅ Default users created');

      const teacher = createdUsers.find(user => user.role === 'teacher');
      const students = createdUsers.filter(user => user.role === 'student');

      // Create sample announcements
      const sampleAnnouncements = [
        {
          title: 'Welcome to Educational Platform!',
          content: 'Welcome to our educational platform. This is a demo announcement.',
          priority: 'high',
          createdBy: teacher._id
        }
      ];

      await Announcement.insertMany(sampleAnnouncements);
      console.log('✅ Sample data initialized');
    }
  } catch (error) {
    console.error('❌ Error initializing default data:', error);
  }
};

// API Routes
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
        phone: user.phone
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
        role: user.role
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

// Dashboard Routes
app.get('/api/dashboard/stats', authenticateToken, async (req, res) => {
  try {
    if (req.user.role === 'teacher') {
      const studentsCount = await User.countDocuments({ role: 'student' });
      const resourcesCount = await Resource.countDocuments();
      const announcementsCount = await Announcement.countDocuments();
      
      res.json({
        students: studentsCount,
        resources: resourcesCount,
        announcements: announcementsCount
      });
    } else {
      const totalResources = await Resource.countDocuments();
      const totalAnnouncements = await Announcement.countDocuments();
      
      res.json({
        totalResources,
        totalAnnouncements
      });
    }
  } catch (error) {
    console.error('Dashboard stats error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Students Management Routes
app.get('/api/students', authenticateToken, requireTeacher, async (req, res) => {
  try {
    const students = await User.find({ role: 'student' }).select('-password');
    res.json(students);
  } catch (error) {
    console.error('Get students error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Announcements Routes
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
      createdBy: req.user.userId
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

// 404 handler for API routes
app.use('/api/*', (req, res) => {
  res.status(404).json({ error: 'API route not found' });
});

// Catch-all handler for non-API routes - return JSON instead of trying to serve HTML
app.use('*', (req, res) => {
  res.status(404).json({ 
    error: 'Route not found',
    message: 'This is an API-only service. Please use /api/* endpoints.',
    available_endpoints: ['/health', '/api/auth/login', '/api/auth/register']
  });
});

// Start server
const startServer = async () => {
  try {
    await initializeDefaultData();
    
    const server = app.listen(PORT, '0.0.0.0', () => {
      console.log(`🚀 Educational Platform API running on port ${PORT}`);
      console.log(`📊 Health check: http://localhost:${PORT}/health`);
      console.log(`🔑 Login endpoint: http://localhost:${PORT}/api/auth/login`);
      console.log(`✅ API-only backend ready!`);
    });

    // Graceful shutdown
    process.on('SIGTERM', () => {
      console.log('💤 SIGTERM received: closing server');
      server.close(() => {
        console.log('🔌 Server closed');
        mongoose.connection.close(false, () => {
          console.log('🗄️ MongoDB connection closed');
          process.exit(0);
        });
      });
    });

  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
};

startServer();

module.exports = app;