// Educational Platform Backend API - Fixed MongoDB Connection Timing
// Resolves the bufferCommands connection timing issue

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
    version: '1.0.0',
    database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
  });
});

// Root endpoint - API info only (no HTML serving)
app.get('/', (req, res) => {
  res.json({
    message: 'Educational Platform Backend API',
    version: '1.0.0',
    status: 'Running',
    database: mongoose.connection.readyState === 1 ? 'connected' : 'connecting',
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

// Initialize Default Data - FIXED to wait for connection
const initializeDefaultData = async () => {
  try {
    console.log('🔄 Checking for existing users...');
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
        },
        {
          email: 'student3@math.com',
          password: await bcrypt.hash('studentpass3', 10),
          name: 'Arjun Patel',
          role: 'student',
          bio: 'Mathematics enthusiast and problem solver.',
          phone: '+91-9876543213'
        }
      ];

      const createdUsers = await User.insertMany(defaultUsers);
      console.log('✅ Default users created');

      const teacher = createdUsers.find(user => user.role === 'teacher');
      const students = createdUsers.filter(user => user.role === 'student');

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
          readBy: [students[0]._id]
        }
      ];

      await Announcement.insertMany(sampleAnnouncements);
      console.log('✅ Sample announcements created');

      // Create sample fee records
      const currentYear = new Date().getFullYear();
      const months = ['January', 'February', 'March', 'April', 'May', 'June',
        'July', 'August', 'September', 'October', 'November', 'December'];
      
      const sampleFees = [];
      for (const student of students) {
        for (let i = 0; i < 3; i++) {
          const monthIndex = (new Date().getMonth() - i + 12) % 12;
          const year = monthIndex > new Date().getMonth() ? currentYear - 1 : currentYear;
          
          let status = 'paid';
          let paymentDate = new Date(year, monthIndex + 1, Math.floor(Math.random() * 28) + 1);
          
          if (i === 0 && student.name === 'Sameer Kumar') {
            status = 'pending';
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
        for (let i = 0; i < 2; i++) {
          const totalMarks = 100;
          const marksObtained = Math.floor(Math.random() * 40) + 60;
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
      console.log('🎉 All sample data initialized successfully!');
    } else {
      console.log('✅ Existing users found, skipping default data initialization');
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

// Dashboard Routes
app.get('/api/dashboard/stats', authenticateToken, async (req, res) => {
  try {
    if (req.user.role === 'teacher') {
      const studentsCount = await User.countDocuments({ role: 'student' });
      const resourcesCount = await Resource.countDocuments();
      const announcementsCount = await Announcement.countDocuments();
      const feesCount = await Fee.countDocuments();
      const resultsCount = await Result.countDocuments();
      
      res.json({
        students: studentsCount,
        resources: resourcesCount,
        announcements: announcementsCount,
        fees: feesCount,
        results: resultsCount
      });
    } else {
      const totalResources = await Resource.countDocuments();
      const totalAnnouncements = await Announcement.countDocuments();
      const upcomingSchedules = await Schedule.countDocuments();
      
      res.json({
        totalResources,
        totalAnnouncements,
        upcomingSchedules
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

// Fee Management Routes
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
        $limit: 10
      }
    ]);

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

// 404 handler for API routes
app.use('/api/*', (req, res) => {
  res.status(404).json({ error: 'API route not found' });
});

// Catch-all handler for non-API routes - return JSON instead of HTML
app.use('*', (req, res) => {
  res.status(404).json({ 
    error: 'Route not found',
    message: 'This is an API-only service. Please use /api/* endpoints.',
    available_endpoints: ['/health', '/api/auth/login', '/api/auth/register']
  });
});

// MongoDB Connection and Server Start - FIXED TIMING
const startServer = async () => {
  try {
    console.log('🔄 Connecting to MongoDB...');
    
    // MongoDB Connection with proper await
    const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/eduplatform';
    
    await mongoose.connect(MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      maxPoolSize: 10,
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
      bufferCommands: false
    });
    
    console.log('✅ Connected to MongoDB');
    
    // Only initialize data AFTER connection is established
    await initializeDefaultData();
    
    const server = app.listen(PORT, '0.0.0.0', () => {
      console.log(`🚀 Educational Platform API running on port ${PORT}`);
      console.log(`📊 Health check: http://localhost:${PORT}/health`);
      console.log(`🔑 Login endpoint: http://localhost:${PORT}/api/auth/login`);
      console.log(`👨‍🏫 Teacher login: teachshashi@tmt.com / shashi12@tmt`);
      console.log(`👨‍🎓 Student login: student1@math.com / studentpass1`);
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

    process.on('SIGINT', () => {
      console.log('💤 SIGINT received: closing server');
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

// Start the server
startServer();

module.exports = app;