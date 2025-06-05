// server.js - Main server file
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const multer = require('multer');
const AWS = require('aws-sdk');
const path = require('path');
const { createServer } = require('http');
const { Server } = require('socket.io');
require('dotenv').config();

const app = express();
app.set('trust proxy', 1);
const server = createServer(app);

// Socket.IO Configuration with CORS
const allowedOrigins = [
  'https://68396333bc5b92e8e2b1d6a9--sickoscoop.netlify.app',
  'https://sickoscoop.netlify.app',
  'http://localhost:3000',
  'http://127.0.0.1:3000',
  process.env.FRONTEND_URL
].filter(Boolean);

const io = new Server(server, {
  cors: {
    origin: allowedOrigins,
    methods: ["GET", "POST"]
  }
});

// ===== MIDDLEWARE =====
app.use(helmet());

// CORS Configuration - FIXED for localhost development
app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true); // Allow no origin
    
    if (origin.includes('localhost') || origin.includes('127.0.0.1')) {
      return callback(null, true); // Allow localhost
    }
    
    const allowedOrigins = [
      'https://68396333bc5b92e8e2b1d6a9--sickoscoop.netlify.app',
      'https://sickoscoop.netlify.app'
    ];
    
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      console.log('⚠️ CORS warning for:', origin);
      callback(null, true); // Allow anyway for now
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Origin', 'X-Requested-With', 'Accept']
}));

app.use(express.json({ limit: '10mb' }));

// Rate limiting - PRODUCTION SAFE
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
  trustProxy: false, // Disable trust proxy for rate limiting
  skip: (req) => {
    // Skip rate limiting for health checks
    return req.path === '/api/health' || req.path === '/';
  }
});
app.use('/api/', limiter);

// ===== AWS S3 Configuration =====
const s3 = new AWS.S3({
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  region: process.env.AWS_REGION || 'us-east-1'
});

// Multer configuration for file uploads
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 100 * 1024 * 1024 // 100MB limit
  },
  fileFilter: (req, file, cb) => {
    // Allow images, videos, audio, and PDFs
    const allowedTypes = [
      'image/jpeg', 'image/png', 'image/gif', 'image/webp',
      'video/mp4', 'video/mpeg', 'video/quicktime', 'video/webm',
      'audio/mpeg', 'audio/wav', 'audio/ogg', 'audio/mp3',
      'application/pdf'
    ];
    
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('File type not supported'), false);
    }
  }
});

// ===== ROOT ROUTE (ADD THIS) =====
app.get('/', (req, res) => {
  res.json({
    message: 'SickoScoop API is running successfully! 🚀',
    version: '1.0.0',
    status: 'active',
   endpoints: {
  auth: ['POST /api/auth/login', 'POST /api/auth/register'],
  posts: ['GET /api/posts', 'POST /api/posts', 'GET /api/posts/public'],  // ← Added!
  chat: ['GET /api/conversations'],
  other: ['GET /api/health']
}
    timestamp: new Date().toISOString()
  });
});

// ===== DATABASE MODELS =====

// User Schema - UPDATED for frontend compatibility
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, trim: true, unique: true }, // CHANGED: name -> username
  email: { type: String, required: true, unique: true, lowercase: true },
  password: { type: String, required: true, minlength: 6 },
  avatar: { type: String, default: '✨' },
  bio: { type: String, default: 'New to SickoScoop', maxlength: 500 },
  verified: { type: Boolean, default: false },
  isPrivate: { type: Boolean, default: false },
  blockedUsers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  followers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  following: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  stalkerReports: [{
    reportedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    reason: String,
    createdAt: { type: Date, default: Date.now }
  }],
  privacyScore: { type: Number, default: 94, min: 0, max: 100 }, // ADDED
  transparencyScore: { type: Number, default: 98, min: 0, max: 100 }, // UPDATED default
  communityScore: { type: Number, default: 96, min: 0, max: 100 }, // ADDED
  lastActive: { type: Date, default: Date.now },
  createdAt: { type: Date, default: Date.now }
});

// Post Schema - UPDATED for frontend compatibility
const postSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }, // CHANGED: author -> userId
  content: { type: String, required: true, maxlength: 2000 },
  mediaFiles: [{ // CHANGED: images -> mediaFiles for compatibility
    type: {
      type: String,
      enum: ['image', 'video', 'audio', 'pdf'],
      required: true
    },
    url: {
      type: String,
      required: true
    },
    filename: String,
    size: Number
  }],
  likes: [{
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, // ADDED user field for frontend
    createdAt: { type: Date, default: Date.now }
  }],
  comments: [{
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, // CHANGED: author -> user
    content: { type: String, maxlength: 500 },
    createdAt: { type: Date, default: Date.now }
  }],
  shares: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  transparencyFlags: {
    isAuthentic: { type: Boolean, default: true },
    isOriginal: { type: Boolean, default: true },
    sensitivityLevel: { type: String, enum: ['low', 'medium', 'high'], default: 'low' }
  },
  visibility: { type: String, enum: ['public', 'followers', 'private'], default: 'public' },
  isPublic: { type: Boolean, default: true }, // ADDED for frontend compatibility
  createdAt: { type: Date, default: Date.now }
});

// Conversation Schema - ADDED for frontend
const conversationSchema = new mongoose.Schema({
  participants: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  }],
  lastMessage: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Message'
  },
  isActive: {
    type: Boolean,
    default: true
  }
}, {
  timestamps: true
});

// Message Schema - UPDATED
const messageSchema = new mongoose.Schema({
  conversationId: { type: mongoose.Schema.Types.ObjectId, ref: 'Conversation' }, // ADDED
  sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  recipient: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, // null for public chat
  content: { type: String, required: true, maxlength: 1000 },
  chatRoom: { type: String, default: 'public' },
  messageType: { type: String, enum: ['text', 'image', 'video', 'audio', 'file'], default: 'text' }, // ADDED
  mediaUrl: String, // ADDED
  isEdited: { type: Boolean, default: false },
  editHistory: [{
    content: String,
    editedAt: { type: Date, default: Date.now }
  }],
  readBy: [{
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    readAt: { type: Date, default: Date.now }
  }],
  isDeleted: { type: Boolean, default: false }, // ADDED
  createdAt: { type: Date, default: Date.now }
});

// Report Schema for anti-stalking
const reportSchema = new mongoose.Schema({
  reporter: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  reportedUser: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  reportType: { 
    type: String, 
    enum: ['stalking', 'harassment', 'fake_account', 'spam', 'inappropriate_content'],
    required: true 
  },
  description: { type: String, required: true, maxlength: 1000 },
  evidence: [{ type: String }], // URLs or file paths
  status: { 
    type: String, 
    enum: ['pending', 'investigating', 'resolved', 'dismissed'],
    default: 'pending' 
  },
  actionTaken: String,
  createdAt: { type: Date, default: Date.now },
  resolvedAt: Date
});

const User = mongoose.model('User', userSchema);
const Post = mongoose.model('Post', postSchema);
const Conversation = mongoose.model('Conversation', conversationSchema); // ADDED
const Message = mongoose.model('Message', messageSchema);
const Report = mongoose.model('Report', reportSchema);

// ===== AUTHENTICATION MIDDLEWARE =====
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ message: 'Access token required' });
  }

  try {
    console.log('🔍 Token received:', token.substring(0, 20) + '...');
    console.log('🔍 JWT_SECRET exists:', !!process.env.JWT_SECRET);
    
    // ✅ CRITICAL: Specify algorithm in verification
    const decoded = jwt.verify(token, process.env.JWT_SECRET, {
      algorithms: ['HS256']  // ← This is crucial!
    });
    
    console.log('✅ Token verified successfully:', decoded);
    
    // ✅ DEMO USER FIX: Handle demo users specially
    if (decoded.userId === 'demo-user-id') {
      console.log('🎭 Demo user detected - creating mock user object');
      
      // Create a mock user object for demo mode
      const demoUser = {
        _id: 'demo-user-id',
        username: 'Demo User',
        email: 'demo@sickoscoop.com',
        avatar: '✨',
        bio: 'Demo user for SickoScoop',
        verified: true,
        privacyScore: 94,
        transparencyScore: 98,
        communityScore: 96,
        blockedUsers: [],
        followers: [],
        following: [],
        isPrivate: false,
        createdAt: new Date()
      };
      
      req.user = demoUser;
      console.log('✅ Demo user set up successfully');
      return next();
    }
    
    // For real users, find in database
    const user = await User.findById(decoded.userId).select('-password');
    console.log('🔍 Real user found:', !!user);
    
    if (!user) {
      return res.status(401).json({ message: 'User not found' });
    }
    
    req.user = user;
    next();
    
  } catch (error) {
    console.error('❌ JWT VERIFICATION ERROR:', error.name, error.message);
    return res.status(403).json({ message: 'Invalid or expired token' });
  }
};

// ===== AUTHENTICATION ROUTES =====

// Register - UPDATED for frontend compatibility
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password } = req.body; // CHANGED: name -> username

    // Validation
    if (!username || !email || !password) {
      return res.status(400).json({ message: 'All fields are required' });
    }

    if (password.length < 6) {
      return res.status(400).json({ message: 'Password must be at least 6 characters' });
    }

    // Check if user exists
    const existingUser = await User.findOne({ 
      $or: [{ email }, { username }] 
    });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists with this email or username' });
    }

    // Hash password
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Create user
    const user = new User({
      username, // CHANGED
      email,
      password: hashedPassword
    });

    await user.save();

    // Generate JWT
    const token = jwt.sign(
      { userId: user._id, username: user.username }, // ADDED username to token
      process.env.JWT_SECRET,
      { 
        algorithm: 'HS256',
        expiresIn: '7d' 
      }
    );

    res.status(201).json({
      message: 'User created successfully',
      token,
      user: {
        id: user._id,
        username: user.username, // CHANGED
        email: user.email,
        avatar: user.avatar,
        bio: user.bio,
        verified: user.verified,
        privacyScore: user.privacyScore, // ADDED
        transparencyScore: user.transparencyScore,
        communityScore: user.communityScore // ADDED
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ message: 'Server error during registration' });
  }
});

// Login - UPDATED for frontend compatibility
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
    }

// Add this at the start of your existing login route
if (email === 'demo@sickoscoop.com' && password === 'demo') {
  const demoUser = {
    id: 'demo-user-id',
    username: 'Demo User',
    email: 'demo@sickoscoop.com',
    verified: true,
    privacyScore: 94,
    transparencyScore: 98,
    communityScore: 96
  };

  const token = jwt.sign(
    { userId: 'demo-user-id', username: 'Demo User' },
    process.env.JWT_SECRET || 'demo-secret-key',
    { algorithm: 'HS256', expiresIn: '7d' }
  );

  return res.json({
    message: 'Demo login successful',
    token,
    user: demoUser
  });
}

    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Check password
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Update last active
    user.lastActive = new Date();
    await user.save();

    // Generate JWT
    const token = jwt.sign(
      { userId: user._id, username: user.username }, // ADDED username
      process.env.JWT_SECRET,
      { 
        algorithm: 'HS256',
        expiresIn: '7d' 
      }
    );

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        username: user.username, // CHANGED
        email: user.email,
        avatar: user.avatar,
        bio: user.bio,
        verified: user.verified,
        privacyScore: user.privacyScore, // ADDED
        transparencyScore: user.transparencyScore,
        communityScore: user.communityScore, // ADDED
        followers: user.followers,
        following: user.following
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error during login' });
  }
});

// Get current user - UPDATED
app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user._id)
      .populate('followers', 'username avatar verified') // CHANGED: name -> username
      .populate('following', 'username avatar verified')
      .select('-password');

    res.json({
      id: user._id,
      username: user.username, // CHANGED
      email: user.email,
      avatar: user.avatar,
      bio: user.bio,
      verified: user.verified,
      privacyScore: user.privacyScore, // ADDED
      transparencyScore: user.transparencyScore,
      communityScore: user.communityScore, // ADDED
      followers: user.followers,
      following: user.following,
      isPrivate: user.isPrivate,
      createdAt: user.createdAt
    });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Verify token endpoint - ADD THIS
app.post('/api/auth/verify', async (req, res) => {
  try {
    const { token } = req.body;
    
    if (!token) {
      return res.status(400).json({ valid: false, message: 'Token required' });
    }

    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET, {
        algorithms: ['HS256']
      });
      
      // Handle demo user
      if (decoded.userId === 'demo-user-id') {
        return res.json({
          valid: true,
          user: {
            id: 'demo-user-id',
            username: 'Demo User',
            email: 'demo@sickoscoop.com',
            verified: true,
            privacyScore: 94,
            transparencyScore: 98,
            communityScore: 96
          }
        });
      }
      
      // Find real user
      const user = await User.findById(decoded.userId).select('-password');
      if (!user) {
        return res.status(401).json({ valid: false, message: 'User not found' });
      }
      
      res.json({
        valid: true,
        user: {
          id: user._id,
          username: user.username,
          email: user.email,
          avatar: user.avatar,
          bio: user.bio,
          verified: user.verified,
          privacyScore: user.privacyScore,
          transparencyScore: user.transparencyScore,
          communityScore: user.communityScore,
          followers: user.followers,
          following: user.following
        }
      });
      
    } catch (jwtError) {
      return res.status(401).json({ valid: false, message: 'Invalid token' });
    }
    
  } catch (error) {
    console.error('Token verification error:', error);
    res.status(500).json({ valid: false, message: 'Server error' });
  }
});

// ===== MEDIA UPLOAD ROUTE - NEW =====
app.post('/api/media/upload', authenticateToken, upload.array('files', 10), async (req, res) => {
  try {
    console.log('📁 File upload request received');
    console.log('Files count:', req.files ? req.files.length : 0);

    if (!req.files || req.files.length === 0) {
      return res.status(400).json({ message: 'No files uploaded' });
    }

    // Check if AWS is configured for production
    if (!process.env.AWS_ACCESS_KEY_ID || !process.env.AWS_SECRET_ACCESS_KEY || !process.env.AWS_S3_BUCKET) {
      return res.status(500).json({ 
        message: 'File upload not configured. Please set up AWS S3 credentials.' 
      });
    }

    const uploadPromises = req.files.map(async (file) => {
      const fileExtension = path.extname(file.originalname);
      const fileName = `media/${Date.now()}-${Math.random().toString(36).substring(7)}${fileExtension}`;
      
      const uploadParams = {
        Bucket: process.env.AWS_S3_BUCKET,
        Key: fileName,
        Body: file.buffer,
        ContentType: file.mimetype,
        ACL: 'public-read'
      };

      console.log('⬆️ Uploading file:', fileName);
      const result = await s3.upload(uploadParams).promise();
      
      return {
        type: file.mimetype.startsWith('image/') ? 'image' :
              file.mimetype.startsWith('video/') ? 'video' :
              file.mimetype.startsWith('audio/') ? 'audio' : 'pdf',
        url: result.Location,
        filename: file.originalname,
        size: file.size
      };
    });

    const uploadedFiles = await Promise.all(uploadPromises);

    console.log('✅ Files uploaded successfully:', uploadedFiles.length);
    res.json({
      message: 'Files uploaded successfully',
      files: uploadedFiles
    });

  } catch (error) {
    console.error('❌ Upload error:', error);
    res.status(500).json({ 
      message: 'Upload failed', 
      error: error.message 
    });
  }
});

// ADD THE PUBLIC POSTS ENDPOINT HERE ↓↓↓

// Get public posts (no authentication required) - NEW ENDPOINT
// Get public posts (no authentication required) - ENHANCED ENDPOINT
app.get('/api/posts/public', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;

    console.log('🌐 Public posts request:', { page, limit, skip });

    // Get public posts with proper population
    const posts = await Post.find({
      $or: [
        { visibility: 'public' },
        { isPublic: true },
        { visibility: { $exists: false } } // Posts without visibility field default to public
      ]
    })
    .populate('userId', 'username avatar verified transparencyScore')
    .populate('likes.user', 'username')
    .populate('comments.user', 'username avatar verified')
    .sort({ createdAt: -1 })
    .skip(skip)
    .limit(limit)
    .lean(); // Use lean() for better performance

    console.log('✅ Found posts:', posts.length);

    // Log first post for debugging
    if (posts.length > 0) {
      console.log('📄 Sample post:', {
        id: posts[0]._id,
        content: posts[0].content?.substring(0, 50),
        author: posts[0].userId?.username,
        hasUserId: !!posts[0].userId
      });
    }

    // Transform for frontend compatibility
    const transformedPosts = posts.map(post => ({
      ...post,
      // Ensure likes are just user IDs for frontend compatibility
      likes: (post.likes || []).map(like => 
        typeof like === 'object' && like.user ? like.user._id || like.user : like
      ),
      // Ensure we have the right structure
      userId: post.userId || { username: 'Unknown User', avatar: '?', verified: false }
    }));

    res.json(transformedPosts);
  } catch (error) {
    console.error('❌ Public posts error:', error);
    res.status(500).json({ 
      message: 'Failed to fetch public posts',
      error: error.message,
      stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
});

// ===== POST ROUTES - UPDATED =====
// (your existing posts routes go here)
// ===== POST ROUTES - UPDATED =====

// Get posts (feed) - UPDATED for frontend compatibility
app.get('/api/posts', authenticateToken, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    // Get posts from non-blocked users
    const posts = await Post.find({
      userId: { $nin: req.user.blockedUsers }, // CHANGED: author -> userId
      $or: [
        { visibility: 'public' },
        { visibility: 'followers', userId: { $in: req.user.following } }
      ]
    })
    .populate('userId', 'username avatar verified transparencyScore') // CHANGED: author -> userId, name -> username
    .populate('likes.user', 'username') // ADDED .user
    .populate('comments.user', 'username avatar verified') // CHANGED: author -> user
    .sort({ createdAt: -1 })
    .skip(skip)
    .limit(limit);

    console.log('📝 Retrieved posts:', posts.length);
    res.json(posts); // CHANGED: return array directly like frontend expects
  } catch (error) {
    console.error('Get posts error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Create post - UPDATED
app.post('/api/posts', authenticateToken, async (req, res) => {
  try {
    const { content, mediaFiles, visibility = 'public' } = req.body; // ADDED mediaFiles

    if (!content || content.trim().length === 0) {
      return res.status(400).json({ message: 'Post content is required' });
    }

    const post = new Post({
      userId: req.user._id, // CHANGED: author -> userId
      content: content.trim(),
      mediaFiles: mediaFiles || [], // CHANGED: images -> mediaFiles
      visibility,
      isPublic: visibility === 'public' // ADDED
    });

    await post.save();
    
    const populatedPost = await Post.findById(post._id)
      .populate('userId', 'username avatar verified transparencyScore'); // CHANGED

    // Emit to Socket.IO for real-time updates
    io.emit('new_post', populatedPost);

    console.log('✅ Post created:', post._id);
    res.status(201).json(populatedPost); // CHANGED: return post directly
  } catch (error) {
    console.error('Create post error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Like/Unlike post - UPDATED for frontend compatibility
app.post('/api/posts/:postId/like', authenticateToken, async (req, res) => {
  try {
    const post = await Post.findById(req.params.postId);
    if (!post) {
      return res.status(404).json({ message: 'Post not found' });
    }

    // Check if user already liked (look for user field)
    const existingLike = post.likes.find(like => 
      like.user && like.user.toString() === req.user._id.toString()
    );
    
    if (existingLike) {
      // Remove like
      post.likes = post.likes.filter(like => 
        !like.user || like.user.toString() !== req.user._id.toString()
      );
    } else {
      // Add like with user field
      post.likes.push({ user: req.user._id });
    }

    await post.save();
    
    // Populate and return full post like frontend expects
    const populatedPost = await Post.findById(post._id)
      .populate('userId', 'username avatar verified')
      .populate('likes.user', 'username');

    res.json(populatedPost); // Return full post object
  } catch (error) {
    console.error('Like post error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// ===== CONVERSATION ROUTES - NEW FOR FRONTEND =====
app.get('/api/conversations', authenticateToken, async (req, res) => {
  try {
    console.log('💬 Fetching conversations for user:', req.user._id);

    const conversations = await Conversation.find({
      participants: req.user._id
    })
    .populate('participants', 'username avatar lastActive') // CHANGED: name -> username
    .populate('lastMessage')
    .sort({ updatedAt: -1 });

    console.log('✅ Conversations found:', conversations.length);
    res.json(conversations);
  } catch (error) {
    console.error('❌ Get conversations error:', error);
    res.status(500).json({ message: 'Server error fetching conversations' });
  }
});

// ===== EXISTING CHAT ROUTES (KEEP FOR BACKWARD COMPATIBILITY) =====

// Get chat conversations (existing route)
app.get('/api/chats', authenticateToken, async (req, res) => {
  try {
    // Find all messages where user is sender or recipient
    const messages = await Message.aggregate([
      {
        $match: {
          $or: [
            { sender: req.user._id },
            { recipient: req.user._id }
          ]
        }
      },
      {
        $sort: { createdAt: -1 }
      },
      {
        $group: {
          _id: {
            $cond: [
              { $eq: ['$sender', req.user._id] },
              '$recipient',
              '$sender'
            ]
          },
          lastMessage: { $first: '$$ROOT' },
          participants: { $first: ['$sender', '$recipient'] }
        }
      }
    ]);

    // Populate user data for chat participants
    const chats = await Message.populate(messages, [
      { path: 'lastMessage.sender', select: 'username avatar verified' }, // CHANGED
      { path: 'lastMessage.recipient', select: 'username avatar verified' }, // CHANGED
      { path: '_id', select: 'username avatar verified' } // CHANGED
    ]);

    res.json(chats);
  } catch (error) {
    console.error('Get chats error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get messages for a specific chat
app.get('/api/messages', authenticateToken, async (req, res) => {
  try {
    const { chatRoom = 'public', with: otherUserId, limit = 50 } = req.query;
    
    let query = {};
    
    if (chatRoom === 'public') {
      query = { chatRoom: 'public' };
    } else if (otherUserId) {
      // Private messages between two users
      query = {
        $or: [
          { sender: req.user._id, recipient: otherUserId },
          { sender: otherUserId, recipient: req.user._id }
        ]
      };
    }

    const messages = await Message.find(query)
      .populate('sender', 'username avatar verified') // CHANGED
      .populate('recipient', 'username avatar verified') // CHANGED
      .sort({ createdAt: -1 })
      .limit(parseInt(limit));

    res.json({ messages: messages.reverse() });
  } catch (error) {
    console.error('Get messages error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Send message
app.post('/api/messages', authenticateToken, async (req, res) => {
  try {
    const { content, recipient, chatRoom = 'public' } = req.body;

    if (!content || content.trim().length === 0) {
      return res.status(400).json({ message: 'Message content is required' });
    }

    const message = new Message({
      sender: req.user._id,
      recipient: recipient || null,
      content: content.trim(),
      chatRoom
    });

    await message.save();
    
    const populatedMessage = await Message.findById(message._id)
      .populate('sender', 'username avatar verified') // CHANGED
      .populate('recipient', 'username avatar verified'); // CHANGED

    // Emit to Socket.IO for real-time chat
    io.emit('new_message', populatedMessage);

    res.status(201).json({ message: 'Message sent successfully', data: populatedMessage });
  } catch (error) {
    console.error('Send message error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// ===== KEEP ALL OTHER EXISTING ROUTES =====

// Get user profile
app.get('/api/users/:userId', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.params.userId)
      .populate('followers', 'username avatar verified') // CHANGED
      .populate('following', 'username avatar verified') // CHANGED
      .select('-password -email -blockedUsers -stalkerReports');

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Check if current user is blocked
    if (user.blockedUsers.includes(req.user._id)) {
      return res.status(403).json({ message: 'You are blocked by this user' });
    }

    res.json({ user });
  } catch (error) {
    console.error('Get user profile error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Update user profile
app.put('/api/users/profile', authenticateToken, async (req, res) => {
  try {
    const { username, bio, avatar, isPrivate } = req.body; // CHANGED: name -> username
    
    const updates = {};
    if (username) updates.username = username; // CHANGED
    if (bio !== undefined) updates.bio = bio;
    if (avatar) updates.avatar = avatar;
    if (isPrivate !== undefined) updates.isPrivate = isPrivate;

    const user = await User.findByIdAndUpdate(
      req.user._id,
      updates,
      { new: true, select: '-password' }
    );

    res.json({ message: 'Profile updated successfully', user });
  } catch (error) {
    console.error('Update profile error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Follow/Unfollow user
app.post('/api/users/:userId/follow', authenticateToken, async (req, res) => {
  try {
    const targetUserId = req.params.userId;
    const currentUserId = req.user._id;

    if (targetUserId === currentUserId.toString()) {
      return res.status(400).json({ message: 'Cannot follow yourself' });
    }

    const targetUser = await User.findById(targetUserId);
    if (!targetUser) {
      return res.status(404).json({ message: 'User not found' });
    }

    const currentUser = await User.findById(currentUserId);
    
    const isFollowing = currentUser.following.includes(targetUserId);
    
    if (isFollowing) {
      // Unfollow
      currentUser.following.pull(targetUserId);
      targetUser.followers.pull(currentUserId);
    } else {
      // Follow
      currentUser.following.push(targetUserId);
      targetUser.followers.push(currentUserId);
    }

    await currentUser.save();
    await targetUser.save();

    res.json({ 
      message: isFollowing ? 'Unfollowed successfully' : 'Followed successfully',
      isFollowing: !isFollowing 
    });
  } catch (error) {
    console.error('Follow/unfollow error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Block/Unblock user
app.post('/api/users/:userId/block', authenticateToken, async (req, res) => {
  try {
    const targetUserId = req.params.userId;
    const currentUser = await User.findById(req.user._id);

    const isBlocked = currentUser.blockedUsers.includes(targetUserId);
    
    if (isBlocked) {
      currentUser.blockedUsers.pull(targetUserId);
    } else {
      currentUser.blockedUsers.push(targetUserId);
      // Also remove from following/followers
      currentUser.following.pull(targetUserId);
      await User.findByIdAndUpdate(targetUserId, {
        $pull: { following: req.user._id, followers: req.user._id }
      });
    }

    await currentUser.save();

    res.json({ 
      message: isBlocked ? 'User unblocked' : 'User blocked',
      isBlocked: !isBlocked 
    });
  } catch (error) {
    console.error('Block/unblock error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Add comment to post
app.post('/api/posts/:postId/comments', authenticateToken, async (req, res) => {
  try {
    const { content } = req.body;
    
    if (!content || content.trim().length === 0) {
      return res.status(400).json({ message: 'Comment content is required' });
    }

    const post = await Post.findById(req.params.postId);
    if (!post) {
      return res.status(404).json({ message: 'Post not found' });
    }

    const comment = {
      user: req.user._id, // CHANGED: author -> user
      content: content.trim()
    };

    post.comments.push(comment);
    await post.save();

    const populatedPost = await Post.findById(post._id)
      .populate('comments.user', 'username avatar verified'); // CHANGED

    res.status(201).json({ 
      message: 'Comment added successfully', 
      comment: populatedPost.comments[populatedPost.comments.length - 1] 
    });
  } catch (error) {
    console.error('Add comment error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// ===== ANTI-STALKING ROUTES =====

// Report user
app.post('/api/reports', authenticateToken, async (req, res) => {
  try {
    const { reportedUser, reportType, description, evidence } = req.body;

    if (!reportedUser || !reportType || !description) {
      return res.status(400).json({ message: 'All fields are required' });
    }

    const report = new Report({
      reporter: req.user._id,
      reportedUser,
      reportType,
      description,
      evidence: evidence || []
    });

    await report.save();

    // Update reported user's transparency score
    await User.findByIdAndUpdate(reportedUser, {
      $push: { 
        stalkerReports: {
          reportedBy: req.user._id,
          reason: reportType,
          createdAt: new Date()
        }
      },
      $inc: { transparencyScore: -5 }
    });

    res.status(201).json({ message: 'Report submitted successfully', report });
  } catch (error) {
    console.error('Submit report error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get transparency score
app.get('/api/users/:userId/transparency', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.params.userId).select('transparencyScore stalkerReports');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({ 
      transparencyScore: user.transparencyScore,
      reportCount: user.stalkerReports.length 
    });
  } catch (error) {
    console.error('Get transparency score error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// ===== HEALTH CHECK =====
app.get('/api/health', (req, res) => {
  res.json({
    status: 'OK',
    message: 'SickoScoop API is running!',
    timestamp: new Date().toISOString()
  });
});

// Debug endpoint
app.get('/api/debug/jwt', (req, res) => {
  res.json({
    hasJwtSecret: !!process.env.JWT_SECRET,
    jwtSecretLength: process.env.JWT_SECRET ? process.env.JWT_SECRET.length : 0,
    nodeEnv: process.env.NODE_ENV,
    jwtSecretStart: process.env.JWT_SECRET ? process.env.JWT_SECRET.substring(0, 10) + '...' : 'undefined'
  });
});

// Add ONLY this debug endpoint after line 1084 - NO sample data creation

// ===== DEBUG ENDPOINT (REAL DATA ONLY) =====

// 🔍 DEBUG ENDPOINT - Check what's actually in your database
app.get('/api/debug/posts', async (req, res) => {
  try {
    console.log('🔍 Starting posts debug...');
    
    // Get all posts without population
    const rawPosts = await Post.find().limit(10);
    console.log('📊 Raw posts count:', rawPosts.length);
    
    // Get all users
    const users = await User.find().select('username email');
    console.log('👥 Users count:', users.length);
    
    // Check for orphaned posts
    const orphanedPosts = await Post.find({
      userId: { $nin: users.map(u => u._id) }
    });
    console.log('🚨 Orphaned posts:', orphanedPosts.length);
    
    // Try population
    const populatedPosts = await Post.find()
      .populate('userId', 'username avatar verified')
      .limit(5);
    
    console.log('🔗 Sample populated posts:');
    populatedPosts.forEach((post, idx) => {
      console.log(`Post ${idx + 1}:`, {
        _id: post._id,
        content: post.content?.substring(0, 50) + '...',
        userId: post.userId,
        hasUsername: !!post.userId?.username
      });
    });
    
    res.json({
      status: 'Debug complete',
      summary: {
        totalPosts: rawPosts.length,
        totalUsers: users.length,
        orphanedPosts: orphanedPosts.length,
        hasValidData: users.length > 0 && rawPosts.length > 0 && orphanedPosts.length === 0
      },
      diagnosis: {
        databaseEmpty: users.length === 0 && rawPosts.length === 0,
        hasUsers: users.length > 0,
        hasPosts: rawPosts.length > 0,
        hasOrphanedPosts: orphanedPosts.length > 0,
        validPopulatedPosts: populatedPosts.filter(p => p.userId?.username).length
      },
      recommendations: (() => {
        if (users.length === 0) return ['Database is empty. Register users on frontend.'];
        if (orphanedPosts.length > 0) return ['Found orphaned posts. Run cleanup endpoint.'];
        if (rawPosts.length === 0) return ['No posts found. Create posts via frontend.'];
        return ['Database looks healthy!'];
      })(),
      sampleData: {
        users: users.slice(0, 3).map(u => ({ username: u.username, email: u.email })),
        posts: populatedPosts.slice(0, 3).map(post => ({
          _id: post._id,
          content: post.content?.substring(0, 100),
          authorUsername: post.userId?.username || 'NO USERNAME',
          authorId: post.userId?._id || 'NO USER ID'
        }))
      }
    });
    
  } catch (error) {
    console.error('❌ Debug error:', error);
    res.status(500).json({ 
      error: error.message,
      stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
});

// 🛠️ CLEANUP ENDPOINT - Only if needed to remove bad data
app.post('/api/debug/cleanup', async (req, res) => {
  try {
    console.log('🛠️ Starting database cleanup...');
    
    // Find and count orphaned posts
    const users = await User.find();
    const userIds = users.map(u => u._id);
    
    const orphanedPosts = await Post.find({
      userId: { $nin: userIds }
    });
    
    if (orphanedPosts.length === 0) {
      return res.json({
        message: 'No cleanup needed - database is clean!',
        deletedPosts: 0
      });
    }
    
    // Delete orphaned posts only
    const deleteResult = await Post.deleteMany({
      userId: { $nin: userIds }
    });
    
    console.log('🗑️ Cleaned up orphaned posts:', deleteResult.deletedCount);
    
    res.json({
      message: 'Cleanup completed - removed orphaned posts only',
      deletedPosts: deleteResult.deletedCount,
      remainingPosts: await Post.countDocuments(),
      remainingUsers: users.length
    });
    
  } catch (error) {
    console.error('❌ Cleanup error:', error);
    res.status(500).json({ 
      error: error.message 
    });
  }
});

// ===== END DEBUG ENDPOINTS =====

// ===== SOCKET.IO REAL-TIME FEATURES =====
io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  socket.on('join_chat', (chatRoom) => {
    socket.join(chatRoom);
    console.log(`User ${socket.id} joined ${chatRoom}`);
  });

  socket.on('leave_chat', (chatRoom) => {
    socket.leave(chatRoom);
    console.log(`User ${socket.id} left ${chatRoom}`);
  });

  socket.on('disconnect', () => {
    console.log('User disconnected:', socket.id);
  });
});

// ===== ERROR HANDLING & 404 - MUST BE LAST =====
app.use((error, req, res, next) => {
  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ message: 'File too large' });
    }
  }
  
  console.error('❌ Unhandled error:', error);
  res.status(500).json({ message: 'Internal server error' });
});

// Handle 404 - THIS MUST BE THE VERY LAST ROUTE
app.use('*', (req, res) => {
  console.log('❌ 404 for:', req.method, req.originalUrl);
  res.status(404).json({ 
    message: 'API endpoint not found',
    requestedUrl: req.originalUrl,
    method: req.method
  });
});

// ===== DATABASE CONNECTION & SERVER START =====
mongoose.connect(process.env.MONGODB_URI)
  .then(() => {
    console.log('Connected to MongoDB');
    const PORT = process.env.PORT || 3001;
    server.listen(PORT, () => {
      console.log(`SickoScoop API server running on port ${PORT}`);
      console.log('🌐 CORS allowed origins:', allowedOrigins);
    });
  })
  .catch((error) => {
    console.error('MongoDB connection error:', error);
    process.exit(1);
  });

module.exports = { app, server, io };