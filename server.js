const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const socketIo = require('socket.io');
const http = require('http');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
require('dotenv').config();

// Create Express app and HTTP server
const app = express();
const server = http.createServer(app);

// Configure Socket.io
const io = socketIo(server, {
  cors: {
    origin: process.env.FRONTEND_URL || "http://localhost:3000",
    methods: ["GET", "POST"]
  }
});

// Security middleware
app.use(helmet());

// CORS configuration
app.use(cors({
  origin: process.env.FRONTEND_URL || "http://localhost:3000",
  credentials: true
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// Stricter rate limiting for auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5 // limit each IP to 5 auth attempts per 15 minutes
});

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// MongoDB connection
const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/sickoscoop', {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log('✅ Connected to MongoDB');
  } catch (error) {
    console.error('❌ MongoDB connection error:', error);
    process.exit(1);
  }
};

connectDB();

// User Schema
const userSchema = new mongoose.Schema({
  name: { 
    type: String, 
    required: true, 
    trim: true, 
    maxlength: 50 
  },
  email: { 
    type: String, 
    required: true, 
    unique: true, 
    lowercase: true 
  },
  password: { 
    type: String, 
    required: true, 
    minlength: 6 
  },
  avatar: { 
    type: String, 
    default: '✨' 
  },
  bio: { 
    type: String, 
    maxlength: 200, 
    default: '' 
  },
  verified: { 
    type: Boolean, 
    default: false 
  },
  followers: [{ 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User' 
  }],
  following: [{ 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User' 
  }],
  blockedUsers: [{ 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User' 
  }],
  privacySettings: {
    allowMessages: { 
      type: String, 
      enum: ['everyone', 'followers', 'none'], 
      default: 'followers' 
    },
    showOnlineStatus: { 
      type: Boolean, 
      default: true 
    },
    profileVisibility: { 
      type: String, 
      enum: ['public', 'followers', 'private'], 
      default: 'public' 
    }
  },
  lastActive: { 
    type: Date, 
    default: Date.now 
  }
}, { 
  timestamps: true 
});

const User = mongoose.model('User', userSchema);

// Post Schema
const postSchema = new mongoose.Schema({
  author: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true 
  },
  content: { 
    type: String, 
    required: true, 
    maxlength: 500 
  },
  likes: [{ 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User' 
  }],
  comments: [{
    author: { 
      type: mongoose.Schema.Types.ObjectId, 
      ref: 'User' 
    },
    content: { 
      type: String, 
      maxlength: 200 
    },
    createdAt: { 
      type: Date, 
      default: Date.now 
    }
  }],
  reported: [{
    reporter: { 
      type: mongoose.Schema.Types.ObjectId, 
      ref: 'User' 
    },
    reason: String,
    createdAt: { 
      type: Date, 
      default: Date.now 
    }
  }],
  visibility: { 
    type: String, 
    enum: ['public', 'followers'], 
    default: 'public' 
  }
}, { 
  timestamps: true 
});

const Post = mongoose.model('Post', postSchema);

// Chat Schema
const chatSchema = new mongoose.Schema({
  participants: [{ 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User' 
  }],
  messages: [{
    sender: { 
      type: mongoose.Schema.Types.ObjectId, 
      ref: 'User' 
    },
    content: { 
      type: String, 
      required: true, 
      maxlength: 1000 
    },
    readBy: [{
      user: { 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'User' 
      },
      readAt: { 
        type: Date, 
        default: Date.now 
      }
    }],
    createdAt: { 
      type: Date, 
      default: Date.now 
    }
  }],
  lastMessage: { 
    type: Date, 
    default: Date.now 
  }
}, { 
  timestamps: true 
});

const Chat = mongoose.model('Chat', chatSchema);

// JWT Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key', (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// =============================================================================
// AUTHENTICATION ROUTES
// =============================================================================

// User Signup
app.post('/api/auth/signup', authLimiter, async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Validation
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists with this email' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Create new user
    const user = new User({
      name,
      email,
      password: hashedPassword
    });

    await user.save();

    // Generate JWT token
    const token = jwt.sign(
      { userId: user._id, email: user.email },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '7d' }
    );

    // Return success response
    res.status(201).json({
      message: 'User created successfully',
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        avatar: user.avatar,
        verified: user.verified
      }
    });

  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// User Login
app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user by email
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    // Check password
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    // Update last active timestamp
    user.lastActive = new Date();
    await user.save();

    // Generate JWT token
    const token = jwt.sign(
      { userId: user._id, email: user.email },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '7d' }
    );

    // Return success response
    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        avatar: user.avatar,
        verified: user.verified
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// =============================================================================
// USER ROUTES
// =============================================================================

// Get user profile
app.get('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId)
      .select('-password')
      .populate('followers following', 'name avatar verified');
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(user);
  } catch (error) {
    console.error('Profile fetch error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update user profile
app.put('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const { name, bio, avatar, privacySettings } = req.body;
    
    const updateData = {};
    if (name) updateData.name = name;
    if (bio !== undefined) updateData.bio = bio;
    if (avatar) updateData.avatar = avatar;
    if (privacySettings) updateData.privacySettings = privacySettings;

    const user = await User.findByIdAndUpdate(
      req.user.userId,
      updateData,
      { new: true }
    ).select('-password');

    res.json(user);
  } catch (error) {
    console.error('Profile update error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// =============================================================================
// POST ROUTES
// =============================================================================

// Create new post
app.post('/api/posts', authenticateToken, async (req, res) => {
  try {
    const { content, visibility = 'public' } = req.body;

    if (!content || content.trim().length === 0) {
      return res.status(400).json({ error: 'Post content is required' });
    }

    const post = new Post({
      author: req.user.userId,
      content: content.trim(),
      visibility
    });

    await post.save();
    await post.populate('author', 'name avatar verified');

    res.status(201).json(post);
  } catch (error) {
    console.error('Post creation error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get all posts (with pagination)
app.get('/api/posts', authenticateToken, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;

    const posts = await Post.find({ visibility: 'public' })
      .populate('author', 'name avatar verified')
      .populate('comments.author', 'name avatar verified')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    res.json(posts);
  } catch (error) {
    console.error('Posts fetch error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Like/Unlike a post
app.post('/api/posts/:postId/like', authenticateToken, async (req, res) => {
  try {
    const post = await Post.findById(req.params.postId);
    if (!post) {
      return res.status(404).json({ error: 'Post not found' });
    }

    const isLiked = post.likes.includes(req.user.userId);
    
    if (isLiked) {
      post.likes.pull(req.user.userId);
    } else {
      post.likes.push(req.user.userId);
    }

    await post.save();
    res.json({ 
      liked: !isLiked, 
      likeCount: post.likes.length 
    });
  } catch (error) {
    console.error('Like toggle error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// =============================================================================
// CHAT ROUTES
// =============================================================================

// Get user's chats
app.get('/api/chats', authenticateToken, async (req, res) => {
  try {
    const chats = await Chat.find({
      participants: req.user.userId
    })
    .populate('participants', 'name avatar verified lastActive')
    .sort({ lastMessage: -1 });

    res.json(chats);
  } catch (error) {
    console.error('Chats fetch error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Create new chat
app.post('/api/chats', authenticateToken, async (req, res) => {
  try {
    const { participantId } = req.body;

    // Check if chat already exists
    let chat = await Chat.findOne({
      participants: { $all: [req.user.userId, participantId] }
    });

    if (!chat) {
      chat = new Chat({
        participants: [req.user.userId, participantId]
      });
      await chat.save();
    }

    await chat.populate('participants', 'name avatar verified');
    res.json(chat);
  } catch (error) {
    console.error('Chat creation error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// =============================================================================
// SOCKET.IO REAL-TIME MESSAGING
// =============================================================================

io.on('connection', (socket) => {
  console.log('🔌 User connected:', socket.id);

  // Join a specific chat room
  socket.on('join-chat', (chatId) => {
    socket.join(chatId);
    console.log(`User ${socket.id} joined chat ${chatId}`);
  });

  // Handle sending messages
  socket.on('send-message', async (data) => {
    try {
      const { chatId, content, senderId } = data;

      // Find the chat and verify user is participant
      const chat = await Chat.findById(chatId);
      if (!chat || !chat.participants.includes(senderId)) {
        return;
      }

      // Create new message
      const message = {
        sender: senderId,
        content,
        createdAt: new Date()
      };

      // Add message to chat
      chat.messages.push(message);
      chat.lastMessage = new Date();
      await chat.save();

      // Populate sender details
      await chat.populate('messages.sender', 'name avatar verified');
      const newMessage = chat.messages[chat.messages.length - 1];

      // Emit message to all users in the chat room
      io.to(chatId).emit('new-message', newMessage);

    } catch (error) {
      console.error('Message send error:', error);
    }
  });

  // Handle user disconnect
  socket.on('disconnect', () => {
    console.log('🔌 User disconnected:', socket.id);
  });
});

// =============================================================================
// UTILITY ROUTES
// =============================================================================

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    message: 'SickoScoop API is running!',
    timestamp: new Date().toISOString() 
  });
});

// Welcome message for root route
app.get('/', (req, res) => {
  res.json({
    message: 'Welcome to SickoScoop API!',
    version: '1.0.0',
    endpoints: {
      health: '/api/health',
      auth: '/api/auth/login, /api/auth/signup',
      posts: '/api/posts',
      chats: '/api/chats',
      user: '/api/user/profile'
    }
  });
});

// =============================================================================
// ERROR HANDLING
// =============================================================================

// Global error handling middleware
app.use((err, req, res, next) => {
  console.error('❌ Server Error:', err.stack);
  res.status(500).json({ 
    error: 'Something went wrong!',
    message: process.env.NODE_ENV === 'development' ? err.message : 'Internal server error'
  });
});

// Handle 404 routes
app.use('*', (req, res) => {
  res.status(404).json({ 
    error: 'Route not found',
    message: `Cannot ${req.method} ${req.originalUrl}`
  });
});

// =============================================================================
// START SERVER
// =============================================================================

const PORT = process.env.PORT || 5000;

server.listen(PORT, () => {
  console.log(`🚀 SickoScoop server running on port ${PORT}`);
  console.log(`📊 Health check: http://localhost:${PORT}/api/health`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
});