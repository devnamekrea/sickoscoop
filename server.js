// server.js - Main server file
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const { createServer } = require('http');
const { Server } = require('socket.io');
require('dotenv').config();

const app = express();
const server = createServer(app);
const io = new Server(server, {
  cors: {
    origin: process.env.FRONTEND_URL || "https://68396333bc5b92e8e2b1d6a9--sickoscoop.netlify.app",
    methods: ["GET", "POST"]
  }
});

// ===== MIDDLEWARE =====
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '10mb' }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use('/api/', limiter);

// ===== DATABASE MODELS =====

// User Schema
const userSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
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
  transparencyScore: { type: Number, default: 100, min: 0, max: 100 },
  lastActive: { type: Date, default: Date.now },
  createdAt: { type: Date, default: Date.now }
});

// Post Schema
const postSchema = new mongoose.Schema({
  author: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  content: { type: String, required: true, maxlength: 2000 },
  images: [{ type: String }],
  likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  comments: [{
    author: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
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
  createdAt: { type: Date, default: Date.now }
});

// Message Schema
const messageSchema = new mongoose.Schema({
  sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  recipient: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, // null for public chat
  content: { type: String, required: true, maxlength: 1000 },
  chatRoom: { type: String, default: 'public' },
  isEdited: { type: Boolean, default: false },
  editHistory: [{
    content: String,
    editedAt: { type: Date, default: Date.now }
  }],
  readBy: [{
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    readAt: { type: Date, default: Date.now }
  }],
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
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    console.log('🔍 Token verified successfully:', decoded);
    
    const user = await User.findById(decoded.userId).select('-password');
    console.log('🔍 User found:', !!user);
    
    if (!user) {
      return res.status(401).json({ message: 'User not found' });
    }
    
    req.user = user;
    next();
  } catch (error) {
    console.error('🚨 JWT VERIFICATION ERROR:', error.name, error.message);
    return res.status(403).json({ message: 'Invalid or expired token' });
  }
};

// ===== AUTHENTICATION ROUTES =====

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Validation
    if (!name || !email || !password) {
      return res.status(400).json({ message: 'All fields are required' });
    }

    if (password.length < 6) {
      return res.status(400).json({ message: 'Password must be at least 6 characters' });
    }

    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists with this email' });
    }

    // Hash password
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Create user
    const user = new User({
      name,
      email,
      password: hashedPassword
    });

    await user.save();

    // Generate JWT
    const token = jwt.sign(
      { userId: user._id }, 
      process.env.JWT_SECRET, 
      { expiresIn: '7d' }
    );

    res.status(201).json({
      message: 'User created successfully',
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        avatar: user.avatar,
        bio: user.bio,
        verified: user.verified,
        transparencyScore: user.transparencyScore
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ message: 'Server error during registration' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
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
      { userId: user._id }, 
      process.env.JWT_SECRET, 
      { expiresIn: '7d' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        avatar: user.avatar,
        bio: user.bio,
        verified: user.verified,
        transparencyScore: user.transparencyScore,
        followers: user.followers.length,
        following: user.following.length
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error during login' });
  }
});

// Get current user
app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user._id)
      .populate('followers', 'name avatar verified')
      .populate('following', 'name avatar verified')
      .select('-password');

    res.json({
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        avatar: user.avatar,
        bio: user.bio,
        verified: user.verified,
        transparencyScore: user.transparencyScore,
        followers: user.followers,
        following: user.following,
        isPrivate: user.isPrivate,
        createdAt: user.createdAt
      }
    });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// ===== USER ROUTES =====

// Get user profile
app.get('/api/users/:userId', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.params.userId)
      .populate('followers', 'name avatar verified')
      .populate('following', 'name avatar verified')
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
    const { name, bio, avatar, isPrivate } = req.body;
    
    const updates = {};
    if (name) updates.name = name;
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

// ===== POST ROUTES =====

// Get posts (feed)
app.get('/api/posts', authenticateToken, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    // Get posts from non-blocked users
    const posts = await Post.find({
      author: { $nin: req.user.blockedUsers },
      visibility: { $in: ['public', 'followers'] }
    })
    .populate('author', 'name avatar verified transparencyScore')
    .populate('comments.author', 'name avatar verified')
    .sort({ createdAt: -1 })
    .skip(skip)
    .limit(limit);

    res.json({ posts, page, hasMore: posts.length === limit });
  } catch (error) {
    console.error('Get posts error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Create post
app.post('/api/posts', authenticateToken, async (req, res) => {
  try {
    const { content, images, visibility = 'public' } = req.body;

    if (!content || content.trim().length === 0) {
      return res.status(400).json({ message: 'Post content is required' });
    }

    const post = new Post({
      author: req.user._id,
      content: content.trim(),
      images: images || [],
      visibility
    });

    await post.save();
    
    const populatedPost = await Post.findById(post._id)
      .populate('author', 'name avatar verified transparencyScore');

    // Emit to Socket.IO for real-time updates
    io.emit('new_post', populatedPost);

    res.status(201).json({ message: 'Post created successfully', post: populatedPost });
  } catch (error) {
    console.error('Create post error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Like/Unlike post
app.post('/api/posts/:postId/like', authenticateToken, async (req, res) => {
  try {
    const post = await Post.findById(req.params.postId);
    if (!post) {
      return res.status(404).json({ message: 'Post not found' });
    }

    const isLiked = post.likes.includes(req.user._id);
    
    if (isLiked) {
      post.likes.pull(req.user._id);
    } else {
      post.likes.push(req.user._id);
    }

    await post.save();

    res.json({ 
      message: isLiked ? 'Post unliked' : 'Post liked',
      isLiked: !isLiked,
      likesCount: post.likes.length 
    });
  } catch (error) {
    console.error('Like post error:', error);
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
      author: req.user._id,
      content: content.trim()
    };

    post.comments.push(comment);
    await post.save();

    const populatedPost = await Post.findById(post._id)
      .populate('comments.author', 'name avatar verified');

    res.status(201).json({ 
      message: 'Comment added successfully', 
      comment: populatedPost.comments[populatedPost.comments.length - 1] 
    });
  } catch (error) {
    console.error('Add comment error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// ===== CHAT/MESSAGE ROUTES =====

// Get messages
app.get('/api/messages', authenticateToken, async (req, res) => {
  try {
    const { chatRoom = 'public', limit = 50 } = req.query;
    
    let query = { chatRoom };
    
    // For private messages, include messages where user is sender or recipient
    if (chatRoom !== 'public') {
      query = {
        $or: [
          { sender: req.user._id, recipient: chatRoom },
          { sender: chatRoom, recipient: req.user._id }
        ]
      };
    }

    const messages = await Message.find(query)
      .populate('sender', 'name avatar verified')
      .populate('recipient', 'name avatar verified')
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
      .populate('sender', 'name avatar verified')
      .populate('recipient', 'name avatar verified');

    // Emit to Socket.IO for real-time chat
    io.emit('new_message', populatedMessage);

    res.status(201).json({ message: 'Message sent successfully', data: populatedMessage });
  } catch (error) {
    console.error('Send message error:', error);
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

//
app.get('/api/debug/jwt', (req, res) => {
  res.json({
    hasJwtSecret: !!process.env.JWT_SECRET,
    jwtSecretLength: process.env.JWT_SECRET ? process.env.JWT_SECRET.length : 0,
    nodeEnv: process.env.NODE_ENV,
    jwtSecretStart: process.env.JWT_SECRET ? process.env.JWT_SECRET.substring(0, 10) + '...' : 'undefined'
  });
});

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

// ===== DATABASE CONNECTION & SERVER START =====
mongoose.connect(process.env.MONGODB_URI)
  .then(() => {
    console.log('Connected to MongoDB');
    const PORT = process.env.PORT || 3001;
    server.listen(PORT, () => {
      console.log(`SickoScoop API server running on port ${PORT}`);
    });
  })
  .catch((error) => {
    console.error('MongoDB connection error:', error);
    process.exit(1);
  });

// ===== ERROR HANDLING =====
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: 'Something went wrong!' });
});

// Handle 404
app.use('*', (req, res) => {
  res.status(404).json({ message: 'API endpoint not found' });
});

module.exports = { app, server, io };