require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const http = require('http');
const { Server } = require('socket.io');
const fs = require('fs');

const app = express();
const server = http.createServer(app);

const ALLOWED_ORIGINS = [
  'http://localhost:3000',
  process.env.FRONTEND_URL
].filter(Boolean);

app.use(cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true);
    cb(null, ALLOWED_ORIGINS.includes(origin));
  },
  credentials: true
}));

const io = new Server(server, {
  cors: {
    origin: [process.env.FRONTEND_URL || 'http://localhost:3000'],
    methods: ['GET', 'POST'],
    credentials: true
  }
});

io.use((socket, next) => {
  try {
    const token =
      socket.handshake.auth?.token ||
      (socket.handshake.headers?.authorization || '').replace('Bearer ', '') ||
      socket.handshake.query?.token;
    if (!token) return next(new Error('No auth'));
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    socket.userId = decoded.userId;
    next();
  } catch (e) {
    next(new Error('Bad auth'));
  }
});

io.on('connection', (socket) => {
  const userId = socket.userId;
  socket.join(`user:${userId}`);

  socket.on('chat:send', async (payload, cb) => {
    try {
      const { toUserId, text } = payload || {};
      if (!toUserId || !text?.trim()) return cb?.({ ok: false, error: 'Invalid payload' });

      let convo = await Conversation.findOne({
        participants: { $all: [userId, toUserId], $size: 2 }
      });

      if (!convo) {
        convo = await Conversation.create({
          participants: [userId, toUserId],
          lastMessageAt: new Date(),
          unread: { [toUserId]: 1, [userId]: 0 }
        });
      }

      const msg = await Message.create({
        conversation: convo._id,
        from: userId,
        to: toUserId,
        text: text.trim()
      });

      convo.lastMessage = msg._id;
      convo.lastMessageAt = msg.createdAt;

      if (convo.unread?.set) {
        convo.unread.set(String(toUserId), (convo.unread.get(String(toUserId)) || 0) + 1);
      } else {
        convo.unread = convo.unread || {};
        convo.unread[toUserId] = (convo.unread[toUserId] || 0) + 1;
      }

      await convo.save();

      const out = {
        _id: msg._id,
        conversation: convo._id,
        from: userId,
        to: toUserId,
        text: msg.text,
        createdAt: msg.createdAt,
        read: msg.read
      };

      io.to(`user:${toUserId}`).emit('chat:new', out);
      io.to(`user:${userId}`).emit('chat:new', out);

      cb?.({ ok: true, message: out, conversationId: convo._id });
    } catch (e) {
      cb?.({ ok: false, error: 'Send failed' });
    }
  });

  socket.on('chat:typing', ({ toUserId, typing }) => {
    if (!toUserId) return;
    io.to(`user:${toUserId}`).emit('chat:typing', { fromUserId: userId, typing: !!typing });
  });

  socket.on('chat:read', async ({ conversationId }) => {
    try {
      const convo = await Conversation.findById(conversationId);
      if (!convo) return;

      await Message.updateMany(
        { conversation: conversationId, to: userId, read: false },
        { $set: { read: true, readAt: new Date() } }
      );

      if (convo.unread?.set) {
        convo.unread.set(String(userId), 0);
      } else {
        convo.unread = convo.unread || {};
        convo.unread[userId] = 0;
      }
      await convo.save();

      const others = convo.participants.filter((p) => p.toString() !== userId);
      others.forEach((o) => io.to(`user:${o}`).emit('chat:read', { conversationId, byUserId: userId }));
    } catch {}
  });
});

// Middleware
app.use(cors({
  origin: 'http://localhost:3000',
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/skroll')
  .then(() => console.log('MongoDB connected successfully 🚀'))
  .catch(err => console.error('MongoDB connection error:', err));

// User Schema
const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
    minlength: 3,
    maxlength: 20,
  },
  displayName: {
    type: String,
    required: true,
    trim: true,
    maxlength: 30,
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
  },
  password: {
    type: String,
    required: true,
    minlength: 6,
  },
  avatar: {
    type: String,
    default: null,
  },
  bio: {
    type: String,
    default: 'living my best brain rot era 💀',
    maxlength: 150,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

// Chat models
const conversationSchema = new mongoose.Schema({
  participants: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }],
  lastMessage: { type: mongoose.Schema.Types.ObjectId, ref: 'Message', default: null },
  lastMessageAt: { type: Date, default: Date.now },
  unread: { type: Map, of: Number, default: {} }
}, { timestamps: true });

const messageSchema = new mongoose.Schema({
  conversation: { type: mongoose.Schema.Types.ObjectId, ref: 'Conversation', index: true },
  from: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  to: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  text: { type: String, required: true, trim: true, maxlength: 2000 },
  read: { type: Boolean, default: false },
  readAt: { type: Date }
}, { timestamps: true });

const Conversation = mongoose.model('Conversation', conversationSchema);
const Message = mongoose.model('Message', messageSchema);

const replySchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  text: { type: String, required: true, maxlength: 500 },
  likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  createdAt: { type: Date, default: Date.now }
});

const commentSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  text: { type: String, required: true, maxlength: 500 },
  likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  createdAt: { type: Date, default: Date.now },
  replies: [replySchema]
});

const videoSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  caption: { type: String, maxlength: 200, default: '' },
  videoUrl: { type: String, required: true },
  likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  views: { type: Number, default: 0 },
  comments: [commentSchema],
  createdAt: { type: Date, default: Date.now }
});

// Hash password before saving
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Compare password method
userSchema.methods.comparePassword = async function(password) {
  return await bcrypt.compare(password, this.password);
};

const User = mongoose.model('User', userSchema);
const Video = mongoose.model('Video', videoSchema);

// Auth Middleware
const authMiddleware = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');

  if (!token) {
    return res.status(401).json({ error: 'No token, authorization denied' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Token is not valid' });
  }
};

// Create upload directories
if (!fs.existsSync('uploads')) {
  fs.mkdirSync('uploads');
}
if (!fs.existsSync('avatars')) {
  fs.mkdirSync('avatars');
}

// Serve static files
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use('/avatars', express.static(path.join(__dirname, 'avatars')));

// Multer setup for video uploads
const videoStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  }
});

const videoUpload = multer({ 
  storage: videoStorage,
  limits: {
    fileSize: 50 * 1024 * 1024,
  },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('video/')) {
      cb(null, true);
    } else {
      cb(new Error('Only video files allowed!'), false);
    }
  }
});

// Multer setup for avatar uploads
const avatarStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'avatars/');
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, 'avatar-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const avatarUpload = multer({ 
  storage: avatarStorage,
  limits: {
    fileSize: 5 * 1024 * 1024,
  },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image files allowed!'), false);
    }
  }
});

// Test route
app.get('/api/test', (req, res) => {
  res.json({ message: 'Server is vibing 🔥' });
});

// AUTH ROUTES
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { username, email, password, displayName } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ 
        error: 'all fields required bestie 💀' 
      });
    }

    const existingUser = await User.findOne({ 
      $or: [{ email }, { username }] 
    });
    
    if (existingUser) {
      return res.status(400).json({ 
        error: existingUser.email === email 
          ? 'email already taken bestie 💀' 
          : 'username already exists, be original fr'
      });
    }

    const user = new User({ 
      username, 
      email, 
      password,
      displayName: displayName || username
    });
    await user.save();

    const token = jwt.sign(
      { userId: user._id }, 
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.status(201).json({
      message: 'welcome to the chaos 🔥',
      token,
      user: {
        id: user._id,
        username: user.username,
        displayName: user.displayName,
        email: user.email,
        avatar: user.avatar,
        bio: user.bio,
      }
    });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ error: 'server said no 😭' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ 
        error: 'email and password required fr' 
      });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ error: 'who dis? email not found 🤔' });
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(400).json({ error: 'wrong password bestie 🚫' });
    }

    const token = jwt.sign(
      { userId: user._id }, 
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      message: 'ur back! lets gooo 🚀',
      token,
      user: {
        id: user._id,
        username: user.username,
        displayName: user.displayName,
        email: user.email,
        avatar: user.avatar,
        bio: user.bio,
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'server is not vibing rn 💀' });
  }
});

app.get('/api/auth/me', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('-password');
    res.json({
      id: user._id,
      username: user.username,
      displayName: user.displayName,
      email: user.email,
      avatar: user.avatar,
      bio: user.bio,
    });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ error: 'could not find u 😭' });
  }
});

// Get profile by username (moved off /api/users to avoid collisions)
app.get('/api/profiles/:username', authMiddleware, async (req, res) => {
  try {
    const uname = req.params.username.toLowerCase().trim();
    const user = await User.findOne({ username: uname })
      .select('username displayName bio avatar createdAt');

    if (!user) return res.status(404).json({ error: 'User not found' });

    return res.json({
      user: {
        id: user._id,
        username: user.username,
        displayName: user.displayName,
        bio: user.bio,
        avatar: user.avatar,
        createdAt: user.createdAt
      },
      isOwnProfile: user._id.toString() === req.userId
    });
  } catch (err) {
    console.error('Get user by username error:', err);
    return res.status(500).json({ error: 'Could not fetch profile' });
  }
});

app.put('/api/auth/profile', authMiddleware, avatarUpload.single('avatar'), async (req, res) => {
  try {
    const { username, displayName, bio } = req.body;
    const userId = req.userId;

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (username && username !== user.username) {
      const existingUser = await User.findOne({ username });
      if (existingUser) {
        return res.status(400).json({ error: 'Username already taken' });
      }
    }

    if (username) user.username = username;
    if (displayName) user.displayName = displayName;
    if (bio !== undefined) user.bio = bio;

    if (req.file) {
      if (user.avatar && user.avatar !== '/avatars/default.png') {
        const oldPath = path.join(__dirname, user.avatar.replace('/', ''));
        if (fs.existsSync(oldPath)) {
          fs.unlinkSync(oldPath);
        }
      }
      user.avatar = `/avatars/${req.file.filename}`;
    }

    await user.save();

    res.json({
      message: 'Profile updated successfully! 🔥',
      user: {
        id: user._id,
        username: user.username,
        displayName: user.displayName,
        email: user.email,
        avatar: user.avatar,
        bio: user.bio,
      }
    });
  } catch (error) {
    console.error('Profile update error:', error);
    res.status(500).json({ error: 'Could not update profile 😭' });
  }
});

// USER STATS ROUTES

// Get user's videos by userId
app.get('/api/users/:userId/videos', authMiddleware, async (req, res) => {
  try {
    const videos = await Video.find({ user: req.params.userId })
      .populate('user', 'username displayName avatar')
      .sort({ createdAt: -1 })
      .lean();

    const enriched = videos.map(v => ({
      ...v,
      isLikedByUser: Array.isArray(v.likes) && v.likes.some(id => id.toString() === req.userId)
    }));

    return res.json(enriched);
  } catch (err) {
    console.error('Get user videos error:', err);
    return res.status(500).json({ error: 'Could not fetch user videos' });
  }
});

// Get current user's videos
app.get('/api/users/videos/me', authMiddleware, async (req, res) => {
  try {
    const videos = await Video.find({ user: req.userId })
      .populate('user', 'username displayName avatar')
      .sort({ createdAt: -1 })
      .lean();

    const enriched = videos.map(v => ({
      ...v,
      isLikedByUser: Array.isArray(v.likes) && v.likes.some(id => id.toString() === req.userId)
    }));

    return res.json(enriched);
  } catch (err) {
    console.error('Get my videos error:', err);
    return res.status(500).json({ error: 'Could not fetch your videos' });
  }
});

// Track video view - Updated to exclude own videos
app.post('/api/videos/:id/view', authMiddleware, async (req, res) => {
  try {
    // First get the video to check ownership
    const video = await Video.findById(req.params.id);
    
    if (!video) {
      return res.status(404).json({ error: 'Video not found' });
    }
    
    // Don't count view if it's the user's own video
    if (video.user.toString() === req.userId) {
      return res.json({ 
        views: video.views, 
        message: 'Own video view not counted' 
      });
    }
    
    // Increment view count for other users' videos
    video.views = (video.views || 0) + 1;
    await video.save();
    
    res.json({ views: video.views });
  } catch (error) {
    console.error('View tracking error:', error);
    res.status(500).json({ error: 'Could not track view' });
  }
});



// Get all videos (feed) with proper populates
app.get('/api/videos/feed', authMiddleware, async (req, res) => {
  try {
    const videos = await Video.find()
      .populate({ path: 'user', select: 'username displayName bio avatar' })
      .populate({ path: 'comments.user', select: 'username displayName avatar' })
      .populate({ path: 'comments.replies.user', select: 'username displayName avatar' })
      .sort({ createdAt: -1 })
      .limit(20)
      .lean();

    const withFlags = videos.map(v => ({
      ...v,
      isLikedByUser: Array.isArray(v.likes) && v.likes.some(id => id.toString() === req.userId)
    }));

    res.json(withFlags);
  } catch (error) {
    console.error('Feed fetch error:', error);
    res.status(500).json({ error: 'Could not fetch feed' });
  }
});

app.get('/api/users/stats', authMiddleware, async (req, res) => {
  try {
    const targetUserId = req.userId;

    const videoStats = await Video.aggregate([
      { $match: { user: new mongoose.Types.ObjectId(targetUserId) } },
      {
        $group: {
          _id: null,
          videoCount: { $sum: 1 },
          totalLikes: { $sum: { $size: '$likes' } },
          totalComments: { $sum: { $size: '$comments' } }
        }
      }
    ]);

    const stats = videoStats[0] || { videoCount: 0, totalLikes: 0, totalComments: 0 };

    const user = await User.findById(targetUserId)
      .select('username displayName bio avatar createdAt');
    if (!user) return res.status(404).json({ error: 'User not found' });

    const accountAgeDays = Math.floor((Date.now() - new Date(user.createdAt)) / (1000 * 60 * 60 * 24));

    return res.json({
      user: {
        id: user._id,
        username: user.username,
        displayName: user.displayName,
        bio: user.bio,
        avatar: user.avatar,
        accountAgeDays
      },
      stats: {
        videoCount: stats.videoCount,
        totalLikes: stats.totalLikes,
        totalComments: stats.totalComments,
        avgLikesPerVideo: stats.videoCount > 0
          ? Math.round((stats.totalLikes / stats.videoCount) * 10) / 10
          : 0
      }
    });
  } catch (err) {
    console.error('User stats error:', err);
    return res.status(500).json({ error: 'Could not fetch user stats' });
  }
});

app.get('/api/users/stats/:userId', authMiddleware, async (req, res) => {
  try {
    const targetUserId = req.params.userId;

    const videoStats = await Video.aggregate([
      { $match: { user: new mongoose.Types.ObjectId(targetUserId) } },
      {
        $group: {
          _id: null,
          videoCount: { $sum: 1 },
          totalLikes: { $sum: { $size: '$likes' } },
          totalComments: { $sum: { $size: '$comments' } }
        }
      }
    ]);

    const stats = videoStats[0] || { videoCount: 0, totalLikes: 0, totalComments: 0 };

    const user = await User.findById(targetUserId)
      .select('username displayName bio avatar createdAt');
    if (!user) return res.status(404).json({ error: 'User not found' });

    const accountAgeDays = Math.floor((Date.now() - new Date(user.createdAt)) / (1000 * 60 * 60 * 24));

    return res.json({
      user: {
        id: user._id,
        username: user.username,
        displayName: user.displayName,
        bio: user.bio,
        avatar: user.avatar,
        accountAgeDays
      },
      stats: {
        videoCount: stats.videoCount,
        totalLikes: stats.totalLikes,
        totalComments: stats.totalComments,
        avgLikesPerVideo: stats.videoCount > 0
          ? Math.round((stats.totalLikes / stats.videoCount) * 10) / 10
          : 0
      }
    });
  } catch (err) {
    console.error('User stats (by id) error:', err);
    return res.status(500).json({ error: 'Could not fetch user stats' });
  }
});

// VIDEO ROUTES
app.get('/api/videos/:id', authMiddleware, async (req, res) => {
  try {
    const video = await Video.findById(req.params.id)
      .populate({ path: 'user', select: 'username displayName bio avatar' })
      .populate({ path: 'comments.user', select: 'username displayName avatar' })
      .populate({ path: 'comments.replies.user', select: 'username displayName avatar' })
      .lean();

    if (!video) return res.status(404).json({ error: 'Video not found' });

    video.isLikedByUser = Array.isArray(video.likes) && video.likes.some(id => id.toString() === req.userId);
    res.json(video);
  } catch (e) {
    console.error('Get video error:', e);
    res.status(500).json({ error: 'Could not fetch video' });
  }
});

// Add a top‑level comment
app.post('/api/videos/:id/comment', authMiddleware, async (req, res) => {
  try {
    const { text } = req.body;
    if (!text || !text.trim()) return res.status(400).json({ error: 'Text required' });

    const v = await Video.findById(req.params.id);
    if (!v) return res.status(404).json({ error: 'Video not found' });

    v.comments.push({ user: req.userId, text: text.trim(), likes: [], replies: [] });
    await v.save();

    const last = v.comments[v.comments.length - 1];
    const populated = await Video.findOne({ _id: v._id, 'comments._id': last._id }, { 'comments.$': 1 })
      .populate({ path: 'comments.user', select: 'username displayName avatar' })
      .lean();

    const c = populated.comments[0];
    return res.status(201).json({
      ...c,
      isLikedByUser: false,
      likesCount: 0,
      isOwn: true,
      replies: []
    });
  } catch (e) {
    console.error('Add comment error:', e);
    return res.status(500).json({ error: 'Could not add comment' });
  }
});

// Get comments (threaded) for a video
app.get('/api/videos/:id/comments', authMiddleware, async (req, res) => {
  try {
    const v = await Video.findById(req.params.id)
      .populate({ path: 'comments.user', select: 'username displayName avatar' })
      .populate({ path: 'comments.replies.user', select: 'username displayName avatar' })
      .lean();

    if (!v) return res.status(404).json({ error: 'Video not found' });

    const comments = (v.comments || [])
      .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
      .map(c => ({
        ...c,
        isLikedByUser: Array.isArray(c.likes) && c.likes.some(id => id.toString() === req.userId),
        likesCount: Array.isArray(c.likes) ? c.likes.length : 0,
        isOwn: c?.user?._id?.toString() === req.userId,
        replies: (c.replies || []).map(r => ({
          ...r,
          isLikedByUser: Array.isArray(r.likes) && r.likes.some(id => id.toString() === req.userId),
          likesCount: Array.isArray(r.likes) ? r.likes.length : 0,
          isOwn: r?.user?._id?.toString() === req.userId
        }))
      }));

    return res.json({ count: comments.length, comments });
  } catch (e) {
    console.error('Get comments error:', e);
    return res.status(500).json({ error: 'Could not fetch comments' });
  }
});

// Reply to a comment
app.post('/api/videos/:id/comments/:commentId/reply', authMiddleware, async (req, res) => {
  try {
    const { text } = req.body;
    if (!text || !text.trim()) return res.status(400).json({ error: 'Text required' });

    const v = await Video.findById(req.params.id);
    if (!v) return res.status(404).json({ error: 'Video not found' });

    const c = v.comments.id(req.params.commentId);
    if (!c) return res.status(404).json({ error: 'Comment not found' });

    c.replies.push({ user: req.userId, text: text.trim(), likes: [] });
    await v.save();

    const newReply = c.replies[c.replies.length - 1];

    // Populate the reply
    const populated = await Video.findOne(
      { _id: v._id, 'comments._id': c._id },
      { 'comments.$': 1 }
    )
      .populate('comments.replies.user', 'username displayName avatar')
      .lean();

    const fullComment = populated.comments[0];
    const pr = fullComment.replies.find(r => r._id.toString() === newReply._id.toString());

    res.status(201).json({
      ...pr,
      isLikedByUser: false,
      likesCount: 0,
      isOwn: true
    });
  } catch (e) {
    console.error('Reply error:', e);
    res.status(500).json({ error: 'Could not add reply' });
  }
});

// Like/unlike a comment
app.post('/api/videos/:id/comments/:commentId/like', authMiddleware, async (req, res) => {
  try {
    const v = await Video.findById(req.params.id);
    if (!v) return res.status(404).json({ error: 'Video not found' });

    const c = v.comments.id(req.params.commentId);
    if (!c) return res.status(404).json({ error: 'Comment not found' });

    const idx = c.likes.findIndex(uid => uid.toString() === req.userId);
    if (idx > -1) c.likes.splice(idx, 1);
    else c.likes.push(req.userId);

    await v.save();
    res.json({ likes: c.likes.length, isLiked: idx === -1 });
  } catch (e) {
    console.error('Comment like error:', e);
    res.status(500).json({ error: 'Could not like comment' });
  }
});

// Like/unlike a reply
app.post('/api/videos/:id/comments/:commentId/replies/:replyId/like', authMiddleware, async (req, res) => {
  try {
    const v = await Video.findById(req.params.id);
    if (!v) return res.status(404).json({ error: 'Video not found' });

    const c = v.comments.id(req.params.commentId);
    if (!c) return res.status(404).json({ error: 'Comment not found' });

    const r = c.replies.id(req.params.replyId);
    if (!r) return res.status(404).json({ error: 'Reply not found' });

    const idx = r.likes.findIndex(uid => uid.toString() === req.userId);
    if (idx > -1) r.likes.splice(idx, 1);
    else r.likes.push(req.userId);

    await v.save();
    res.json({ likes: r.likes.length, isLiked: idx === -1 });
  } catch (e) {
    console.error('Reply like error:', e);
    res.status(500).json({ error: 'Could not like reply' });
  }
});

app.post('/api/videos/upload', authMiddleware, videoUpload.single('video'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No video file uploaded 😭' });
    }

    const { caption } = req.body;
    const videoUrl = `/uploads/${req.file.filename}`;

    const video = new Video({
      user: req.userId,
      caption: caption || '',
      videoUrl: videoUrl,
    });

    await video.save();
    await video.populate('user', 'username displayName bio avatar');

    res.status(201).json({
      message: 'Video uploaded successfully! chaos unleashed 🔥',
      video: video,
    });
  } catch (error) {
    console.error('Video upload error:', error);
    res.status(500).json({ error: 'Upload failed fr 💀' });
  }
});

app.get('/api/videos/feed', authMiddleware, async (req, res) => {
  try {
    const videos = await Video.find()
      .populate('user', 'username displayName bio avatar')
      .populate('comments.user', 'username displayName avatar')
      .sort({ createdAt: -1 })
      .limit(20);

    res.json(videos);
  } catch (error) {
    console.error('Feed fetch error:', error);
    res.status(500).json({ error: 'Could not fetch feed 😭' });
  }
});

app.post('/api/videos/:id/like', authMiddleware, async (req, res) => {
  try {
    const video = await Video.findById(req.params.id);
    if (!video) {
      return res.status(404).json({ error: 'Video not found 🤷‍♀️' });
    }

    const userIndex = video.likes.indexOf(req.userId);
    if (userIndex > -1) {
      video.likes.splice(userIndex, 1);
    } else {
      video.likes.push(req.userId);
    }

    await video.save();
    res.json({ likes: video.likes.length, isLiked: userIndex === -1 });
  } catch (error) {
    console.error('Like error:', error);
    res.status(500).json({ error: 'Could not process like 💔' });
  }
});

app.post('/api/videos/:id/comment', authMiddleware, async (req, res) => {
  try {
    const { text } = req.body;
    if (!text) {
      return res.status(400).json({ error: 'Comment text required' });
    }

    const video = await Video.findById(req.params.id);
    if (!video) {
      return res.status(404).json({ error: 'Video not found 🤷‍♀️' });
    }

    video.comments.push({
      user: req.userId,
      text: text,
    });

    await video.save();
    await video.populate('comments.user', 'username displayName');

    res.json({ 
      message: 'Comment added successfully! 💬',
      comments: video.comments 
    });
  } catch (error) {
    console.error('Comment error:', error);
    res.status(500).json({ error: 'Could not add comment 😭' });
  }
});

// Get shareable video link
app.get('/api/videos/share/:id', async (req, res) => {
  try {
    const video = await Video.findById(req.params.id)
      .populate('user', 'username displayName')
      .select('caption user createdAt');
    
    if (!video) {
      return res.status(404).json({ error: 'Video not found' });
    }

    // Generate shareable link
    const shareLink = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/video/${req.params.id}`;
    
    res.json({
      link: shareLink,
      video: {
        id: video._id,
        caption: video.caption,
        username: video.user.username,
        displayName: video.user.displayName
      }
    });
  } catch (error) {
    console.error('Share link error:', error);
    res.status(500).json({ error: 'Could not generate share link' });
  }
});

// Get single video details
app.get('/api/videos/:id', authMiddleware, async (req, res) => {
  try {
    const video = await Video.findById(req.params.id)
      .populate('user', 'username displayName bio avatar')
      .populate('comments.user', 'username displayName avatar')
      .lean();

    if (!video) {
      return res.status(404).json({ error: 'Video not found' });
    }

    // Add isLikedByUser field
    video.isLikedByUser = video.likes.some(likeId => likeId.toString() === req.userId);

    res.json(video);
  } catch (error) {
    console.error('Get video error:', error);
    res.status(500).json({ error: 'Could not fetch video' });
  }
});

// SEARCH ROUTES
app.get('/api/search/users', authMiddleware, async (req, res) => {
  try {
    const { q } = req.query;
    if (!q) {
      return res.status(400).json({ error: 'Search query required' });
    }

    const users = await User.find({
      $and: [
        {
          $or: [
            { username: { $regex: q, $options: 'i' } },
            { displayName: { $regex: q, $options: 'i' } }
          ]
        },
        { _id: { $ne: req.userId } }
      ]
    }).select('username displayName bio avatar').limit(10);

    res.json(users);
  } catch (error) {
    console.error('Search users error:', error);
    res.status(500).json({ error: 'Search failed 😭' });
  }
});

// Search videos - include isLikedByUser in results
app.get('/api/search/videos', authMiddleware, async (req, res) => {
  try {
    const { q, includeOwn } = req.query;
    if (!q) return res.status(400).json({ error: 'Search query required' });

    const findQuery = {
      $or: [{ caption: { $regex: q, $options: 'i' } }]
    };
    if (includeOwn !== 'true') {
      findQuery.user = { $ne: req.userId };
    }

    const videos = await Video.find(findQuery)
      .populate('user', 'username displayName bio avatar')
      .sort({ createdAt: -1 })
      .limit(20)
      .lean();

    const enriched = videos.map(v => ({
      ...v,
      isLikedByUser: Array.isArray(v.likes) && v.likes.some(id => id.toString() === req.userId)
    }));

    res.json(enriched);
  } catch (error) {
    console.error('Search videos error:', error);
    res.status(500).json({ error: 'Video search failed' });
  }
});

// LEADERBOARD ROUTES
app.get('/api/leaderboard', authMiddleware, async (req, res) => {
  try {
    const leaderboard = await Video.aggregate([
      {
        $group: {
          _id: '$user',
          totalLikes: { $sum: { $size: '$likes' } },
          videoCount: { $sum: 1 },
          avgLikesPerVideo: { $avg: { $size: '$likes' } }
        }
      },
      {
        $lookup: {
          from: 'users',
          localField: '_id',
          foreignField: '_id',
          as: 'userInfo'
        }
      },
      {
        $unwind: '$userInfo'
      },
      {
        $project: {
          _id: 1,
          totalLikes: 1,
          videoCount: 1,
          avgLikesPerVideo: { $round: ['$avgLikesPerVideo', 1] },
          username: '$userInfo.username',
          displayName: '$userInfo.displayName',
          avatar: '$userInfo.avatar',
          bio: '$userInfo.bio'
        }
      },
      {
        $sort: { totalLikes: -1 }
      },
      {
        $limit: 50
      }
    ]);

    const rankedLeaderboard = leaderboard.map((user, index) => ({
      ...user,
      rank: index + 1
    }));

    res.json(rankedLeaderboard);
  } catch (error) {
    console.error('Leaderboard error:', error);
    res.status(500).json({ error: 'Could not fetch leaderboard 😭' });
  }
});

app.get('/api/leaderboard/my-rank', authMiddleware, async (req, res) => {
  try {
    const leaderboard = await Video.aggregate([
      {
        $group: {
          _id: '$user',
          totalLikes: { $sum: { $size: '$likes' } },
          videoCount: { $sum: 1 }
        }
      },
      {
        $sort: { totalLikes: -1 }
      }
    ]);

    const userRank = leaderboard.findIndex(user => user._id.toString() === req.userId) + 1;
    const userStats = leaderboard.find(user => user._id.toString() === req.userId);

    res.json({
      rank: userRank || null,
      totalLikes: userStats?.totalLikes || 0,
      videoCount: userStats?.videoCount || 0
    });
  } catch (error) {
    console.error('User rank error:', error);
    res.status(500).json({ error: 'Could not fetch your rank 😭' });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ error: 'File too large! 📁💀' });
    }
  }
  
  if (err.message === 'Only video files allowed!' || err.message === 'Only image files allowed!') {
    return res.status(400).json({ error: err.message });
  }
  
  console.error(err.stack);
  res.status(500).json({ error: 'Something broke! 💀' });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Route not found 🤷‍♀️' });
});

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📱 Frontend should connect to: http://localhost:${PORT}`);
  console.log(`📂 Video uploads: /uploads`);
  console.log(`🖼️ Avatar uploads: /avatars`);
});