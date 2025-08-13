const express = require('express');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const authMiddleware = require('../middleware/auth');

const router = express.Router();

// Sign up
router.post('/signup', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // Validate input
    if (!username || !email || !password) {
      return res.status(400).json({ 
        error: 'all fields required bestie 💀' 
      });
    }

    // Check if user exists
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

    // Create new user
    const user = new User({ username, email, password });
    await user.save();

    // Generate token
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
        email: user.email,
        bio: user.bio,
      }
    });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ error: 'server said no 😭' });
  }
});

// Login
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validate input
    if (!email || !password) {
      return res.status(400).json({ 
        error: 'email and password required fr' 
      });
    }

    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ error: 'who dis? email not found 🤔' });
    }

    // Check password
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(400).json({ error: 'wrong password bestie 🚫' });
    }

    // Generate token
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
        email: user.email,
        bio: user.bio,
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'server is not vibing rn 💀' });
  }
});

// Get current user
router.get('/me', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('-password');
    res.json(user);
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ error: 'could not find u 😭' });
  }
});

module.exports = router;