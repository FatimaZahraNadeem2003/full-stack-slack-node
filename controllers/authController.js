const User = require('../models/User');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');


const registerUser = async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ message: 'Username, email, and password are required' });
    }

    // Check if any users exist - if not, first user becomes admin
    const existingUsers = await User.countDocuments();
    const isAdmin = existingUsers === 0; // First user is admin

    const existingUser = await User.findOne({
      $or: [{ email }, { username }]
    });
    if (existingUser) {
      return res.status(409).json({ message: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      username,
      email,
      password: hashedPassword,
      role: isAdmin ? 'admin' : 'user' // Set role based on whether they're the first user
    });

    await newUser.save();

    const token = jwt.sign(
      { 
        userId: newUser._id, 
        username: newUser.username, 
        email: newUser.email,
        role: newUser.role  // Include role in token
      },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    const userResponse = {
      id: newUser._id,
      username: newUser.username,
      email: newUser.email,
      role: newUser.role,
      avatar: newUser.avatar,
      isActive: newUser.isActive,
      lastSeen: newUser.lastSeen,
      createdAt: newUser.createdAt,
      updatedAt: newUser.updatedAt
    };
    
    res.status(201).json({
      message: isAdmin ? 'Admin registered successfully' : 'User registered successfully',
      token,
      user: userResponse
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
};


const loginUser = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    
    user.lastSeen = new Date();
    await user.save();

    const token = jwt.sign(
      { 
        userId: user._id, 
        username: user.username, 
        email: user.email,
        role: user.role  // Include role in token
      },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    const userResponse = {
      id: user._id,
      username: user.username,
      email: user.email,
      role: user.role,
      avatar: user.avatar,
      isActive: user.isActive,
      lastSeen: user.lastSeen,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt
    };
    
    res.json({
      message: 'Login successful',
      token,
      user: userResponse
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
};


const checkAdmin = async (req, res) => {
  try {
    const userCount = await User.countDocuments();
    res.json({ 
      hasAdmin: userCount > 0,
      userCount: userCount
    });
  } catch (error) {
    console.error('Error checking admin status:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
};

module.exports = {
  registerUser,
  loginUser,
  checkAdmin
};