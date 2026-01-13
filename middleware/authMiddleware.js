const jwt = require('jsonwebtoken');
const User = require('../models/User');

const protect = async (req, res, next) => {
  let token;

  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    try {
      token = req.headers.authorization.split(' ')[1];

      // Debug logging to see what's happening
      console.log('JWT Secret in use:', process.env.JWT_SECRET ? 'SET' : 'NOT SET');
      console.log('Token received:', token ? 'PRESENT' : 'MISSING');
      
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      console.log('Token decoded successfully:', decoded);

      req.user = await User.findById(decoded.userId).select('-password');
      req.userRole = decoded.role;

      next();
    } catch (error) {
      console.error('Authentication error:', error);
      console.error('Error name:', error.name);
      console.error('Error message:', error.message);
      return res.status(401).json({ error: 'Not authorized, token failed' });
    }
  }

  if (!token) {
    return res.status(401).json({ error: 'Not authorized, no token' });
  }
};

const adminOnly = async (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Not authorized, no user found' });
  }

  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied, admin only' });
  }

  next();
};

module.exports = { protect, adminOnly };