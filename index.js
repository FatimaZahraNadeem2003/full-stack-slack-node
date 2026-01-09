const express = require('express');
const cors = require('cors');
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const connectDB = require('./config/db');

const app = express();
const PORT = process.env.PORT || 5000;

connectDB();

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

app.use(express.json());
app.use(cors());

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

const User = require('./models/User');
const Message = require('./models/Message');
const Space = require('./models/Space');

app.get('/api/health', (req, res) => {
  res.json({ status: 'Backend server is running!' });
});

app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ message: 'Username, email, and password are required' });
    }

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
      password: hashedPassword
    });

    await newUser.save();

    const token = jwt.sign(
      { userId: newUser._id, username: newUser.username, email: newUser.email },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    const userResponse = {
      id: newUser._id,
      username: newUser.username,
      email: newUser.email,
      avatar: newUser.avatar,
      isActive: newUser.isActive,
      lastSeen: newUser.lastSeen,
      createdAt: newUser.createdAt,
      updatedAt: newUser.updatedAt
    };
    
    res.status(201).json({
      message: 'User registered successfully',
      token,
      user: userResponse
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
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
      { userId: user._id, username: user.username, email: user.email },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    const userResponse = {
      id: user._id,
      username: user.username,
      email: user.email,
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
});

app.get('/api/messages', authenticateToken, async (req, res) => {
  try {
    const spaceId = req.query.space || 'general'; 
    
 
    const messages = await Message.find({ space: spaceId })
      .populate('sender', 'username email avatar')
      .populate('space', 'name')
      .sort({ createdAt: -1 })
      .limit(50); 
    
    res.json({
      messages: messages.map(msg => ({
        id: msg._id,
        content: msg.content,
        user: msg.sender.username,
        userId: msg.sender._id,
        spaceId: msg.space._id,
        spaceName: msg.space.name,
        timestamp: msg.createdAt,
        messageType: msg.messageType,
        isEdited: msg.isEdited,
        isDeleted: msg.isDeleted
      }))
    });
  } catch (error) {
    console.error('Error fetching messages:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.post('/api/messages', authenticateToken, async (req, res) => {
  try {
    const { content, spaceId } = req.body;
    const userId = req.user.userId; 
    
    if (!content || !spaceId) {
      return res.status(400).json({ error: 'Content and spaceId are required' });
    }
    
    const space = await Space.findById(spaceId);
    if (!space) {
      return res.status(404).json({ error: 'Space not found' });
    }
    
    const isMember = space.members.some(member => 
      member.user.toString() === userId.toString()
    );
    
    if (!isMember) {
      return res.status(403).json({ error: 'User is not a member of this space' });
    }
    
    const newMessage = new Message({
      content,
      sender: userId,
      space: spaceId,
      messageType: 'text' 
    });
    
    await newMessage.save();
    
    await newMessage.populate('sender', 'username email avatar');
    
    res.status(201).json({
      id: newMessage._id,
      content: newMessage.content,
      user: newMessage.sender.username,
      userId: newMessage.sender._id,
      spaceId: newMessage.space,
      timestamp: newMessage.createdAt,
      messageType: newMessage.messageType,
      isEdited: newMessage.isEdited,
      isDeleted: newMessage.isDeleted
    });
  } catch (error) {
    console.error('Error sending message:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.get('/api/spaces', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    
    const spaces = await Space.find({
      'members.user': userId
    }).populate('members.user', 'username email');
    
    res.json({
      spaces: spaces.map(space => ({
        id: space._id,
        name: space.name,
        description: space.description,
        type: space.type,
        members: space.members.map(member => ({
          id: member.user._id,
          username: member.user.username,
          email: member.user.email,
          role: member.role
        })),
        isArchived: space.isArchived,
        lastActivity: space.lastActivity,
        createdAt: space.createdAt,
        updatedAt: space.updatedAt
      }))
    });
  } catch (error) {
    console.error('Error fetching spaces:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.post('/api/spaces', authenticateToken, async (req, res) => {
  try {
    const { name, description, type } = req.body;
    const userId = req.user.userId;
    
    if (!name) {
      return res.status(400).json({ error: 'Name is required' });
    }
    
    const newSpace = new Space({
      name,
      description,
      type: type || 'public'
    });
    
    const memberInfo = {
      user: userId,
      role: 'admin'
    };
    
    newSpace.members.push(memberInfo);
    newSpace.admins.push(userId);
    
    await newSpace.save();
    
    await newSpace.populate('members.user', 'username email');
    
    res.status(201).json({
      id: newSpace._id,
      name: newSpace.name,
      description: newSpace.description,
      type: newSpace.type,
      members: [{
        id: userId,
        role: 'admin'
      }],
      isArchived: newSpace.isArchived,
      lastActivity: newSpace.lastActivity,
      createdAt: newSpace.createdAt,
      updatedAt: newSpace.updatedAt
    });
  } catch (error) {
    console.error('Error creating space:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.post('/api/spaces/:spaceId/join', authenticateToken, async (req, res) => {
  try {
    const { spaceId } = req.params;
    const userId = req.user.userId;
    
    const space = await Space.findById(spaceId);
    if (!space) {
      return res.status(404).json({ error: 'Space not found' });
    }
    
    const isAlreadyMember = space.members.some(member => 
      member.user.toString() === userId.toString()
    );
    
    if (isAlreadyMember) {
      return res.status(400).json({ error: 'User is already a member of this space' });
    }
    
    space.members.push({
      user: userId,
      role: 'member'
    });
    
    await space.save();
    
    res.json({ message: 'Successfully joined space', spaceId: space._id });
  } catch (error) {
    console.error('Error joining space:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

module.exports = app;