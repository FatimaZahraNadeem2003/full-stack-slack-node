const express = require('express');
const cors = require('cors');
const connectDB = require('./config/db');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

const http = require('http');
const socketIo = require('socket.io');
const { setIO, emitToSpace } = require('./utils/socketHandler');

connectDB();

app.use(express.json());
app.use(cors());

const server = http.createServer(app);

const io = socketIo(server, {
  cors: {
    origin: process.env.NODE_ENV === 'production' ? false : ['http://localhost:3000'],
    methods: ['GET', 'POST']
  }
});

setIO(io);

io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  
  if (!token) {
    return next(new Error('Authentication error'));
  }

  const jwt = require('jsonwebtoken');
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    socket.userId = decoded.id;
    next();
  } catch (err) {
    next(new Error('Invalid token'));
  }
});

io.on('connection', (socket) => {
  console.log('User connected:', socket.userId);

  socket.on('join_spaces', async (spaceIds) => {
    if (Array.isArray(spaceIds)) {
      spaceIds.forEach(spaceId => {
        socket.join(`space_${spaceId}`);
        console.log(`User ${socket.userId} joined space ${spaceId}`);
      });
    }
  });

  socket.on('send_message', async (data) => {
    try {
      const { content, spaceId } = data;
      
      if (!content || !spaceId) {
        socket.emit('error', { message: 'Content and spaceId are required' });
        return;
      }

      const User = require('./models/User');
      const user = await User.findById(socket.userId);
      if (!user) {
        socket.emit('error', { message: 'User not found' });
        return;
      }

      const Space = require('./models/Space');
      const space = await Space.findById(spaceId);
      if (!space) {
        socket.emit('error', { message: 'Space not found' });
        return;
      }

      const isMember = space.members.some(member => 
        member.user.toString() === socket.userId.toString()
      );

      if (!isMember) {
        socket.emit('error', { message: 'User is not a member of this space' });
        return;
      }

      const Message = require('./models/Message');
      const newMessage = new Message({
        content,
        sender: socket.userId,
        space: spaceId,
        messageType: 'text'
      });

      await newMessage.save();
      await newMessage.populate('sender', 'username email avatar');

      const messageData = {
        id: newMessage._id,
        content: newMessage.content,
        user: newMessage.sender.username,
        userId: newMessage.sender._id,
        spaceId: newMessage.space,
        timestamp: newMessage.createdAt,
        messageType: newMessage.messageType,
        isEdited: newMessage.isEdited,
        isDeleted: newMessage.isDeleted
      };

      emitToSpace(spaceId, 'receive_message', messageData);

      socket.emit('message_sent', messageData);
    } catch (error) {
      console.error('Error sending message via socket:', error);
      socket.emit('error', { message: 'Failed to send message' });
    }
  });

  socket.on('disconnect', () => {
    console.log('User disconnected:', socket.userId);
  });
});

app.use('/api/auth', require('./routes/authRoutes'));

const Message = require('./models/Message');
const Space = require('./models/Space');
const { protect } = require('./middleware/authMiddleware');

app.get('/api/health', (req, res) => {
  res.json({ status: 'Backend server is running!' });
});

app.get('/api/messages', protect, async (req, res) => {
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

app.post('/api/messages', protect, async (req, res) => {
  try {
    const { content, spaceId } = req.body;
    const userId = req.user._id; 
    
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
    
    const messageData = {
      id: newMessage._id,
      content: newMessage.content,
      user: newMessage.sender.username,
      userId: newMessage.sender._id,
      spaceId: newMessage.space,
      timestamp: newMessage.createdAt,
      messageType: newMessage.messageType,
      isEdited: newMessage.isEdited,
      isDeleted: newMessage.isDeleted
    };
    
    emitToSpace(spaceId, 'receive_message', messageData);
    
    res.status(201).json(messageData);
  } catch (error) {
    console.error('Error sending message:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.get('/api/spaces', protect, async (req, res) => {
  try {
    const userId = req.user._id;
    
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

app.post('/api/spaces', protect, async (req, res) => {
  try {
    const { name, description, type } = req.body;
    const userId = req.user._id;
    
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

app.post('/api/spaces/:spaceId/join', protect, async (req, res) => {
  try {
    const { spaceId } = req.params;
    const userId = req.user._id;
    
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

server.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

module.exports = app;
