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
    socket.userRole = decoded.role; 
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

  socket.on('join_direct_messages', async (userIds) => {
    if (Array.isArray(userIds)) {
      userIds.forEach(userId => {
        const directMessageRoom = [socket.userId, userId].sort().join('_');
        socket.join(`dm_${directMessageRoom}`);
        console.log(`User ${socket.userId} joined direct message room with ${userId}`);
      });
    }
  });

  socket.on('send_message', async (data) => {
    try {
      const { content, spaceId, recipientId } = data; 
      
      if (!content) {
        socket.emit('error', { message: 'Content is required' });
        return;
      }

      const User = require('./models/User');
      const user = await User.findById(socket.userId);
      if (!user) {
        socket.emit('error', { message: 'User not found' });
        return;
      }

      let targetSpaceId = spaceId;
      let isDirectMessage = false;

      if (recipientId) {
        isDirectMessage = true;
        const Space = require('./models/Space');
        const userIds = [socket.userId, recipientId].sort(); 
        const dmSpace = await Space.findOne({
          type: 'direct',
          members: { $size: 2 }, 
          $and: [
            { 'members': { $elemMatch: { user: userIds[0] } } },
            { 'members': { $elemMatch: { user: userIds[1] } } }
          ]
        });

        if (dmSpace) {
          targetSpaceId = dmSpace._id;
        } else {
          const newDMSpace = new Space({
            name: `DM_${userIds.join('_')}`, 
            type: 'direct',
            description: `Direct messages between ${user.username} and another user`,
            members: [
              { user: userIds[0], role: 'member' },
              { user: userIds[1], role: 'member' }
            ],
            admins: [userIds[0]] 
          });

          await newDMSpace.save();
          targetSpaceId = newDMSpace._id;
        }
      } else {
        const Space = require('./models/Space');
        const space = await Space.findById(spaceId);
        if (!space) {
          socket.emit('error', { message: 'Space not found' });
          return;
        }

        const isMember = space.members.some(member => 
          member.user.toString() === socket.userId.toString()
        );

        if (!isMember && user.role !== 'admin') {
          socket.emit('error', { message: 'User is not a member of this space' });
          return;
        }
      }

      const Message = require('./models/Message');
      const newMessage = new Message({
        content,
        sender: socket.userId,
        space: targetSpaceId,
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

      if (isDirectMessage) {
        const directMessageRoom = userIds.sort().join('_');
        io.to(`dm_${directMessageRoom}`).emit('receive_direct_message', messageData);
        
        const Notification = require('./models/Notification');
        const recipient = await User.findById(recipientId);
        if (recipient) {
          const notification = new Notification({
            userId: recipient._id,
            type: 'direct_message',
            title: `Direct message from ${user.username}`,
            message: content,
            relatedObjectId: newMessage._id,
            conversationId: targetSpaceId
          });
          await notification.save();
          
          io.to(recipient._id.toString()).emit('new_notification', {
            id: notification._id,
            type: notification.type,
            title: notification.title,
            message: notification.message,
            timestamp: notification.createdAt,
            isRead: notification.isRead
          });
        }
      } else {
        emitToSpace(targetSpaceId, 'receive_message', messageData);
        
        const Space = require('./models/Space');
        const space = await Space.findById(targetSpaceId);
        
        const mentionRegex = /@(\w+)/g;
        const mentions = content.match(mentionRegex);
        
        if (mentions) {
          for (const mention of mentions) {
            const username = mention.substring(1);
            const mentionedUser = await User.findOne({ username: username });
            
            if (mentionedUser && mentionedUser._id.toString() !== socket.userId.toString()) {
              const notification = new Notification({
                userId: mentionedUser._id,
                type: 'mention',
                title: `${user.username} mentioned you`,
                message: content,
                relatedObjectId: newMessage._id,
                spaceId: targetSpaceId
              });
              await notification.save();
              
              io.to(mentionedUser._id.toString()).emit('new_notification', {
                id: notification._id,
                type: notification.type,
                title: notification.title,
                message: notification.message,
                timestamp: notification.createdAt,
                isRead: notification.isRead
              });
            }
          }
        }
        
        if (space) {
          for (const member of space.members) {
            const memberId = member.user.toString();
            if (memberId !== socket.userId.toString()) {
              const notification = new Notification({
                userId: memberId,
                type: 'message',
                title: `New message in #${space.name}`,
                message: `${user.username}: ${content}`,
                relatedObjectId: newMessage._id,
                spaceId: targetSpaceId
              });
              await notification.save();
              
              io.to(memberId).emit('new_notification', {
                id: notification._id,
                type: notification.type,
                title: notification.title,
                message: notification.message,
                timestamp: notification.createdAt,
                isRead: notification.isRead
              });
            }
          }
        }
      }

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
const User = require('./models/User');
const Notification = require('./models/Notification');
const { protect, adminOnly } = require('./middleware/authMiddleware');

app.get('/api/health', (req, res) => {
  res.json({ status: 'Backend server is running!' });
});

app.get('/api/direct-messages/conversations', protect, async (req, res) => {
  try {
    const userId = req.user._id;
    
    const directMessageSpaces = await Space.find({
      type: 'direct',
      'members.user': userId
    })
    .populate('members.user', 'username email avatar role')
    .populate({
      path: 'members.user',
      select: 'username email avatar role'
    })
    .sort({ lastActivity: -1 });

    const conversations = directMessageSpaces.map(dmSpace => {
      const otherParticipant = dmSpace.members.find(member => 
        member.user._id.toString() !== userId.toString()
      );
      
      return {
        id: dmSpace._id,
        spaceName: dmSpace.name,
        type: dmSpace.type,
        participants: dmSpace.members.map(member => ({
          id: member.user._id,
          username: member.user.username,
          email: member.user.email,
          role: member.user.role,
          avatar: member.user.avatar
        })),
        otherUser: otherParticipant ? otherParticipant.user : null,
        lastActivity: dmSpace.lastActivity
      };
    });

    res.json({ conversations });
  } catch (error) {
    console.error('Error fetching direct message conversations:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.get('/api/direct-messages/:conversationId', protect, async (req, res) => {
  try {
    const { conversationId } = req.params;
    const userId = req.user._id;

    const dmSpace = await Space.findOne({
      _id: conversationId,
      type: 'direct',
      'members.user': userId
    });

    if (!dmSpace) {
      return res.status(403).json({ error: 'Access denied' });
    }

    const messages = await Message.find({ space: conversationId })
      .populate('sender', 'username email avatar role')
      .populate('space', 'name')
      .sort({ createdAt: -1 })
      .limit(50); 

    res.json({
      messages: messages.map(msg => ({
        id: msg._id,
        content: msg.content,
        user: msg.sender.username,
        userId: msg.sender._id,
        userRole: msg.sender.role, 
        spaceId: msg.space._id,
        spaceName: msg.space.name,
        timestamp: msg.createdAt,
        messageType: msg.messageType,
        isEdited: msg.isEdited,
        isDeleted: msg.isDeleted
      }))
    });
  } catch (error) {
    console.error('Error fetching direct messages:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.post('/api/direct-messages', protect, async (req, res) => {
  try {
    const { content, recipientId } = req.body;
    const senderId = req.user._id;

    if (!content || !recipientId) {
      return res.status(400).json({ error: 'Content and recipientId are required' });
    }

    if (senderId.toString() === recipientId.toString()) {
      return res.status(400).json({ error: 'Cannot send message to yourself' });
    }

    const Space = require('./models/Space');
    const userIds = [senderId, recipientId].sort(); 
    const dmSpace = await Space.findOne({
      type: 'direct',
      members: { $size: 2 },
      $and: [
        { 'members': { $elemMatch: { user: userIds[0] } } },
        { 'members': { $elemMatch: { user: userIds[1] } } }
      ]
    });

    let targetSpaceId;
    if (dmSpace) {
      targetSpaceId = dmSpace._id;
    } else {
      const User = require('./models/User');
      const sender = await User.findById(senderId);
      const recipient = await User.findById(recipientId);
      
      if (!sender || !recipient) {
        return res.status(404).json({ error: 'Sender or recipient not found' });
      }

      const newDMSpace = new Space({
        name: `DM_${userIds.join('_')}`, 
        type: 'direct',
        description: `Direct messages between ${sender.username} and ${recipient.username}`,
        members: [
          { user: userIds[0], role: 'member' },
          { user: userIds[1], role: 'member' }
        ],
        admins: [userIds[0]] 
      });

      await newDMSpace.save();
      targetSpaceId = newDMSpace._id;
    }

    const newMessage = new Message({
      content,
      sender: senderId,
      space: targetSpaceId,
      messageType: 'text' 
    });

    await newMessage.save();
    await newMessage.populate('sender', 'username email avatar role');

    const messageData = {
      id: newMessage._id,
      content: newMessage.content,
      user: newMessage.sender.username,
      userId: newMessage.sender._id,
      userRole: newMessage.sender.role, 
      spaceId: newMessage.space,
      timestamp: newMessage.createdAt,
      messageType: newMessage.messageType,
      isEdited: newMessage.isEdited,
      isDeleted: newMessage.isDeleted
    };

    await Space.findByIdAndUpdate(targetSpaceId, { lastActivity: new Date() });

    res.status(201).json(messageData);
  } catch (error) {
    console.error('Error sending direct message:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.get('/api/messages', protect, async (req, res) => {
  try {
    const spaceId = req.query.space || 'general'; 
    
    const space = await Space.findById(spaceId);
    if (space && space.type === 'direct') {
      const userId = req.user._id;
      const isParticipant = space.members.some(member => 
        member.user.toString() === userId.toString()
      );
      
      if (!isParticipant && req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Access denied' });
      }
    } else {
      if (req.user.role !== 'admin') {
        const userSpaces = await Space.find({
          'members.user': req.user._id
        }).select('_id');
        
        const userSpaceIds = userSpaces.map(space => space._id.toString());
        if (!userSpaceIds.includes(spaceId)) {
          return res.status(403).json({ error: 'Access denied' });
        }
      }
    }
    
    const messages = await Message.find({ space: spaceId })
      .populate('sender', 'username email avatar role')
      .populate('space', 'name')
      .sort({ createdAt: -1 })
      .limit(50); 
    
    res.json({
      messages: messages.map(msg => ({
        id: msg._id,
        content: msg.content,
        user: msg.sender.username,
        userId: msg.sender._id,
        userRole: msg.sender.role, 
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
    
    if (space.type === 'direct') {
      const isParticipant = space.members.some(member => 
        member.user.toString() === userId.toString()
      );
      
      if (!isParticipant && req.user.role !== 'admin') {
        return res.status(403).json({ error: 'User is not a participant of this direct message' });
      }
    } else {
      const isMember = space.members.some(member => 
        member.user.toString() === userId.toString()
      );
      
      if (!isMember && req.user.role !== 'admin') {
        return res.status(403).json({ error: 'User is not a member of this space' });
      }
    }
    
    const newMessage = new Message({
      content,
      sender: userId,
      space: spaceId,
      messageType: 'text' 
    });
    
    await newMessage.save();
    
    await newMessage.populate('sender', 'username email avatar role');
    
    const messageData = {
      id: newMessage._id,
      content: newMessage.content,
      user: newMessage.sender.username,
      userId: newMessage.sender._id,
      userRole: newMessage.sender.role, 
      spaceId: newMessage.space,
      timestamp: newMessage.createdAt,
      messageType: newMessage.messageType,
      isEdited: newMessage.isEdited,
      isDeleted: newMessage.isDeleted
    };
    
    await Space.findByIdAndUpdate(spaceId, { lastActivity: new Date() });
    
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
    
    let spaces;
    if (req.user.role === 'admin') {
      spaces = await Space.find({}).populate('members.user', 'username email role');
    } else {
      spaces = await Space.find({
        $or: [
          { 'members.user': userId }, 
          { type: 'direct', 'members.user': userId } 
        ]
      }).populate('members.user', 'username email role');
    }
    
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
          role: member.user.role,
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
    
    if (type === 'direct') {
      return res.status(400).json({ error: 'Direct message spaces must be created through the direct message endpoint' });
    }
    
    const newSpace = new Space({
      name,
      description,
      type: type || 'public'
    });
    
    const memberInfo = {
      user: userId,
      role: req.user.role === 'admin' ? 'admin' : 'admin' 
    };
    
    newSpace.members.push(memberInfo);
    if (req.user.role === 'admin') {
      newSpace.admins.push(userId);
    }
    
    await newSpace.save();
    
    await newSpace.populate('members.user', 'username email role');
    
    res.status(201).json({
      id: newSpace._id,
      name: newSpace.name,
      description: newSpace.description,
      type: newSpace.type,
      members: [{
        id: userId,
        role: req.user.role === 'admin' ? 'admin' : 'admin'
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
    
    if (space.type === 'direct') {
      return res.status(400).json({ error: 'Cannot join direct message spaces' });
    }
    
    const isAlreadyMember = space.members.some(member => 
      member.user.toString() === userId.toString()
    );
    
    if (isAlreadyMember) {
      return res.status(400).json({ error: 'User is already a member of this space' });
    }
    
    space.members.push({
      user: userId,
      role: req.user.role === 'admin' ? 'admin' : 'member'
    });
    
    if (req.user.role === 'admin') {
      space.admins.push(userId);
    }
    
    await space.save();
    
    res.json({ message: 'Successfully joined space', spaceId: space._id });
  } catch (error) {
    console.error('Error joining space:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.get('/api/notifications', protect, async (req, res) => {
  try {
    const userId = req.user._id;
    const { isRead, limit = 50, page = 1 } = req.query;
    
    let query = { userId: userId };
    if (isRead !== undefined) {
      query.isRead = isRead === 'true';
    }
    
    const skip = (page - 1) * limit;
    
    const notifications = await Notification.find(query)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));
    
    const total = await Notification.countDocuments(query);
    
    res.json({
      notifications: notifications.map(notification => ({
        id: notification._id,
        type: notification.type,
        title: notification.title,
        message: notification.message,
        isRead: notification.isRead,
        spaceId: notification.spaceId,
        conversationId: notification.conversationId,
        createdAt: notification.createdAt,
        updatedAt: notification.updatedAt
      })),
      pagination: {
        total,
        page: parseInt(page),
        pages: Math.ceil(total / limit),
        limit: parseInt(limit)
      }
    });
  } catch (error) {
    console.error('Error fetching notifications:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.put('/api/notifications/:notificationId/read', protect, async (req, res) => {
  try {
    const { notificationId } = req.params;
    const userId = req.user._id;
    
    const notification = await Notification.findOneAndUpdate(
      { _id: notificationId, userId: userId },
      { isRead: true },
      { new: true }
    );
    
    if (!notification) {
      return res.status(404).json({ error: 'Notification not found' });
    }
    
    res.json({
      message: 'Notification marked as read',
      notification: {
        id: notification._id,
        type: notification.type,
        title: notification.title,
        message: notification.message,
        isRead: notification.isRead,
        spaceId: notification.spaceId,
        conversationId: notification.conversationId,
        createdAt: notification.createdAt,
        updatedAt: notification.updatedAt
      }
    });
  } catch (error) {
    console.error('Error updating notification:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.put('/api/notifications/mark-all-read', protect, async (req, res) => {
  try {
    const userId = req.user._id;
    
    await Notification.updateMany(
      { userId: userId, isRead: false },
      { isRead: true }
    );
    
    res.json({ message: 'All notifications marked as read' });
  } catch (error) {
    console.error('Error marking all notifications as read:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.delete('/api/notifications/:notificationId', protect, async (req, res) => {
  try {
    const { notificationId } = req.params;
    const userId = req.user._id;
    
    const notification = await Notification.findOneAndDelete({
      _id: notificationId,
      userId: userId
    });
    
    if (!notification) {
      return res.status(404).json({ error: 'Notification not found' });
    }
    
    res.json({ message: 'Notification deleted' });
  } catch (error) {
    console.error('Error deleting notification:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.delete('/api/notifications', protect, async (req, res) => {
  try {
    const userId = req.user._id;
    
    await Notification.deleteMany({ userId: userId });
    
    res.json({ message: 'All notifications deleted' });
  } catch (error) {
    console.error('Error deleting all notifications:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.get('/api/admin/users', protect, adminOnly, async (req, res) => {
  try {
    const users = await User.find({}).select('-password');
    
    res.json({
      users: users.map(user => ({
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        isActive: user.isActive,
        lastSeen: user.lastSeen,
        createdAt: user.createdAt,
        updatedAt: user.updatedAt
      }))
    });
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.get('/api/admin/messages', protect, adminOnly, async (req, res) => {
  try {
    const { spaceId, limit = 50, skip = 0 } = req.query;
    
    let query = {};
    if (spaceId) {
      query.space = spaceId;
    }
    
    const messages = await Message.find(query)
      .populate('sender', 'username email role')
      .populate('space', 'name')
      .sort({ createdAt: -1 })
      .skip(parseInt(skip))
      .limit(parseInt(limit));
    
    res.json({
      messages: messages.map(msg => ({
        id: msg._id,
        content: msg.content,
        user: msg.sender.username,
        userId: msg.sender._id,
        userRole: msg.sender.role,
        spaceId: msg.space._id,
        spaceName: msg.space.name,
        timestamp: msg.createdAt,
        messageType: msg.messageType,
        isEdited: msg.isEdited,
        isDeleted: msg.isDeleted
      })),
      totalCount: await Message.countDocuments(query)
    });
  } catch (error) {
    console.error('Error fetching messages:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.get('/api/admin/spaces', protect, adminOnly, async (req, res) => {
  try {
    const spaces = await Space.find({})
      .populate('members.user', 'username email role')
      .populate('admins', 'username email');
    
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
          role: member.user.role,
        })),
        admins: space.admins,
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

app.get('/api/users/search', protect, async (req, res) => {
  try {
    const { q, limit = 10 } = req.query;
    const userId = req.user._id;
    
    if (!q) {
      return res.status(400).json({ error: 'Query parameter "q" is required' });
    }
    
    const users = await User.find({
      _id: { $ne: userId },
      $or: [
        { username: { $regex: q, $options: 'i' } },
        { email: { $regex: q, $options: 'i' } }
      ]
    })
    .select('-password')
    .limit(parseInt(limit));
    
    res.json({
      users: users.map(user => ({
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        isActive: user.isActive,
        lastSeen: user.lastSeen,
        createdAt: user.createdAt,
        updatedAt: user.updatedAt
      }))
    });
  } catch (error) {
    console.error('Error searching users:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

server.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

module.exports = app;




