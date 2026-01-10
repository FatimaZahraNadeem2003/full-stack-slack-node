const mongoose = require('mongoose');

const notificationSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  type: {
    type: String,
    enum: ['message', 'mention', 'direct_message', 'system', 'reaction'],
    required: true,
  },
  title: {
    type: String,
    required: true,
  },
  message: {
    type: String,
    required: true,
  },
  relatedObjectId: {
    type: mongoose.Schema.Types.ObjectId,
    // Could reference Message, Space, or other objects depending on the type
  },
  isRead: {
    type: Boolean,
    default: false,
  },
  spaceId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Space',
    default: null,
  },
  conversationId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Space', // Direct messages are also represented as spaces
    default: null,
  },
}, {
  timestamps: true, // Adds createdAt and updatedAt fields
});

// Index for efficient querying by user and read status
notificationSchema.index({ userId: 1, isRead: 1 });

// Index for efficient querying by user and creation date
notificationSchema.index({ userId: 1, createdAt: -1 });

module.exports = mongoose.model('Notification', notificationSchema);