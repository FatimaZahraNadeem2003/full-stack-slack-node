const mongoose = require('mongoose');

const messageSchema = new mongoose.Schema({
  content: {
    type: String,
    required: [true, 'Message content is required'],
    trim: true,
    maxlength: [1000, 'Message cannot exceed 1000 characters'],
  },
  sender: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  space: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Space',
    required: true,
  },
  messageType: {
    type: String,
    enum: ['text', 'image', 'file', 'system'],
    default: 'text',
  },
  readBy: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
  }],
  repliedTo: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Message',
    default: null,
  },
  isEdited: {
    type: Boolean,
    default: false,
  },
  isDeleted: {
    type: Boolean,
    default: false,
  },
}, {
  timestamps: true, 
});

messageSchema.index({ space: 1, createdAt: -1 }); 
messageSchema.index({ sender: 1 }); 
messageSchema.index({ createdAt: -1 });

module.exports = mongoose.model('Message', messageSchema);
