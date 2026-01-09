const mongoose = require('mongoose');

const spaceSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'Space name is required'],
    trim: true,
    maxlength: [100, 'Space name cannot exceed 100 characters'],
  },
  description: {
    type: String,
    trim: true,
    maxlength: [500, 'Description cannot exceed 500 characters'],
  },
  type: {
    type: String,
    enum: ['public', 'private', 'direct'],
    default: 'public',
  },
  members: [{
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
    },
    role: {
      type: String,
      enum: ['admin', 'moderator', 'member'],
      default: 'member',
    },
    joinedAt: {
      type: Date,
      default: Date.now,
    },
  }],
  admins: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
  }],
  moderators: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
  }],
  isArchived: {
    type: Boolean,
    default: false,
  },
  avatar: {
    type: String, 
  },
  lastActivity: {
    type: Date,
    default: Date.now,
  },
}, {
  timestamps: true,
});

spaceSchema.index({ name: 1 });
spaceSchema.index({ type: 1 });
spaceSchema.index({ members: 1 });
spaceSchema.index({ admins: 1 });
spaceSchema.index({ createdAt: -1 }); 

module.exports = mongoose.model('Space', spaceSchema);