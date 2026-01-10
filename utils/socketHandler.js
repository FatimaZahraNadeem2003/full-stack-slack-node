let ioInstance = null;

module.exports = {
  setIO: (io) => {
    ioInstance = io;
  },
  
  getIO: () => {
    if (!ioInstance) {
      throw new Error('Socket.IO instance not initialized');
    }
    return ioInstance;
  },
  
  emitToSpace: (spaceId, event, data) => {
    if (!ioInstance) {
      console.error('Socket.IO instance not initialized');
      return;
    }
    ioInstance.to(`space_${spaceId}`).emit(event, data);
  }
};