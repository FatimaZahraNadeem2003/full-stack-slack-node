const express = require('express');
const cors = require('cors');
const path = require('path');
const app = express();
const PORT = process.env.PORT || 5000;

app.use(express.json());
app.use(cors());

app.get('/api/health', (req, res) => {
  res.json({ status: 'Backend server is running!' });
});

app.get('/api/messages', (req, res) => {
  res.json({
    messages: [
      { id: 1, user: 'John', text: 'Hello!', timestamp: new Date().toISOString() },
      { id: 2, user: 'Jane', text: 'Hi there!', timestamp: new Date().toISOString() }
    ]
  });
});

app.post('/api/messages', (req, res) => {
  const { user, text } = req.body;
  if (!user || !text) {
    return res.status(400).json({ error: 'User and text are required' });
  }
  
  const newMessage = {
    id: Date.now(),
    user,
    text,
    timestamp: new Date().toISOString()
  };
  //
  res.status(201).json(newMessage);
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

module.exports = app;