const express = require('express');
const { registerUser, loginUser, checkAdmin, verifyToken } = require('../controllers/authController');
const { protect } = require('../middleware/authMiddleware');

const router = express.Router();

router.route('/register').post(registerUser);
router.route('/').post(loginUser);
router.route('/check-admin').get(checkAdmin);
router.route('/verify').get(protect, verifyToken);

module.exports = router;