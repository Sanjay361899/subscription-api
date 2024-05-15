const express = require('express');
const router = express();

router.use(express.json());

const userController = require('../controllers/userController');
const { registerValidator, loginValidator } = require('../helpers/validation');

const auth = require('../middleware/auth');

router.post('/register', registerValidator, userController.userRegister);

router.post('/login', loginValidator, userController.loginUser);

//authenticated routes
router.get('/profile', auth, userController.userProfile);
router.get('/logout', auth, userController.logout);

module.exports = router;