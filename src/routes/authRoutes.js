import express from 'express';
import { AuthController } from '../controllers/index.js'; 
import { AuthService } from '../services/index.js'; 
import { AuthHelper } from '../helpers/helper.js';
import ResponseHandler from '../utils/responseHandler.js';
import { signupSchema, loginSchema, forgotPasswordSchema, resetPasswordSchema } from '../validations/authValidation.js';
import { validateRequest } from '../middlewares/index.js';

const router = express.Router();
const authHelper = new AuthHelper()
const responseHandler = new ResponseHandler();

const authService = new AuthService();
const authController = new AuthController({ bAuthService: authService, responseHandler });

// signup route
router.post('/signup', validateRequest(signupSchema), authController.signup.bind(authController));

//login route
router.post('/login', validateRequest(loginSchema), authController.login.bind(authController));

// Forgot Password route
router.post('/forgotPassword', validateRequest(forgotPasswordSchema), authController.forgotPassword.bind(authController));

// Reset Password route
router.post('/resetPassword/:token', validateRequest(resetPasswordSchema), authController.resetPassword.bind(authController));

//logout
router.get('/logout', authHelper.jwtVerifyToken, authController.logout.bind(authController));

// Export router
export default router;
