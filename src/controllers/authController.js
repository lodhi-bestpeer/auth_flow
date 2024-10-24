import { catchAsync } from "../utils/errorHandler.js";

export class AuthController {
  constructor({ bAuthService, responseHandler }) {
    this.authService = bAuthService;
    this.responseHandler = responseHandler;
  }

  // Signup
  signup = catchAsync(async (req, res, next) => {
    const returnData = await this.authService.signupService(req.body);
    await this.responseHandler.handleServiceResponse(req, res, returnData);
  });

  // Login
  login = catchAsync(async (req, res, next) => {
    const returnData = await this.authService.loginService(req.body);
    await this.responseHandler.handleServiceResponse(req, res, returnData);
  });

  // Forgot Password
  forgotPassword = catchAsync(async (req, res, next) => {
    const { email } = req.body;
    const returnData = await this.authService.forgotPassword(email, req);
    await this.responseHandler.handleServiceResponse(req, res, returnData);
  });

  // Reset Password
  resetPassword = catchAsync(async (req, res, next) => {
    const { password } = req.body;
    const { token } = req.params;
    const returnData = await this.authService.resetPassword(token, password);
    await this.responseHandler.handleServiceResponse(req, res, returnData);
  });

  // logout
  logout = catchAsync(async (req, res, next) => {
    const { id } = req.user;
    const returnData = await this.authService.logout(id);
    await this.responseHandler.handleServiceResponse(req, res, returnData);
  });
}
