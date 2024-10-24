import crypto from "crypto";
import { User } from "../models/index.js";
import {
  AppError,
  handleValidationError,
  handleDuplicateFieldsDB,
} from "../utils/errorHandler.js";
import { AuthHelper } from "../helpers/helper.js";
import { EmailService } from "./emailService.js";
import { messages } from "../constants/constant.js";

export class AuthService {
  // Signup
  async signupService(userData) {
    try {
      const user = await User.create(userData);
      return {
        success: true,
        statusCode: 201,
        data: user,
      };
    } catch (error) {
      if (error.name === "ValidationError") {
        throw handleValidationError(error);
      }
      if (error.code === 11000) {
        throw handleDuplicateFieldsDB(error);
      }
      throw new AppError(messages.auth.signup.signupFailed, 500);
    }
  }

  // Login
  async loginService(credentials) {
    const authHelper = new AuthHelper();
    try {
      const { email, password } = credentials;
      const user = await User.findOne({ email });
      if (!user || !(await user.matchPassword(password))) {
        throw new AppError(messages.auth.login.invalidCredentials, 401);
      }

      const authKey = authHelper.generateRandomString();
      const token = authHelper.generateToken({
        id: user._id,
        email: user.email,
        role: user.role,
        authKey,
      });

      user.authkey = authKey;
      await user.save();

      return {
        success: true,
        statusCode: 200,
        data: { id: user._id, email: user.email },
        token,
      };
    } catch (error) {
      throw new AppError(error, 500);
    }
  }

  // Forgot Password
  async forgotPassword(email, req) {
    const user = await User.findOne({ email });
    if (!user) {
      throw new AppError(messages.auth.forgotPassword.noUser, 404);
    }

    const resetToken = user.createPasswordResetToken();
    await user.save({ validateBeforeSave: false });

    const resetURL = `${req.protocol}://${req.get(
      "host"
    )}/api/v1/auth/resetPassword/${resetToken}`;

    try {
      await new EmailService().sendResetPasswordEmail(user.email, resetURL);
      return {
        success: true,
        statusCode: 200,
        message: messages.auth.forgotPassword.emailSent,
      };
    } catch (error) {
      user.resetPasswordToken = undefined;
      user.resetPasswordExpires = undefined;
      await user.save({ validateBeforeSave: false });

      throw new AppError(messages.auth.forgotPassword.emailSendError, 500);
    }
  }

  // Reset Password
  async resetPassword(token, password) {
    const hashedToken = crypto.createHash("sha256").update(token).digest("hex");

    const user = await User.findOne({
      resetPasswordToken: hashedToken,
      resetPasswordExpires: { $gt: Date.now() },
    });

    if (!user) {
      throw new AppError(
        messages.auth.resetPassword.tokenInvalidOrExpired,
        400
      );
    }

    user.password = password;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    return {
      success: true,
      statusCode: 200,
      message: messages.auth.resetPassword.passwordUpdated,
    };
  }

  //logout
  async logout(id) {
    await User.findByIdAndUpdate(id, { authkey: null });

    return {
      success: true,
      statusCode: 200,
      message: messages.auth.login.logout,
    };
  }
}
