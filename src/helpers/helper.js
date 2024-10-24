
import jwt from "jsonwebtoken";
import { AppError } from "../utils/errorHandler.js";
import { User } from "../models/userModel.js";
import { messages } from "../constants/constant.js";


export class AuthHelper {
  constructor(secret = "supersecretkey", expiresIn = "1d") {
    this.secret = secret;
    this.expiresIn = expiresIn;
  }

  // Method to generate JWT token
  generateToken(user) {
    return jwt.sign(
      {
        id: user._id,
        email: user.email,
        role: user.role,
        authKey: user.authKey
      },
      this.secret,
      { expiresIn: this.expiresIn }
    );
  }

  // Middleware for verifying JWT token
   jwtVerifyToken = async(req, res, next)=> {
    try {
      let token;
      if (req.headers.authorization && req.headers.authorization.startsWith("Bearer")) {
        token = req.headers.authorization.split(" ")[1];
      }

      if (!token) {
        return next(new AppError(messages.auth.login.notLogin, 401));
      }

      
      const decoded = jwt.verify(token, this.secret);

      const currentUser = await User.findOne({id:decoded.id, authkey:decoded.authKey});

      if (!currentUser) {
        return next(new AppError(messages.auth.login.noLongerExists, 401));
      }

      req.user = currentUser;
      next();
    } catch (err) {
      console.log("error:", err)
      return next(new AppError(messages.auth.login.loginFailed, 401));
    }
  }

  // Middleware to check user roles
  roleMiddleware(...roles) {
    return (req, res, next) => {
      const userRole = req.user?.role;

      if (!roles.includes(userRole)) {
        return res.status(403).json({
          message: messages.auth.role.access
        });
      }

      next();
    };
  }

// Generate a random string
 generateRandomString(length = 9) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    const charactersLength = characters.length;
  
    for (let i = 0; i < length; i++) {
      result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
  
    return result;
  }
}

