export const messages = {
  authMessages: {
    SUCCESS: {
      LOGIN: "User logged in successfully.",
      SIGNUP: "User registered successfully.",
      LOGOUT: "User logged out successfully.",
      PASSWORD_RESET: "Password reset successfully.",
    },
    ERROR: {
      INVALID_CREDENTIALS: "Invalid credentials. Please try again.",
      UNAUTHORIZED: "Unauthorized access. Please log in.",
      USER_NOT_FOUND: "User does not exist.",
      EMAIL_ALREADY_EXISTS: "Email is already registered.",
      TOKEN_EXPIRED: "Your session has expired. Please log in again.",
      TOKEN_INVALID: "Invalid or expired token.",
      ACCOUNT_LOCKED:
        "Account is locked due to multiple failed login attempts.",
    },
    WARNING: {
      PASSWORD_WEAK: "Password is too weak. Please choose a stronger password.",
      ACCOUNT_LOCKED:
        "Your account has been temporarily locked. Please try again later.",
    },
    INFO: {
      PASSWORD_RESET_LINK_SENT: "Password reset link sent to your email.",
      VERIFY_EMAIL: "Please check your email to verify your account.",
    },
  },

  logMessages: {
    REQUEST: {
      INCOMING: (method, url) => `Incoming request: ${method} ${url}`,
      RESPONSE: (method, url, statusCode) =>
        `Response for request: ${method} ${url} - Status: ${statusCode}`,
    },
    ERROR: {
      GENERAL: (message) => `Error occurred: ${message}`,
      NOT_FOUND: (url) => `Can't find ${url} on this server!`,
      UNDEFINED: (url) => `Undefined route: ${url}`,
      DB_CONNECTION: "Database connection error.",
      INVALID_INPUT: "Invalid input data.",
      AUTH_FAILED: "Authentication failed.",
    },
    INFO: {
      SERVER_STARTED: (port) => `Server started and listening on port ${port}.`,
    },
  },

  auth: {
    signup: {
      validationError: "Invalid input data.",
      duplicateField:
        "Duplicate field value detected. Please use a different value.",
      signupFailed: "Signup failed. Please try again.",
    },
    login: {
      invalidCredentials: "Invalid email or password.",
      loginFailed: "Login failed. Please try again.",
      logout:"You have successfully logged out. Please log in again to continue.",
      noLongerExists: "The user belonging to this token no longer exists.",
      notLogin: "You are not logged in! Please login to access this resource."
    },
    forgotPassword: {
      noUser: "There is no user with that email address.",
      emailSent: "Reset password email sent successfully.",
      emailSendError: "There was an error sending the email. Try again later.",
    },
    resetPassword: {
      tokenInvalidOrExpired: "Token is invalid or has expired.",
      passwordUpdated: "Password has been updated successfully!",
    },
    role:{
      access: "Access denied. You do not have the required role."
    }
  },
  general: {
    internalServerError: "Something went wrong. Please try again later.",
  },
};

export const appSettings = {
  tier: {
    standard: "standard",
    carbon: "carbon",
    platinum: "platinum",
  },
  role: {
    admin: "admin",
    user: "user",
  },
  environment: {
    production: "production",
    development: "development",
  },
};
