import dotenv from "dotenv";
dotenv.config();
import express from "express";
import rateLimit from "express-rate-limit";
import compression from "compression";
import helmet from "helmet";
import cors from "cors";
import hpp from "hpp"

import connectDB from "./config/db.js";
import Routes from "./routes/index.js";
import { globalErrorHandler, AppError } from "./utils/errorHandler.js";
import logger from "./utils/logger.js";
import { messages, appSettings } from "./constants/constant.js";

const app = express();

// Middleware
app.use(helmet()); // Helmet use for security headers
app.use(hpp()); // Prevent HTTP Parameter Pollution
app.use(express.json()); // Parse JSON request bodies
app.use(express.urlencoded({ extended: true })); // Parse URL-encoded data
app.use(compression()); // Compress response bodies for better performance
app.use(cors()); // Allow CORS

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
});
app.use(limiter);

// Logging Middleware for incoming requests
app.use((req, res, next) => {
  logger.info(messages.logMessages.REQUEST.INCOMING(req.method, req.url));
  next();
});

// Database Connection with Logging
// connectDB();

app.use("/",(req, res)=>{
  res.status(200).json({
    message: "CICD is running successfully...",
    name: "my name is sourabh"
  })
})

// Routes
app.use("/api/v1", Routes);

app.all("*", (req, res, next) => {
  logger.warn(messages.logMessages.ERROR.UNDEFINED(req.originalUrl));
  next(
    new AppError(messages.logMessages.ERROR.NOT_FOUND(req.originalUrl), 404)
  );
});

// Global error handler middleware
app.use((err, req, res, next) => {
  if (process.env.NODE_ENV === appSettings.environment.development) {
    logger.error(messages.logMessages.ERROR.GENERAL(err.message), err);
  } else if (process.env.NODE_ENV === appSettings.environment.production) {
    logger.error(messages.logMessages.ERROR.GENERAL(err.message));
  }
  globalErrorHandler(err, req, res, next);
});

export default app;
