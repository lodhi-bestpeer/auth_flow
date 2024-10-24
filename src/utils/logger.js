import winston, { format } from "winston";

import "winston-daily-rotate-file";

const LOG_DIR = process.env.LOG_DIR || "logs",
    LOG_LEVEL = process.env.LOG_LEVEL || "info",
    /**
     * Create a new winston logger.
     */
    logger = winston.createLogger( {
        format: format.combine(
            format.errors({ stack: true })
        ),
        "transports": [
            new winston.transports.Console( {
                "format": format.combine( format.colorize(), format.simple() ),
                "level": "info"
            } ),
            new winston.transports.DailyRotateFile( {
                "format": format.combine( format.timestamp(), format.json() ),
                "maxFiles": "15d",
                "level": LOG_LEVEL,
                "dirname": LOG_DIR,
                "datePattern": "YYYY-MM-DD",
                "filename": "%DATE%-debug.log"
            } )
        ]
    } );

/**
 * A writable stream for winston logger.
 */
export const logStream = {
    write( message ) {
        logger.info( message.toString() );
    }
};

export default logger;