import { AppError } from '../utils/errorHandler.js';

export const validateRequest = (schema) => (req, res, next) => {
    const errors = [];

    if (Object.keys(req.body).length > 0) {
        const { error } = schema.validate(req.body, { abortEarly: false });
        if (error) {
            const bodyMessages = error.details.map((detail) => detail.message).join(', ');
            errors.push(`${bodyMessages}`);
        }
    }

    if (Object.keys(req.query).length > 0) {
        const { error } = schema.validate(req.query, { abortEarly: false });
        if (error) {
            const queryMessages = error.details.map((detail) => detail.message).join(', ');
            errors.push(`${queryMessages}`);
        }
    }

    if (errors.length) {
        return next(new AppError(errors.join(' | '), 400));
    }

    next();
};

