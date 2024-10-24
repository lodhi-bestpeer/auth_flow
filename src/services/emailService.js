import nodemailer from 'nodemailer';
import { template }  from '../templates/resetPassword.template.js'
import { messages } from "../constants/constant.js";


export class EmailService {
    constructor() {
        this.transporter = nodemailer.createTransport({
            // host: process.env.MAIL_HOST || 'smtp.gmail.com',
            // port: process.env.MAIL_PORT || 587,
            // secure: process.env.MAIL_PORT == 465, // Use true if using port 465
            service:"gmail",
            auth: {
                user: process.env.MAIL_USERNAME,
                pass: process.env.MAIL_PASSWORD,
            },
        });
    }

    async sendResetPasswordEmail(toEmail, resetLink) {
        const htmlContent = template.replace('{{resetLink}}', resetLink); 

        const mailOptions = {
            from: process.env.MAIL_USERNAME,
            to: toEmail,
            subject: 'Reset Your Password',
            html: htmlContent,
        };

        try {
            await this.transporter.sendMail(mailOptions);
            console.log('Reset password email sent successfully');
        } catch (error) {
            console.error('Error sending reset password email:', error);
            throw new Error(messages.auth.forgotPassword.emailSendError);
        }
    }
}

    