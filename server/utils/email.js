const nodemailer = require('nodemailer');

const sendEmail = async options => {
    try {
        const { EMAIL_HOST, EMAIL_PORT, EMAIL_USERNAME, EMAIL_PASSWORD } = process.env;
        const { email, subject, message } = options;

        // 1. Create a transport object //3:17 for GMAIL in video 135
        const transporter = nodemailer.createTransport({
            host: EMAIL_HOST,
            port: EMAIL_PORT,
            auth: {
                user: EMAIL_USERNAME,
                pass: EMAIL_PASSWORD
            }
        });

        // 2. Define the email options
        const mailOptions = {
            from: 'MTG Collection Tracker <hello@mtgcollectiontracker.com>',
            to: email,
            subject: subject,
            text: message
        }

        // 3. Send the email
        await transporter.sendMail(mailOptions);
    } catch (err) {
        throw new Error(err);
    }
}

module.exports = sendEmail;