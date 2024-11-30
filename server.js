const express = require('express');
const mysql = require('mysql');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const session = require('express-session');
require('dotenv').config();

const app = express();
const port = 3000;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static('public'));

app.use(session({
    secret: 'your_secret_key',
    resave: false,
    saveUninitialized: true,
}));

const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
});

db.connect((err) => {
    if (err) throw err;
    console.log('Connected to database!');
});

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
});

// Helper Function to Generate OTP
function generateOTP() {
    return crypto.randomInt(100000, 999999).toString();
}

// Register
app.post('/register', (req, res) => {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
        return res.status(400).send('All fields are required!');
    }

    const hashedPassword = bcrypt.hashSync(password, 10);

    const query = 'INSERT INTO users (username, email, password) VALUES (?, ?, ?)';
    db.query(query, [username, email, hashedPassword], (err) => {
        if (err) {
            console.error('Error during registration:', err);
            return res.status(500).send('Failed to register!');
        }
        res.send('Registration successful! You can now login.');
    });
});

// Login
app.post('/login', (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).send('All fields are required!');
    }

    const query = 'SELECT * FROM users WHERE email = ?';
    db.query(query, [email], (err, results) => {
        if (err || results.length === 0) {
            return res.status(400).send('Email not found!');
        }

        const user = results[0];
        if (bcrypt.compareSync(password, user.password)) {
            req.session.userId = user.id;
            const username = user.username;

            const otp = generateOTP();
            const expiresAt = new Date(Date.now() + 5 * 60000);

            const otpQuery = 'INSERT INTO otp_codes (email, otp_code, expires_at) VALUES (?, ?, ?)';
            db.query(otpQuery, [email, otp, expiresAt], (err) => {
                if (err) {
                    console.error('Error saving OTP:', err);
                    return res.status(500).send('Failed to generate OTP!');
                }

                // Send OTP via email
                const mailOptions = {
                    from: process.env.EMAIL_USER,
                    to: email,
                    subject: 'Kode OTP untuk Verifikasi Login Anda - ANL Studio',
                    html: `
                    <html>
                        <head>
                            <style>
                                body {
                                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                                    background-color: #f6f9fc;
                                    margin: 0;
                                    padding: 0;
                                }
                                .container {
                                    background-color: #ffffff;
                                    border-radius: 12px;
                                    padding: 40px;
                                    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                                    width: 100%;
                                    max-width: 600px;
                                    margin: 20px auto;
                                }
                                .header {
                                    text-align: center;
                                    margin-bottom: 30px;
                                }
                                .logo {
                                    font-size: 28px;
                                    font-weight: bold;
                                    color: #2d3748;
                                    margin-bottom: 10px;
                                }
                                h1 {
                                    color: #1a365d;
                                    font-size: 24px;
                                    margin-bottom: 20px;
                                    text-align: center;
                                }
                                p {
                                    font-size: 16px;
                                    color: #4a5568;
                                    line-height: 1.6;
                                    margin-bottom: 15px;
                                }
                                .otp-container {
                                    text-align: center;
                                    margin: 30px 0;
                                    padding: 20px;
                                    background-color: #f8fafc;
                                    border-radius: 8px;
                                }
                                .otp {
                                    font-family: 'Courier New', monospace;
                                    font-size: 36px;
                                    font-weight: bold;
                                    color: #2b6cb0;
                                    letter-spacing: 8px;
                                    padding: 10px 20px;
                                    background-color: #ebf8ff;
                                    border-radius: 8px;
                                    border: 2px dashed #4299e1;
                                }
                                .warning {
                                    background-color: #fff5f5;
                                    border-left: 4px solid #fc8181;
                                    padding: 15px;
                                    margin: 20px 0;
                                    border-radius: 4px;
                                }
                                .footer {
                                    margin-top: 40px;
                                    padding-top: 20px;
                                    border-top: 1px solid #e2e8f0;
                                    text-align: center;
                                    font-size: 14px;
                                    color: #718096;
                                }
                                .help-text {
                                    font-size: 14px;
                                    color: #718096;
                                    text-align: center;
                                    margin-top: 15px;
                                }
                                .social-links {
                                    margin-top: 20px;
                                    text-align: center;
                                }
                                .social-links a {
                                    color: #4a5568;
                                    text-decoration: none;
                                    margin: 0 10px;
                                }
                            </style>
                        </head>
                        <body>
                            <div class="container">
                                <div class="header">
                                    <div class="logo">ANL Studio</div>
                                </div>
                                
                                <h1>Verifikasi Login Anda</h1>
                                
                                <p>Hai ${username}</p>
                                
                                <p>Kami menerima permintaan untuk login ke akun ANL Studio Anda. Untuk memastikan keamanan akun Anda, silakan gunakan kode OTP berikut:</p>
                                
                                <div class="otp-container">
                                    <div class="otp">${otp}</div>
                                    <p class="help-text">Kode ini akan kadaluarsa dalam 5 menit</p>
                                </div>
                                
                                <div class="warning">
                                    <p style="margin: 0;"><strong>Penting:</strong> Jangan pernah membagikan kode OTP ini kepada siapapun, termasuk pihak yang mengaku sebagai staff ANL Studio. Tim kami tidak akan pernah meminta kode OTP Anda.</p>
                                </div>
                                
                                <p>Jika Anda tidak merasa melakukan permintaan login ini, abaikan email ini dan segera hubungi tim support kami untuk keamanan akun Anda.</p>
                                
                                <div class="footer">
                                    <p>Terima kasih telah menggunakan layanan ANL Studio</p>
                                    <div class="social-links">
                                        <a href="#">Facebook</a> |
                                        <a href="#">Twitter</a> |
                                        <a href="#">Instagram</a>
                                    </div>
                                    <p>&copy; ${new Date().getFullYear()} ANL Studio. Hak Cipta Dilindungi.</p>
                                    <p>Jika Anda membutuhkan bantuan, silakan hubungi support@anlstudio.com</p>
                                </div>
                            </div>
                        </body>
                    </html>
            `
        };

                transporter.sendMail(mailOptions, (err) => {
                    if (err) {
                        console.error('Error sending email:', err);
                        return res.status(500).send('Failed to send OTP email!');
                    }
                    res.redirect('/verify-otp.html');
                });
            });
        } else {
            res.status(400).send('Incorrect password!');
        }
    });
});

// Verify OTP
app.post('/verify-otp', (req, res) => {
    const { email, otp } = req.body;

    if (!email || !otp) {
        return res.status(400).send('All fields are required!');
    }

    const query = 'SELECT * FROM otp_codes WHERE email = ? AND otp_code = ? AND expires_at > NOW()';
    db.query(query, [email, otp], (err, results) => {
        if (err || results.length === 0) {
            return res.status(400).send('Invalid or expired OTP!');
        }

        res.redirect('/index.html');
    });
});

// Get User Profile
app.get('/profile', (req, res) => {
    if (!req.session || !req.session.userId) {
        return res.status(401).send('Unauthorized: Please log in');
    }

    const userId = req.session.userId;
    const query = 'SELECT username, email FROM users WHERE id = ?';

    db.query(query, [userId], (err, results) => {
        if (err) {
            console.error('Error fetching profile:', err);
            return res.status(500).send('Failed to fetch profile');
        }

        if (results.length === 0) {
            return res.status(404).send('User not found');
        }

        res.json(results[0]);
    });
});

// Update Username
app.post('/update-username', (req, res) => {
    if (!req.session || !req.session.userId) {
        return res.status(401).send('Unauthorized: Please log in');
    }

    const userId = req.session.userId;
    const { username } = req.body;

    if (!username) {
        return res.status(400).send('Username is required');
    }

    const query = 'UPDATE users SET username = ? WHERE id = ?';
    db.query(query, [username, userId], (err, result) => {
        if (err) {
            console.error('Error updating username:', err);
            return res.status(500).send('Failed to update username');
        }

        res.send('Username updated successfully');
    });
});

// Logout
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Error logging out:', err);
            return res.status(500).send('Failed to log out');
        }
        res.redirect('/login.html');
    });
});

// Contact Me - Save Message and Send Email
app.post('/contact', (req, res) => {
    const { name, email, message } = req.body;

    // Validasi input
    if (!name || !email || !message) {
        return res.status(400).send('All fields are required!');
    }

    // Simpan pesan ke database
    const query = 'INSERT INTO messages (name, email, message) VALUES (?, ?, ?)';
    db.query(query, [name, email, message], (err, result) => {
        if (err) {
            console.error('Error saving message to database:', err);
            return res.status(500).send('Failed to save message!');
        }

        // Kirim email ke admin
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: process.env.ADMIN_EMAIL,
            subject: 'New Contact Form Submission',
            html: `
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <style>
                    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600&display=swap');
                    body, table, td, div { 
                        font-family: 'Inter', sans-serif; 
                        line-height: 1.6; 
                        margin: 0; 
                        padding: 0; 
                    }
                    @media only screen and (max-width: 600px) {
                        .container {
                            width: 100% !important;
                            min-width: 100% !important;
                        }
                        .mobile-padding {
                            padding: 15px !important;
                        }
                        .mobile-text-center {
                            text-align: center !important;
                        }
                        .mobile-full-width {
                            width: 100% !important;
                        }
                        .mobile-hide {
                            display: none !important;
                        }
                        .mobile-show {
                            display: block !important;
                            width: auto !important;
                            max-height: inherit !important;
                            overflow: visible !important;
                            float: none !important;
                        }
                        .mobile-table {
                            display: block !important;
                            width: 100% !important;
                        }
                    }
                </style>
            </head>
            <body style="
                background-color: #f4f6f9; 
                margin: 0; 
                padding: 20px;
                -webkit-text-size-adjust: 100%;
                -ms-text-size-adjust: 100%;
            ">
                <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="border-collapse: collapse;">
                    <tr>
                        <td align="center" style="padding: 10px 0;">
                            <table 
                                role="presentation" 
                                width="600" 
                                cellspacing="0" 
                                cellpadding="0" 
                                style="
                                    border-collapse: collapse; 
                                    max-width: 600px; 
                                    width: 100%;
                                    background-color: white; 
                                    border-radius: 12px; 
                                    box-shadow: 0 4px 20px rgba(0,0,0,0.08);
                                    overflow: hidden;
                                " 
                                class="container"
                            >
                                <!-- Header -->
                                <tr>
                                    <td style="
                                        background: linear-gradient(135deg, #6a11cb 0%, #2575fc 100%);
                                        color: white;
                                        padding: 25px;
                                        text-align: center;
                                    " class="mobile-padding mobile-text-center">
                                        <h1 style="
                                            margin: 0; 
                                            font-size: 24px; 
                                            font-weight: 600;
                                        ">📧 New Contact</h1>
                                    </td>
                                </tr>
        
                                <!-- Content -->
                                <tr>
                                    <td style="padding: 30px;" class="mobile-padding">
                                        <!-- Contact Info -->
                                        <table 
                                            role="presentation" 
                                            width="100%" 
                                            cellspacing="0" 
                                            cellpadding="0" 
                                            style="
                                                background-color: #f9fafb; 
                                                border-left: 5px solid #2575fc;
                                                padding: 20px;
                                                margin-bottom: 20px;
                                                border-radius: 6px;
                                            "
                                        >
                                            <tr>
                                                <td style="
                                                    color: #6b7280; 
                                                    font-weight: 600;
                                                    width: 120px;
                                                    padding-bottom: 10px;
                                                " class="mobile-text-center">Name</td>
                                                <td style="
                                                    color: #1f2937; 
                                                    font-weight: 500;
                                                    padding-bottom: 10px;
                                                " class="mobile-text-center">${name}</td>
                                            </tr>
                                            <tr>
                                                <td style="
                                                    color: #6b7280; 
                                                    font-weight: 600;
                                                    padding-bottom: 10px;
                                                " class="mobile-text-center">Email</td>
                                                <td style="
                                                    color: #2575fc; 
                                                    font-weight: 500;
                                                    padding-bottom: 10px;
                                                " class="mobile-text-center">${email}</td>
                                            </tr>
                                            <tr>
                                                <td style="
                                                    color: #6b7280; 
                                                    font-weight: 600;
                                                    vertical-align: top;
                                                " class="mobile-text-center">Timestamp</td>
                                                <td style="
                                                    color: #4b5563;
                                                " class="mobile-text-center">${new Date().toLocaleString()}</td>
                                            </tr>
                                        </table>
        
                                        <!-- Message Content -->
                                        <table 
                                            role="presentation" 
                                            width="100%" 
                                            cellspacing="0" 
                                            cellpadding="0" 
                                            style="
                                                background-color: #f9fafb; 
                                                border: 1px solid #e5e7eb;
                                                border-radius: 8px;
                                                padding: 20px;
                                            "
                                        >
                                            <tr>
                                                <td style="
                                                    color: #111827; 
                                                    font-weight: 600;
                                                    border-bottom: 2px solid #2575fc;
                                                    padding-bottom: 10px;
                                                    margin-bottom: 15px;
                                                ">Message Content</td>
                                            </tr>
                                            <tr>
                                                <td style="
                                                    color: #374151; 
                                                    line-height: 1.8; 
                                                    white-space: pre-wrap;
                                                    padding-top: 15px;
                                                ">${message}</td>
                                            </tr>
                                        </table>
        
                                        <!-- Footer Note -->
                                        <table 
                                            role="presentation" 
                                            width="100%" 
                                            cellspacing="0" 
                                            cellpadding="0" 
                                            style="margin-top: 25px;"
                                        >
                                            <tr>
                                                <td style="
                                                    text-align: center; 
                                                    color: #6b7280;
                                                    font-size: 12px;
                                                " class="mobile-text-center">
                                                    This is an automated message from your website's contact form.
                                                </td>
                                            </tr>
                                        </table>
                                    </td>
                                </tr>
        
                                <!-- Copyright -->
                                <tr>
                                    <td style="
                                        background-color: #f9fafb; 
                                        padding: 15px;
                                        text-align: center;
                                        border-top: 1px solid #e5e7eb;
                                    " class="mobile-text-center">
                                        <p style="
                                            margin: 0; 
                                            color: #6b7280;
                                        ">© ${new Date().getFullYear()} ANL Studio (By Muhammad Rizki Aulia)</p>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                </table>
            </body>
            </html>
            `,
        };

        transporter.sendMail(mailOptions, (err) => {
            if (err) {
                console.error('Error sending email:', err);
                return res.status(500).send('Failed to send email!');
            }

            res.send('Your message has been sent successfully!');
        });
    });
});

// Start Server
app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});
