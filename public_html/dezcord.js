//index.js for dezcord
const express = require("express");
const app = express();
const axios = require('axios');
const cheerio = require('cheerio'); //for real time code snippets
const bodyParser = require('body-parser');
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const multer = require("multer");
const json2csv = require("json2csv").parse;
//const fs = require('fs');
const fs = require('fs-extra');
const path = require('path');
const YOUR_DOMAIN = 'https://dezcord.com';
const nodemailer = require("nodemailer");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const dotenv = require("dotenv");
const envPath = path.resolve(__dirname, "../config/index.env"); // Adjust the path as per your file location

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

dotenv.config({ path: envPath });

console.log(process.env.DB_HOST);
const transporter = nodemailer.createTransport({
    sendmail: true,
    newline: "unix",
    path: "/usr/sbin/sendmail", // Path to the sendmail command
});

// Initialize session middleware (login and authentication)
app.use(session({
    secret: "your-secret-key",
    resave: false,
    saveUninitialized: false,
}));

// Initialize Passport and configure it to use the LocalStrategy for authentication
app.use(passport.initialize());
app.use(passport.session());
passport.use(
    new LocalStrategy(
        {
            usernameField: "email",
            passwordField: "password",
        },
        async (email, password, done) => {
            try {
                const query = {
                    text: "SELECT * FROM users WHERE email = $1",
                    values: [email],
                };
                const result = await pool.query(query);
                const user = result.rows[0];

                if (!user) {
                    return done(null, false, { message: "Invalid email or password" });
                }

                const isPasswordMatch = await bcrypt.compare(password, user.password);
                if (!isPasswordMatch) {
                    return done(null, false, { message: "Invalid email or password" });
                }

                return done(null, user);
            } catch (err) {
                return done(err);
            }
        }
    )
);

// Serialize and deserialize user objects for session management:
passport.serializeUser((user, done) => {
    done(null, user.id);
});

// Update the deserialization logic in the passport.deserializeUser function to include the is_superuser property:
passport.deserializeUser(async (id, done) => {
    try {
        const query = {
            text: "SELECT * FROM users WHERE id = $1",
            values: [id],
        };
        const result = await pool.query(query);
        const user = result.rows[0];
        done(null, {
            id: user.id,
            email: user.email,
            isSuperUser: user.is_superuser, // Add isSuperUser property
        });
    } catch (err) {
        done(err);
    }
});

// Set up body parser for handling POST requests
app.use(express.urlencoded({ extended: true }));

// PostgreSQL database envars
const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_DATABASE,
    password: process.env.DB_PASSWORD,
});

// Test the database connection and console.log the status
pool.connect((err) => {
    if (err) {
        console.error("Error connecting to database", err.stack);
    } else {
        console.log("Connected to database");
    }
});

// Serve static files from the "resources" directory
app.use("/resources", express.static(path.join(__dirname, "resources")));

// Generate a random token of specified length (default 20 characters)
function generateToken(length = 20) {
    const characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let token = "";

    for (let i = 0; i < length; i++) {
        const randomIndex = Math.floor(Math.random() * characters.length);
        token += characters.charAt(randomIndex);
    }

    // Ensure token length is exactly 'length'
    while (token.length < length) {
        const randomIndex = Math.floor(Math.random() * characters.length);
        token += characters.charAt(randomIndex);
    }

    return token;
}

// Google OAUTH settings: has to be below the setup for envars
const GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
////////// STANDARD GOOGLE LOGIN -----------------------IN 
passport.use("google", new GoogleStrategy({
    clientID: GOOGLE_CLIENT_ID,
    clientSecret: GOOGLE_CLIENT_SECRET,
    callbackURL: "https://dezcord.com/auth/google/callback" // Update the callback URL
},

    async function (accessToken, refreshToken, profile, done) {
        try {
            // Check if the user already exists in the database based on the Google ID
            const query = {
                text: "SELECT * FROM users WHERE google_id = $1",
                values: [profile.id],
            };
            const result = await pool.query(query);
            let user = result.rows[0];

            if (!user) {
                // If the user does not exist, create a new user record with default values for missing fields
                const token = generateToken(); // Generate a new token only if it doesn't exist
                const email = profile.emails ? profile.emails[0].value : null;
                const insertQuery = {
                    text: "INSERT INTO users (google_id, google_email, google_display_name, first_name, last_name, email, password, token, created_at) VALUES ($1, $2, $3, $4, $5, $6, 'google', $7, CURRENT_TIMESTAMP) RETURNING *",
                    values: [profile.id, email, profile.displayName, profile.displayName, profile.displayName, email, token]
                };

                const insertResult = await pool.query(insertQuery);
                user = insertResult.rows[0];

            } else {
                // If the user exists, update their information with the Google data
                if (!user.token) { // Only generate a new token if one doesn't already exist
                    user.token = generateToken();
                    const updateTokenQuery = {
                        text: "UPDATE users SET token = $1 WHERE google_id = $2",
                        values: [user.token, profile.id],
                    };
                    await pool.query(updateTokenQuery);
                }

                const email = profile.emails ? profile.emails[0].value : null;
                const updateQuery = {
                    text: "UPDATE users SET google_email = $1, google_display_name = $2, last_name = $3 WHERE google_id = $4 RETURNING *",
                    values: [email, profile.displayName, 'google', profile.id],
                };
                const updateResult = await pool.query(updateQuery);
                user = updateResult.rows[0];

            }

            return done(null, user);
        } catch (err) {
            return done(err);
        }
    }));

// Handle Google Sign-In callback
app.get('/auth/google',
    passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback',
    passport.authenticate('google', { failureRedirect: '/login' }),
    (req, res) => {
        console.log("google auth");
        const userToken = req.user.token;
        console.log("User token after Google OAuth:", userToken);
        // Successful authentication, redirect to user portal
        res.redirect('/user-portal');
    }
);
////////// STANDARD GOOGLE LOGIN -----------------------OUT 

// STRIPE Declared after req variables
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

// Standard Checkout
app.post('/standardCheckoutSession', async (req, res) => {
    const userId = req.user.id;

    const session = await stripe.checkout.sessions.create({
        line_items: [
            {
                price: 'price_1PYMIMLDHsl47WVWml4Od97a',

                quantity: 1,
            },
        ],
        mode: 'subscription',
        //mode: 'payment',
        success_url: 'https://dezcord.com/success',
        cancel_url: 'https://dezcord.com/cancel',
        client_reference_id: userId
    });

    console.log(session);
    res.redirect(session.url);
});


// Define the GET route for /login
app.get("/login", (req, res) => {
    res.render("login");
});

// Implement the login route with Passport's authenticate method:
app.post("/login", (req, res, next) => {
    console.log("Login request received");
    passport.authenticate("local", (err, user, info) => {
        if (err) {
            console.error("Error during authentication:", err);
            return next(err);
        }
        if (!user) {
            console.log("Invalid email or password");
            res.render('index', { message: 'Invalid email or password' });
        }
        req.logIn(user, (err) => {
            if (err) {
                console.error("Error logging in:", err);
                return next(err);
            }
            console.log("User logged in:", user);
            return res.redirect("/user-portal");
        });
    })(req, res, next);
});

// Protect routes using authentication middleware
function authenticate(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect("/");
}

// Middleware for parsing JSON data
app.use(bodyParser.urlencoded({ extended: true }));

app.use(express.json());

app.get("/reset-password", (req, res) => {
    res.render("reset-password");
});

app.get("/reset-success", (req, res) => {
    res.render("reset-success");
});

// Generate a random token using our function
function generateResetToken() {
    const token = generateToken(20); // Generate a random token of length 20
    console.log("Reset Token:", token);
    return token;
}

// Generate a random token using our function
function generateRandomToken() {
    const token = generateToken(20); // Generate a random token of length 20
    console.log("Random Token Generated:", token);
    return token;
}

// Password reset request
app.post("/reset-password", async (req, res) => {
    const { email } = req.body;
    console.log("Password reset request received for email:", email);
    const query = {
        text: "SELECT * FROM users WHERE email = $1",
        values: [email],
    };
    try {
        const result = await pool.query(query);
        const user = result.rows[0];
        console.log("Password reset token generated/reset for email:", email);
        if (!user) {
            return res.status(404).send("User not found");
        }
        // Generate a password reset token using our function
        const resetToken = generateResetToken();

        // Save the reset token and its expiration time in the user's record
        user.resetToken = resetToken;
        user.resetTokenExpiry = new Date().toISOString(); // Set resetTokenExpiry to the current time

        // Update the user's record in the database
        const updateQuery = {
            text: "UPDATE users SET reset_token = $1, reset_token_expiry = $2 WHERE id = $3",
            values: [resetToken, user.resetTokenExpiry, user.id],
        };
        await pool.query(updateQuery);

        // Send the password reset email
        const resetLink = `https://dezcord.com/reset-password/${resetToken}`;
        const mailOptions = {
            from: "service@vineform.com",
            to: email,
            subject: "dezcord Password Reset",
            text: `To reset your password, click the following link: ${resetLink}`,
        };
        await transporter.sendMail(mailOptions);
        console.log("Password reset email sent for email:", email);
        res.render("check-email");
    } catch (err) {
        console.error("Error resetting password:", err);
        res.status(500).send("Error resetting password");
    }
});

app.get("/reset-form", (req, res) => {
    res.render("reset-form");
});

app.get("/reset-password/:token", async (req, res) => {
    const { token } = req.params;
    const query = {
        text: "SELECT * FROM users WHERE reset_token = $1",
        values: [token],
    };
    try {
        const result = await pool.query(query);
        const user = result.rows[0];

        if (!user || new Date(user.reset_token_expiry) < new Date()) {
            return res.status(400).send("Invalid or expired reset token");
        }

        // Render the password reset form with the token
        res.render("reset-form");

    } catch (err) {
        console.error("Error verifying reset token:", err);
        res.status(500).send("Error verifying reset token");
    }
});

app.post("/reset-password/:token", async (req, res) => {
    const { token } = req.params;
    const { password } = req.body;
    console.log("Password reset form submitted with token:", token);
    const query = {
        text: "SELECT * FROM users WHERE reset_token = $1",
        values: [token],
    };
    try {
        const result = await pool.query(query);
        const user = result.rows[0];
        console.log("Password reset successful for token:", token);
        if (!user || new Date(user.reset_token_expiry) < new Date()) {
            return res.status(400).send("Invalid or expired reset token");
        }

        // Update the user's password with the new password
        const hashedPassword = await bcrypt.hash(password, 10);
        const updateQuery = {
            text: "UPDATE users SET password = $1, reset_token = NULL WHERE id = $2",
            values: [hashedPassword, user.id],
        };
        await pool.query(updateQuery);

        res.render("reset-success");
        console.log("Password reset successfully for token:", token);
    } catch (err) {
        console.error("Error resetting password:", err);
        res.status(500).send("Error resetting password");
    }
});

// Define the GET route for /check-email
app.get("/check-email", (req, res) => {
    res.render("check-email");
});


app.get('/privacy-policy', (req, res) => {
    res.render('privacy-policy');
});

app.get('/tos', (req, res) => {
    res.render('tos');
});

async function updateUser(req, userId, stripeUserId, amountDue) { // Include req as a parameter
    try {
        let serviceType;
        let expirationInterval;

        // Determine service type based on amount due
        if (amountDue === 500) {
            serviceType = 'blue';
            expirationInterval = '30 days';
        } else if (amountDue === 300) {
            serviceType = 'standard';
            expirationInterval = '30 days';
        } else if (amountDue === 200) {
            serviceType = 'chrome';
            expirationInterval = '48 hours';
        } else if (amountDue === 2000) {
            serviceType = 'gold';
            expirationInterval = '30 days'; // Corrected expiration for gold
        } else {
            // Handle other cases if necessary
            serviceType = 'unknown';
            expirationInterval = '0'; // Set expiration to zero for unknown service type
        }

        // Log the user ID, service type, and Stripe user ID
        console.log('User ID:', userId);
        console.log('Service Type:', serviceType);
        console.log('Stripe User ID:', stripeUserId);

        // Construct and execute the update query updated w/expiration date
        const updateQuery = `
        UPDATE users
        SET service_type = $1,
            stripe_user_id = $2,
            service_exp_date = NOW() + INTERVAL '${expirationInterval}' -- Add service expiration date
        WHERE id = $3
        RETURNING *;`;

        pool.query(updateQuery, [serviceType, stripeUserId, userId], (err, result) => {
            if (err) {
                console.error('Error updating user information:', err);
                return; // No need to send a response here; it's handled in the route handler
            }
            console.log('User information updated successfully');
            // Send response or perform further actions if needed
        });
    } catch (error) {
        console.error('Error updating user information:', error);
        throw error; // Rethrow the error for handling in the calling function
    }
}

// Define endpoint to handle Stripe webhook events
app.post('/stripeData', async (req, res) => {
    try {
        // Retrieve event data from the request body
        const eventData = req.body;

        // Check if the event type is 'checkout.session.completed'
        if (eventData.type === 'checkout.session.completed') {
            // Log the inbound data
            console.log('Incoming data for checkout.session.completed event:');
            console.log(eventData);

            // Extract user ID from the client_reference_id field
            const userId = eventData.data.object.client_reference_id;

            // Extract relevant data from the event
            const { amount_total: amountTotal } = eventData.data.object;

            // Extract Stripe user ID from customer
            const stripeUserId = eventData.data.object.customer;

            // Update user information in the database
            await updateUser(req, userId, stripeUserId, amountTotal); // Pass req as a parameter

            // Respond with a 200 status to acknowledge receipt of the event
            res.status(200).send('Webhook received successfully');
        } else {
            // If the event type is not 'checkout.session.completed', ignore the event
            res.status(200).send('Event ignored');
        }
    } catch (error) {
        console.error('Error processing webhook event:', error);
        // Respond with an error status if there's an issue processing the event
        res.status(500).send('Error processing webhook event');
    }
});

app.get("/", async (req, res) => {
    if (req.isAuthenticated()) {
        try {
            const userId = req.user.id; // Assuming your user object has an id field

            // Fetch the user's token and theme preference from the database
            const query = 'SELECT token, set_theme, dark_mode FROM users WHERE id = $1';
            const { rows } = await pool.query(query, [userId]);
            const user = rows[0];

            // Ensure user data is present
            if (!user) {
                throw new Error("User not found");
            }

            const userToken = user.token;
            const theme = user.dark_mode ? 'dark' : 'light';

            console.log("User token:", userToken); // Log userToken for debugging

            res.render("home", {
                isAuthenticated: true,
                userToken,
                theme
            });
        } catch (error) {
            console.error("Error retrieving user data:", error);
            res.render("home", {
                isAuthenticated: false,
                userToken: null,
                theme: 'light'
            });
        }
    } else {
        res.render("home", {
            isAuthenticated: false,
            userToken: null,
            theme: 'light'
        });
    }
});
app.get("/home2", async (req, res) => {
    if (req.isAuthenticated()) {
        try {
            const userId = req.user.id; // Assuming your user object has an id field

            // Fetch the user's token and theme preference from the database
            const query = 'SELECT token, set_theme, dark_mode FROM users WHERE id = $1';
            const { rows } = await pool.query(query, [userId]);
            const user = rows[0];

            // Ensure user data is present
            if (!user) {
                throw new Error("User not found");
            }

            const userToken = user.token;
            const theme = user.dark_mode ? 'dark' : 'light';

            console.log("User token:", userToken); // Log userToken for debugging

            res.render("home", {
                isAuthenticated: true,
                userToken,
                theme
            });
        } catch (error) {
            console.error("Error retrieving user data:", error);
            res.render("home2", {
                isAuthenticated: false,
                userToken: null,
                theme: 'light'
            });
        }
    } else {
        res.render("home2", {
            isAuthenticated: false,
            userToken: null,
            //theme: 'light'
        });
    }
});

// Registration route
app.post("/register", async (req, res) => {
    const { first_name, last_name, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const token = generateToken();

    try {
        // Insert new user into the database
        const insertQuery = {
            text: "INSERT INTO users (first_name, last_name, email, password, token, created_at) VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP) RETURNING *",
            values: [first_name, last_name, email, hashedPassword, token],
        };

        const insertResult = await pool.query(insertQuery);
        const user = insertResult.rows[0];

        if (!user) {
            console.error("Error creating user: User data not found");
            return res.status(500).send("Error creating user");
        }

        // Store user ID in session to keep them logged in
        req.session.userId = user.id;

        // Log in the user after successful registration
        req.login(user, (err) => {
            if (err) {
                console.error("Error logging in:", err);
                return res.status(500).send("Error logging in: " + err.message);
            }
            console.log("User logged in:", user);

            // Redirect to the home page
            res.redirect('/user-portal');
        });
    } catch (err) {
        console.error("Error creating user:", err);
        res.status(500).send("Error creating user: " + err.message);
    }
});

app.get("/user-portal", authenticate, async (req, res) => {
    try {
        const userId = req.user.id; // Assuming req.user contains the authenticated user's info

        // Fetch the user's theme preference from the database
        const query = 'SELECT set_theme, dark_mode FROM users WHERE id = $1';
        const { rows } = await pool.query(query, [userId]);
        const userPreferences = rows[0] || { set_theme: false, dark_mode: false };

        // Render the user-portal view with the user's theme preferences
        res.render("user-portal", {
            isAuthenticated: true,
            theme: userPreferences.dark_mode ? 'dark' : 'light'
        });
    } catch (error) {
        console.error('Error fetching user preferences:', error);
        res.status(500).send('Internal Server Error');
    }
});

// Route handler for updating the email address
app.post('/updateEmail', async (req, res) => {
    try {
        if (!req.isAuthenticated()) {
            return res.status(401).json({ error: 'User not authenticated' });
        }

        const userId = req.user.id; // Assuming your user object has an id field
        const { email } = req.body;

        // Update the user's fwd_addr1 in the database
        const updateQuery = {
            text: 'UPDATE users SET fwd_addr1 = $1 WHERE id = $2 RETURNING *',
            values: [email, userId],
        };

        const updateResult = await pool.query(updateQuery);

        res.status(200).json({ message: 'Email updated successfully' });
    } catch (error) {
        console.error('Error updating email:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/toggle-theme', authenticate, async (req, res) => {
    try {
        const userId = req.user.id; 
        const { set_theme, dark_mode } = req.body;

        const query = `
        UPDATE users
        SET set_theme = $1, dark_mode = $2
        WHERE id = $3
      `;
        const values = [set_theme, dark_mode, userId];

        await pool.query(query, values);
        res.json({ success: true });
    } catch (error) {
        console.error('Error updating theme preferences:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

// Serve any file requested ie twittercard.png
app.get("/resources/:file", (req, res) => {
    const fileName = req.params.file;
    const filePath = path.join(__dirname, "resources", fileName);
    res.sendFile(filePath, (err) => {
        if (err) {
            res.status(404).send("File not found");
        }
    });
});

// Set up multer for file uploads
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const uploadPath = path.join(__dirname, '..', 'userData');
        fs.ensureDirSync(uploadPath);
        cb(null, uploadPath);
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + generateRandomToken(20);
        cb(null, uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({ storage: storage });

app.post('/userImageUpload', upload.single('file2'), async (req, res) => {
    console.log(req.body); // Log the entire body to debug
    let userName = req.body.userName;

    // Check if userName is an array
    if (Array.isArray(userName)) {
        userName = userName[0]; // Get the first value
    }

    if (typeof userName === 'string') {
        userName = userName.trim();
    } else {
        console.error('userName is not a string:', userName);
        return res.status(400).send('Invalid user name.');
    }

    if (!userName) {
        return res.status(400).send('User name is required.');
    }

    if (!req.file) {
        return res.status(400).send('No file uploaded.');
    }

    const userId = req.user.id;

    try {
        const client = await pool.connect();

        // Check for duplicate user name
        const duplicateCheckQuery = 'SELECT 1 FROM chat WHERE user_id = $1 AND user_name = $2';
        const duplicateCheckValues = [userId, userName];
        const duplicateCheckResult = await client.query(duplicateCheckQuery, duplicateCheckValues);

        if (duplicateCheckResult.rowCount > 0) {
            // Duplicate user name found
            client.release();
            return res.status(409).send('User name already exists.');
        }

        // Update all existing rows for this user in the chat table
        const updateQuery = 'UPDATE chat SET user_name = $1 WHERE user_id = $2';
        await client.query(updateQuery, [userName, userId]);

        // Insert the new profile picture
        const newProfilePicture = req.file.filename;
        const insertQuery = 'INSERT INTO chat (user_name, user_id, profile_picture) VALUES ($1, $2, $3)';
        await client.query(insertQuery, [userName, userId, newProfilePicture]);

        client.release();

        res.status(200).send('File uploaded and data saved successfully, user name updated.');
    } catch (err) {
        console.error('Error inserting or updating data:', err);
        res.status(500).send('Error saving data to the database.');
    }
});

app.post('/serverImageUpload', upload.single('file'), async (req, res) => {
    console.log(req.body); // Log the entire body to debug
    let serverName = req.body.serverName;

    // Check if serverName is an array
    if (Array.isArray(serverName)) {
        serverName = serverName[0]; // Get the first value
    }

    if (typeof serverName === 'string') {
        serverName = serverName.trim();
    } else {
        console.error('serverName is not a string:', serverName);
        return res.status(400).send('Invalid server name.');
    }

    if (!serverName) {
        return res.status(400).send('Server name is required.');
    }

    if (!req.file) {
        return res.status(400).send('No file uploaded.');
    }

    const userId = req.user.id;

    try {
        const client = await pool.connect();

        // Check for duplicate server name
        const duplicateCheckQuery = 'SELECT 1 FROM chat WHERE user_id = $1 AND server_name = $2';
        const duplicateCheckValues = [userId, serverName];
        const duplicateCheckResult = await client.query(duplicateCheckQuery, duplicateCheckValues);

        if (duplicateCheckResult.rowCount > 0) {
            // Duplicate server name found
            client.release();
            return res.status(409).send('Server name already exists.');
        }

        const serverId = generateRandomToken(20);
        const attachmentUniqueId = req.file.filename;

        const insertQuery = 'INSERT INTO chat (server_name, server_id, user_id, attachment_unique_id) VALUES ($1, $2, $3, $4)';
        const insertValues = [serverName, serverId, userId, attachmentUniqueId];

        await client.query(insertQuery, insertValues);
        client.release();

        res.status(200).send('File uploaded and data saved successfully.');
    } catch (err) {
        console.error('Error inserting data:', err);
        res.status(500).send('Error saving data to the database.');
    }
});

// Middleware to serve images securely
app.get('/userImage/:filename', (req, res) => {
    const userId = req.user.id; // Ensure you have a way to get the logged-in user's ID
    const filename = req.params.filename;

    // Query to check if the user owns the requested file
    const queryText = 'SELECT 1 FROM chat WHERE user_id = $1 AND attachment_unique_id = $2';
    const values = [userId, filename];

    pool.query(queryText, values, (err, result) => {
        if (err) {
            console.error('Database query error:', err);
            return res.status(500).send('Server error.');
        }

        if (result.rowCount > 0) {
            // User is authorized to access the file
            const filePath = path.join(__dirname, '..', 'userData', filename);
            res.sendFile(filePath);
        } else {
            // User is not authorized
            res.status(403).send('Forbidden');
        }
    });
});

app.get('/fetchUserServers', async (req, res) => {
    const userId = req.user.id; // Assuming req.user.id contains the logged-in user's ID

    console.log('Fetching user servers for user ID:', userId); // Log user ID

    try {
        const client = await pool.connect();
        const queryText = 'SELECT server_name, attachment_unique_id FROM chat WHERE user_id = $1';
        const values = [userId];

        console.log('Executing query:', queryText, values); // Log query and values

        const result = await client.query(queryText, values);
        client.release();

        console.log('Query result:', result.rows); // Log query result

        res.json(result.rows); // Send JSON response with queried data
    } catch (err) {
        console.error('Error fetching user servers:', err);
        res.status(500).send('Error fetching user servers.');
    }
});

// Middleware to serve profile pictures
app.get('/profilePicture/:filename', (req, res) => {
    const filename = req.params.filename;

    if (filename === 'purpleDefaultProfile.png') {
        // Serve the default profile picture
        const defaultPicturePath = path.join('/var/www/dezcord.com/public_html/resources', filename);
        return res.sendFile(defaultPicturePath);
    }

    // Check if the file exists in userData
    const filePath = path.join(__dirname, '..', 'userData', filename);

    fs.access(filePath, fs.constants.F_OK, (err) => {
        if (err) {
            // If file does not exist, serve the default profile picture
            const defaultPicturePath = path.join('/var/www/dezcord.com/public_html/resources', 'purpleDefaultProfile.png');
            return res.sendFile(defaultPicturePath);
        } else {
            // File exists, serve it
            return res.sendFile(filePath);
        }
    });
});

app.get('/fetchDefaultServerChannels', async (req, res) => {
    try {
        const client = await pool.connect();

        // Query to fetch channels
        const channelsQuery = 'SELECT user_name, channel_name FROM chat WHERE user_id = $1';
        const channelsResult = await client.query(channelsQuery, [0]);
        const channels = channelsResult.rows;

        // Query to fetch the most recent user_name and profile_picture from the chat table
        const userProfileQuery = `
            SELECT user_name, profile_picture
            FROM chat
            WHERE user_id = $1
            ORDER BY serial DESC
            LIMIT 1`;
        const userProfileResult = await client.query(userProfileQuery, [req.user.id]);
        const chatUserName = userProfileResult.rows[0]?.user_name;
        let profilePicture = userProfileResult.rows[0]?.profile_picture;

        // Determine username
        let username;
        if (chatUserName) {
            username = chatUserName;
        } else {
            // Fallback to token-based username if no user_name in chat table
            const userQuery = 'SELECT token FROM users WHERE id = $1';
            const userResult = await client.query(userQuery, [req.user.id]);
            const user = userResult.rows[0];
            username = `user.${user.token.slice(0, 10)}`;
        }

        // Determine profile picture URL
        if (!profilePicture) {
            profilePicture = '/profilePicture/purpleDefaultProfile.png';
        } else {
            profilePicture = `/profilePicture/${profilePicture}`;
        }

        client.release();

        res.status(200).json({ channels, username, profilePicture });
    } catch (err) {
        console.error('Error fetching default server channels:', err);
        res.status(500).send('Error fetching default server channels.');
    }
});

app.post('/submitChat', async (req, res) => {
    const { userName, chatText } = req.body;
    const userId = req.user.id; // Assuming user is authenticated and req.user is available

    try {
        const client = await pool.connect();

        // Query to fetch default chat details
        const chatDetailsQuery = 'SELECT server_name, server_id, channel_name, channel_id FROM chat WHERE user_id = $1 LIMIT 1';
        const chatDetailsResult = await client.query(chatDetailsQuery, [0]);
        const chatDetails = chatDetailsResult.rows[0];

        // Query to fetch user profile picture
        const profilePictureQuery = `
            SELECT COALESCE(profile_picture, 'purpleDefaultProfile.png') AS profile_picture
            FROM chat
            WHERE user_id = $1
            ORDER BY serial DESC
            LIMIT 1
        `;
        const profilePictureResult = await client.query(profilePictureQuery, [userId]);
        const profilePicture = profilePictureResult.rows[0].profile_picture;

        // Insert new chat message with username and profile picture
        const insertChatQuery = `
            INSERT INTO chat (server_name, server_id, channel_name, channel_id, user_id, user_name, chat_text, profile_picture)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        `;
        await client.query(insertChatQuery, [
            chatDetails.server_name,
            chatDetails.server_id,
            chatDetails.channel_name,
            chatDetails.channel_id,
            userId,
            userName,
            chatText,
            profilePicture
        ]);

        client.release();
        res.status(200).json({ success: true });
    } catch (err) {
        console.error('Error submitting chat:', err);
        res.status(500).send('Error submitting chat.');
    }
});

app.get('/fetchChatMessages', async (req, res) => {
    try {
        const client = await pool.connect();

        // Query to fetch chat messages along with the user's most recent profile picture
        const chatMessagesQuery = `
            SELECT 
                c.user_name, 
                c.chat_text, 
                c.timestamp, 
                COALESCE(
                    '/profilePicture/' || COALESCE(u.profile_picture, 'purpleDefaultProfile.png'),
                    '/profilePicture/purpleDefaultProfile.png'
                ) AS profile_picture
            FROM chat c
            LEFT JOIN LATERAL (
                SELECT profile_picture
                FROM chat
                WHERE user_id = c.user_id
                ORDER BY serial DESC
                LIMIT 1
            ) u ON true
            WHERE c.server_name = 'Treyark'
            ORDER BY c.timestamp DESC;
        `;

        const chatMessagesResult = await client.query(chatMessagesQuery);
        const chatMessages = chatMessagesResult.rows;

        client.release();
        res.status(200).json(chatMessages);
    } catch (err) {
        console.error('Error fetching chat messages:', err);
        res.status(500).send('Error fetching chat messages.');
    }
});

app.listen(3010, () => {
    console.log("Server listening on port 3010");
});