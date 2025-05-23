# File Buddy - Developer Documentation

## Quick Start
For those familiar with Flask and MongoDB, here's the TL;DR:
1. Clone repo & install requirements
2. Set up .env with MongoDB & Gmail credentials
3. Run `python main.py`
Full setup instructions in "Project Setup Guide" below.


## File Dictionary

### Root Directory
- `main.py`: Entry point of the application. Initializes Flask app with debug mode and configures logging. Sets up the server to run on specified port.
- `Procfile`: Deployment configuration for Render. Contains command to run the application using gunicorn.
- `requirements.txt`: Lists all Python dependencies and their versions required to run the project.
- `.env`: Configuration file containing sensitive data like MongoDB URI, email credentials, and Flask secret key.

### /website Directory
- `__init__.py`: Flask application factory. Initializes MongoDB, Flask-Login, Flask-Mail, and registers blueprints. Sets up database collections and indexes.
- `models.py`: Defines User class and database operations. Handles user authentication, file metadata storage, and file count tracking.
- `account_routes.py`: Handles all user-related routes including authentication, profile management, and password recovery using email verification.
- `file_routes.py`: Manages file operations including upload, download, deletion, and password protection using GridFS for file storage.

### /website/templates
- `base.html`: Base template with navigation bar, footer, and common styling. All other templates extend from this.
- `index.html`: Landing page template showing welcome message and login/signup options.
- `login.html`: User login form with email and password fields.
- `signup.html`: Registration form collecting username, email, and password.
- `emailverify.html`: Email verification page for new user registration.
- `home.html`: Dashboard template showing user's overview after login.
- `upload.html`: File upload interface with file selection and optional password protection.
- `browse.html`: File browsing interface with search, filtering, and file management options.
- `profile.html`: User profile page showing account details and uploaded files.
- `developers.html`: Team information page with developer profiles.
- `forgot1.html`, `forgot2.html`, `forgot3.html`: Three-step password recovery process templates.

### /website/static
- `css/`: Contains custom CSS styles for the application.
- Logo files: `logo-qcu.png`, `logo-filebuddy.png` for branding.
- Profile pictures: Various `.jpg` and `.jfif` files for team members.

## Project Setup Guide

## Project Setup Guide

### 1. Local Development Setup
1. Clone the repository:
   ```bash
   git clone https://github.com/eybruhm/file-buddy.git
   cd file-buddy
   ```

2. Create and activate virtual environment:
   ```bash
   python -m venv venv
   venv\Scripts\activate  # On Windows
   source venv/bin/activate  # On Unix/MacOS
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### 2. MongoDB Setup
1. Create MongoDB Atlas account at https://www.mongodb.com/cloud/atlas
2. Create new project and cluster
3. Set up database access:
   - Create database user with read/write permissions
   - Add IP address to access list (0.0.0.0/0 for all IPs)
4. Get connection string from Atlas
5. Install MongoDB Compass
6. Connect to Atlas using the connection string
7. Create database named "FileSharingDB"
8. Collections will be automatically created by the application:
   - users: Stores user information and file statistics
   - files: Stores file metadata
   - fs.files and fs.chunks: Created by GridFS for file storage

### 3. Environment Variables
Create `.env` file with these variables:
```
MONGO_URI=mongodb+srv://<username>:<password>@<cluster>.mongodb.net/FileSharingDB?retryWrites=true&w=majority
FLASK_SECRET_KEY=your_secret_key_here
MAIL_USERNAME=your_gmail_address
MAIL_PASSWORD=your_gmail_app_password
```

### 4. Email Setup (Gmail)
1. Enable 2-Step Verification in Google Account
2. Generate App Password:
   - Go to Google Account Security
   - Select App Passwords
   - Generate password for "Mail" app
   - Use this password in MAIL_PASSWORD environment variable

### 5. Render Deployment
1. Create new Web Service in Render
2. Connect to GitHub repository
3. Configure:
   - Build Command: `pip install -r requirements.txt`
   - Start Command: `gunicorn main:app`
   - Environment Variables: Add all from `.env`
4. Deploy

### 6. Important Notes
- MongoDB Atlas IP Whitelist: Add 0.0.0.0/0 to allow Render servers
- File Size: Default max upload size is 5GB per user [not finished/coded]
- Email: System uses Gmail SMTP for sending verification codes
- Security: All passwords are hashed before storage
- File Storage: Uses GridFS for efficient handling of large files

### 7. Development Tips
- Debug mode is enabled in main.py for local development
- Use MongoDB Compass to monitor database operations
- Check logs in Render dashboard for deployment issues
- Test email functionality with temporary email accounts
- Use git branches for new features



## Code Structure Documentation

### __init__.py Variables
- `mail`: Flask-Mail instance for handling email operations like verification and password reset.
- `mongo`: PyMongo instance for MongoDB database operations and GridFS file storage.
- `login_manager`: Flask-Login manager for handling user authentication and sessions.
- `logger`: Logging instance configured for application-wide error and info tracking.

### __init__.py Functions
- `create_app()`: Application factory that configures Flask app, initializes extensions, and sets up MongoDB collections and indexes.
- `load_user(user_id)`: User loader callback for Flask-Login to manage user sessions.

### models.py Classes
- `User`: UserMixin class implementing required Flask-Login methods for user authentication and session management.

### models.py Functions
- `update_user_file_counts(user_id)`: Updates user's file statistics by type (image, video, document, etc.).
- `create_user(username, email, password)`: Creates new user with hashed password and initializes storage metrics.
- `save_file_metadata(...)`: Stores uploaded file information in MongoDB with optional password protection.

### account_routes.py Routes
- `@home('/')`: Landing page with welcome message and authentication options.
- `@login('/login')`: User authentication with email and password validation.
- `@signup('/signup')`: New user registration with email verification.
- `@email_verification('/email_verification')`: Validates email verification code for new signups.
- `@dashboard('/dashboard')`: User's main dashboard after authentication.
- `@profile('/profile')`: User profile management and file statistics.
- `@browse('/browse')`: Search and browse files/users with filtering options.
- `@forgot_password_identify_email('/forgot-password-identify-email')`: Step 1 of password recovery.
- `@forgot_password_verify_otp('/forgot-password-verify-otp')`: Step 2 of password recovery with OTP.
- `@change_password('/change-password')`: Final step of password recovery process.
- `@update_username('/update-username')`: Updates user's username with validation.
- `@update_password('/update-password')`: Changes user's password with security checks.

### account_routes.py Functions
- `send_verification_email(email, code)`: Sends verification code for new user registration.
- `forgot_password_verification_email(email, code)`: Sends OTP for password recovery.
- `block_logged_in_users(f)`: Decorator preventing authenticated users from accessing auth pages.
- `require_forgot_email_identification(f)`: Decorator ensuring proper flow of password recovery.
- `require_verified_otp(f)`: Decorator validating OTP verification before password reset.

### file_routes.py Routes
- `@upload_file('/upload')`: Handles file uploads with optional password protection.
- `@download_file('/download/<file_id>')`: Securely serves files with password validation.
- `@verify_password('/verify-password')`: Validates password for protected file access.
- `@delete_file('/delete/<file_id>')`: Removes file from GridFS and updates user statistics.

### file_routes.py Functions
- `get_gridfs()`: Returns GridFS instance for file storage operations.

## Security Features
- Password hashing for user accounts and protected files
- Email verification for new registrations
- OTP-based password recovery
- Session management for secure file access
- GridFS for secure file storage
- Rate limiting on sensitive operations [not implemented yet]

## Database Schema
- Users Collection: Stores user profiles, authentication, and file statistics
- Files Collection: Maintains file metadata and access controls
- GridFS: Handles actual file storage and retrieval

## Future Enhancements
- Implement file sharing between users
- Add file version control
- Enable file preview for supported formats
- Implement rate limiting
- Add user storage quotas
- Enable file expiration dates 