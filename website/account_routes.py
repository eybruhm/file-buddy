from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from flask_mail import Message
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import random
import os
from . import mongo, mail
from .models import User
from functools import wraps


# Define the Blueprint
account_routes = Blueprint('account_routes', __name__)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.login_view = "account_routes.login"  # Redirect unauthorized users to login page

# ✅ Load User Function (Needed for Flask-Login)
@login_manager.user_loader
def load_user(user_id):
    user = mongo.db.users.find_one({"_id": user_id})  # Find user in database
    if user:
        return User(user_id=str(user["_id"]), username=user["username"], email=user["email"])
    return None

# 🔐 DECORATOR 1: BLOCK ACCESS IF USER IS LOGGED IN
def block_logged_in_users(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # ✅ If a user is already logged in, they should not access forgot password or signup/login routes
        if current_user.is_authenticated:
            flash("You are already logged in.", "warning")
            return redirect(url_for('account_routes.dashboard'))  # 🔄 Redirect to dashboard
        return f(*args, **kwargs)  # ✅ Continue to route function if not logged in
    return decorated_function


# 🔐 DECORATOR 2: REQUIRE EMAIL IDENTIFICATION (STEP 1 OF FORGOT PASSWORD)
def require_forgot_email_identification(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # ✅ Prevent access if user is already logged in
        if current_user.is_authenticated:
            flash("You are already logged in.", "warning")
            return redirect(url_for('account_routes.dashboard'))  # 🔄 Redirect to dashboard

        # 🔍 Check if the session has the required email + OTP data from step 1
        if 'forgot_password_data' not in session:
            flash("You must verify your email first.", "warning")
            return redirect(url_for('account_routes.forgot_password_identify_email'))  # ⛔ Block access and redirect to step 1
        return f(*args, **kwargs)  # ✅ Continue to route function if session is valid
    return decorated_function


# 🔐 DECORATOR 3: REQUIRE OTP VERIFIED BEFORE RESET PASSWORD
def require_verified_otp(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # 🚫 Block if user is already logged in
        if current_user.is_authenticated:
            flash("You are already logged in.", "warning")
            return redirect(url_for('account_routes.dashboard'))

        # 🔍 Get the session data
        forgot_data = session.get('forgot_password_data')

        # 🔒 Block if no session or OTP not verified
        if not forgot_data or not forgot_data.get('otp_verified'):
            flash("Please verify the OTP sent to your email first.", "warning")
            return redirect(url_for('account_routes.forgot_password_verify_otp'))

        # ✅ Passed all checks
        return f(*args, **kwargs)
    return decorated_function




# ===========================
# 🚀 HOME ROUTE (Redirect logged-in users)
# ===========================
@account_routes.route('/')
def home():
    if current_user.is_authenticated:  # ✅ If logged in, redirect to dashboard
        return redirect(url_for('account_routes.dashboard'))
    return render_template('index.html')

# ===========================
# 🚀 LOGIN ROUTE (Redirect logged-in users)
# ===========================
@account_routes.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:  # ✅ If logged in, redirect to dashboard
        return redirect(url_for('account_routes.dashboard'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # 🔹 Find user by email
        user = mongo.db.users.find_one({"email": email})

        if not user:
            flash("Email not found. Please sign up.", "danger")
            return redirect(url_for('account_routes.login'))  # Redirect to login page
        
        # 🔹 Check if password matches
        if not check_password_hash(user["password_hashed"], password):
            flash("Incorrect password. Please try again.", "danger")
            return redirect(url_for('account_routes.login'))

        # ✅ Create a User instance
        user_obj = User(user_id=str(user["_id"]), username=user["username"], email=user["email"])

        # ✅ Log in the user (Flask-Login handles session)
        login_user(user_obj)

        flash(f"Welcome, {user['username']}!", "success")
        return redirect(url_for('account_routes.dashboard'))  # 🚀 Redirect after login

    return render_template('login.html')


# ===========================
# 🚀 FORGOT PASSWORD 1 ROUTE [FOR LOGIN.HTML TO REDIRECT TO FORGOT1.HTML]
# ===========================
@account_routes.route('/forgot-password')
def forgot_password():
    return render_template('forgot1.html')


# ===========================
# 🚀 DASHBOARD ROUTE (Restrict non-logged-in users)
# ===========================
@account_routes.route('/dashboard')
@login_required  # ✅ Restrict access to logged-in users
def dashboard():
    return render_template('home.html', username=current_user.username)

# # # # # # # # # # # # # # # # # # # # # # # # # # # # 
# # # # # # # # # # # # # # # # # # # # # # # # # # # # 
# # # # # # # # # # # # # # # # # # # # # # # # # # # # 
@account_routes.route('/upload')
@login_required  # ✅ Restrict access to logged-in users
def upload():
    return render_template('upload.html', username=current_user.username)

@account_routes.route('/browse')
@login_required  # ✅ Restrict access to logged-in users
def browse():
    return render_template('browse.html', username=current_user.username)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # 
# # # # # # # # # # # # # # # # # # # # # # # # # # # # 
# # # # # # # # # # # # # # # # # # # # # # # # # # # # 

# ===========================
# 🚀 LOGOUT ROUTE
# ===========================
@account_routes.route('/logout')
@login_required  # ✅ Only logged-in users can log out
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('account_routes.login'))


# ===========================
# 🚀 SIGNUP ROUTE (Redirect logged-in users)
# ===========================
@account_routes.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:  # ✅ If logged in, redirect to dashboard
        return redirect(url_for('account_routes.dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # 🔹 Validate username length (2-15 characters)
        if len(username) < 2 or len(username) > 15:
            flash('Username must be between 2 and 15 characters.', 'danger')
            return redirect(url_for('account_routes.signup'))

        # 🔹 Validate password length (minimum 8 characters)
        if len(password) < 8:
            flash('Password must be at least 8 characters long.', 'danger')
            return redirect(url_for('account_routes.signup'))

        # 🔹 Check if passwords match
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('account_routes.signup'))

        # 🔹 Check if email already exists
        existing_user = mongo.db.users.find_one({"email": email})
        if existing_user:
            flash('Email is already registered. Please log in.', 'danger')
            return redirect(url_for('account_routes.signup'))
        
        # 🔹 Check if username already exists
        existing_user = mongo.db.users.find_one({"username": username})
        if existing_user:
            flash('Username is already taken. Please change it.', 'danger')
            return redirect(url_for('account_routes.signup'))

        # ✅ If all checks pass, generate a 6-digit verification code
        verification_code = str(random.randint(100000, 999999))

        # 🔹 Store verification data in session (Temporary storage)
        session['signup_data'] = {
            'username': username,
            'email': email,
            'password': generate_password_hash(password),  # Hash password for security
            'verification_code': verification_code  # Store the generated code
        }

        # 🔹 Send email verification code
        send_verification_email(email, verification_code)

        # ✅ Redirect to email verification page
        return redirect(url_for('account_routes.email_verification'))

    return render_template('signup.html')


# ===========================
# 🚀 EMAIL VERIFICATION ROUTE
# ===========================
@account_routes.route('/email_verification', methods=['GET', 'POST'])
def email_verification():
    if current_user.is_authenticated:  # ✅ If logged in, redirect to dashboard
        return redirect(url_for('account_routes.dashboard'))

    if request.method == 'POST':
        entered_code = request.form.get('verification_code')

        # 🔹 Get stored data from session
        signup_data = session.get('signup_data')

        if not signup_data:
            flash('Session expired. Please sign up again.', 'danger')
            return redirect(url_for('account_routes.signup'))

        # 🔹 Check if the entered code matches the stored code
        if entered_code == signup_data['verification_code']:
            # ✅ Insert user into database
            mongo.db.users.insert_one({
                "username": signup_data['username'],
                "email": signup_data['email'],
                "password_hashed": signup_data['password'],  # Already hashed password
                "created_at": mongo.db.command("serverStatus")["localTime"],
                "profile_picture": "",
                "storage_used": 0,
                "max_storage": 5000000000,  # 5GB limit
                "total_uploads": 0,
                "uploads_count": {
                    "image": 0, "video": 0, "docs": 0, "compressed": 0, "code": 0
                }
            })

            # ✅ Clear session data (No longer needed)
            session.pop('signup_data', None)

            # ✅ Redirect to dashboard
            flash('Account created successfully! You can now log in.', 'success')
            return redirect(url_for('account_routes.dashboard'))
        else:
            flash('Invalid verification code. Please try again.', 'danger')

    return render_template('emailverify.html')



# ===========================
# 🚀 SIGN UP EMAIL VERIFICATION RESEND CODE [EMAILVERIFY.HTML]
# ===========================
@account_routes.route('/resend_verification', methods=['POST'])
def resend_verification():
    if current_user.is_authenticated:  # ✅ Prevent logged-in users from resending
        return redirect(url_for('account_routes.dashboard'))

    signup_data = session.get('signup_data')
    if not signup_data:
        flash("Session expired. Please sign up again.", "danger")
        return redirect(url_for('account_routes.signup'))

    email = signup_data['email']
    new_code = str(random.randint(100000, 999999))

    # ✅ Update the stored session code
    session['signup_data']['verification_code'] = new_code

    # ✅ Resend the email
    send_verification_email(email, new_code)

    flash("New verification code sent to your email.", "success")
    return redirect(url_for('account_routes.email_verification'))

# ===========================
# 🚀 SIGN UP EMAIL VERIFICATION
# ===========================
def send_verification_email(email, code):
    try:
        msg = Message(subject="Your File Buddy Sign-Up Code is Here!", sender=("File Buddy Sign-Up", "filebuddy.6@gmail.com"), recipients=[email])
        msg.body = f"Heres your OTP: {code}"
        # Email body with the verification code
        msg.html = f"""
        <html>
        <body>
            <p>Hello,</p>
            <p>Thank you for signing up with File Buddy. To complete your registration, please use the code below to verify your email address.</p>
            <p><strong>Verification Code: {code}</strong></p>
            <p>If you did not initiate this registration, please disregard this email.</p>
            <p>Sincerely,<br>The File Buddy Team</p>
        </body>
        </html>
        """
        mail.send(msg)
        print(f"Verification code {code} sent to {email}")
    except Exception as e:
        print(f"Failed to send email: {str(e)}")



# ===========================
# 🚀 FORGOT PASSWORD EMAIL VERIFICATION
# ===========================
def forgot_password_verification_email(email, code):
    try:
        msg = Message(subject="Your File Buddy Password Reset Code is Here!", sender=("File Buddy Forgot Password", "filebuddy.6@gmail.com"), recipients=[email])
        msg.html = f"""
        <html>
        <body>
            <p>Hello,</p>
            <p>A password reset request was made for your File Buddy account. To reset your password, please use the code below:</p>
            <p><strong>Reset Code: {code}</strong></p>
            <p>If you didn't request this, please ignore this message.</p>
            <p>Sincerely,<br>The File Buddy Team</p>
        </body>
        </html>
        """

        mail.send(msg)
        print(f"Verification code {code} sent to {email}")
    except Exception as e:
        print(f"Failed to send email: {str(e)}")

# ===========================
# 🚀 FORGOT PASSWORD STEP 1: IDENTIFY EMAIL 
# ===========================
@account_routes.route('/forgot-password-identify-email', methods=['GET', 'POST'])
@block_logged_in_users  # 🔒 Only allow logged out users
def forgot_password_identify_email():
    if request.method == 'POST':
        email = request.form.get('email')  # Get the email entered by user

        # 🔹 Check if the email exists in the database
        user = mongo.db.users.find_one({"email": email})

        if not user:
            flash("Email not found. Please sign up.", "danger")  # Flash message if email doesn't exist
            return redirect(url_for('account_routes.forgot_password_identify_email'))  # Redirect to same page

        # ✅ Generate a 6-digit OTP code
        otp_code = str(random.randint(100000, 999999))

        # 🔹 Store the email and OTP in session for later use
        session['forgot_password_data'] = {
            'email': email,
            'otp_code': otp_code  # Store the generated OTP
        }

        # 🔹 Send OTP via email
        forgot_password_verification_email(email, otp_code)  

        flash("A verification code has been sent to your email.", "success")
        
        # ✅ Redirect to OTP verification page (forgot2.html)
        return redirect(url_for('account_routes.forgot_password_verify_otp'))  # Route to OTP verification page

    return render_template('forgot1.html')  # Render the forgot1.html page if GET request

# ===========================
# 🚀 FORGOT PASSWORD STEP 2: OTP VERIFICATION
# ===========================
@account_routes.route('/forgot-password-verify-otp', methods=['GET', 'POST'])
@require_forgot_email_identification  # 🔒 Require step 1 completion + logged out
def forgot_password_verify_otp():
    if request.method == 'POST':
        otp_entered = request.form.get('otp')  # Get the OTP entered by user
        resend = request.form.get('resend')  # Check if the resend button was clicked

        # 🔹 Get stored email and OTP from session
        forgot_password_data = session.get('forgot_password_data')

        if not forgot_password_data:
            flash("Session expired. Please start the process again.", "danger")
            return redirect(url_for('account_routes.forgot_password_identify_email'))  # Redirect to email identification page

        stored_otp = forgot_password_data.get('otp_code')
        email = forgot_password_data.get('email')

        if resend == "true":
            # ✅ Resend OTP
            new_otp = str(random.randint(100000, 999999))  # Generate new OTP
            session['forgot_password_data']['otp_code'] = new_otp  # Store new OTP in session
            forgot_password_verification_email(email, new_otp)  # Send new OTP via email

            flash("A new OTP has been sent to your email.", "success")
            return render_template('forgot2.html')  # Render the same page again

        # ✅ Check if the entered OTP matches the stored OTP
        if otp_entered == stored_otp:
            # ✅ Store flag that OTP was verified
            session['forgot_password_data']['otp_verified'] = True
            flash("OTP verified successfully. You can now reset your password.", "success")
            return redirect(url_for('account_routes.change_password'))


        else:
            flash("Invalid OTP. Please try again.", "danger")
            return render_template('forgot2.html')  # Render the same page again

    return render_template('forgot2.html')

# ===========================
# 🚀 FORGOT PASSWORD STEP 3 : CHANGE PASSWORD
# ===========================
@account_routes.route('/change-password', methods=['GET', 'POST'])
@require_verified_otp  # ✅ Only allow if OTP verified
def change_password():
    # Check if the session has the required data (email and OTP code)
    forgot_password_data = session.get('forgot_password_data')

    if not forgot_password_data:
        flash("Session expired. Please start the process again.", "danger")
        return redirect(url_for('account_routes.forgot_password_identify_email'))  # Redirect to email identification page

    if request.method == 'POST':
        password = request.form.get('password')  # Get the new password
        confirm_password = request.form.get('confirm_password')  # Get the confirmed password

        # Validate password length (at least 8 characters)
        if len(password) < 8:
            flash("Password must be at least 8 characters long.", "danger")
            return render_template('forgot3.html')

        # Check if the passwords match
        if password != confirm_password:
            flash("Passwords do not match. Please try again.", "danger")
            return render_template('forgot3.html')

        # Hash the new password for storage
        hashed_password = generate_password_hash(password)

        # Update the password in the database
        email = forgot_password_data['email']  # Get the email from session
        mongo.db.users.update_one({"email": email}, {"$set": {"password_hashed": hashed_password}})

        # Clear the session data (no longer needed)
        session.pop('forgot_password_data', None)

        # Redirect to the login page after successful password reset
        flash("Your password has been successfully reset. You can now log in.", "success")
        session.pop('forgot_password_data', None)  # ✅ Clear session after reset
        return redirect(url_for('account_routes.login'))  # Redirect to login page

    return render_template('forgot3.html')
