import os
from flask import Flask
from flask_pymongo import PyMongo
from flask_mail import Mail
from flask_login import LoginManager
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Create database and mail objects
mongo = PyMongo()
mail = Mail()
login_manager = LoginManager()

def create_app():
    """Factory function to create and configure the Flask app."""
    app = Flask(__name__)

    # 🔹 Set a secret key for session security
    app.config["SECRET_KEY"] = os.getenv('FLASK_SECRET_KEY', os.urandom(24))

    # Configure MongoDB connection using environment variable
    app.config["MONGO_URI"] = os.getenv('MONGO_URI')

    # ✅ Configure Flask-Mail with Gmail
    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USE_SSL'] = False
    app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
    app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
    app.config['MAIL_DEFAULT_SENDER'] = ('File Buddy', os.getenv('MAIL_USERNAME'))
    app.config['MAIL_MAX_EMAILS'] = None
    app.config['MAIL_ASCII_ATTACHMENTS'] = False

    # Initialize extensions
    mongo.init_app(app)
    mail.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'account_routes.login'

    # Import and register Blueprints
    from .account_routes import account_routes
    app.register_blueprint(account_routes)

    from .file_routes import file_routes
    app.register_blueprint(file_routes)

    # ✅ Initialize MongoDB collections (as references)
    app.db = mongo.db  # Shortcut to access database
    app.users_col = mongo.db.users  # User info
    app.files_col = mongo.db.files  # File metadata (type, size, privacy, owner, etc.)

    # ✅ Optional: Create index for faster search (e.g., on username, file name, etc.)
    app.files_col.create_index("filename")
    app.files_col.create_index("owner_id")


    return app
