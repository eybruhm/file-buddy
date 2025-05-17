import os
from flask import Flask
from flask_pymongo import PyMongo
from flask_mail import Mail
from flask_login import LoginManager
from dotenv import load_dotenv
import pymongo

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
    mongodb_uri = os.getenv('MONGO_URI')
    if not mongodb_uri:
        raise ValueError("No MongoDB URI found in environment variables")
    
    app.config["MONGO_URI"] = mongodb_uri

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

    with app.app_context():
        # Test MongoDB connection
        try:
            # Force a database command to test the connection
            mongo.db.command('ping')
            print("MongoDB connection successful!")
            
            # Initialize collections
            db = mongo.db
            if "users" not in db.list_collection_names():
                db.create_collection("users")
            if "files" not in db.list_collection_names():
                db.create_collection("files")
            
            # Set up collection references
            app.db = db
            app.users_col = db.users
            app.files_col = db.files
            
            # Create indexes
            app.files_col.create_index("filename")
            app.files_col.create_index("owner_id")
            
        except Exception as e:
            print(f"MongoDB connection error: {e}")
            raise

    return app
