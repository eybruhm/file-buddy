import os
from flask import Flask
from flask_pymongo import PyMongo
from flask_mail import Mail
from flask_login import LoginManager
from dotenv import load_dotenv
import logging
from pymongo import MongoClient

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Load environment variables from .env file
load_dotenv()

# Initialize Flask extensions
mail = Mail()
login_manager = LoginManager()
mongo = PyMongo()

def init_mongo_collections(app):
    """Initialize MongoDB collections and indexes."""
    try:
        with app.app_context():
            db = mongo.db
            # Create collections if they don't exist
            collections = db.list_collection_names()
            if "users" not in collections:
                db.create_collection("users")
            if "files" not in collections:
                db.create_collection("files")
            
            # Create indexes
            db.users.create_index("email", unique=True)
            db.users.create_index("username", unique=True)
            db.files.create_index([("filename", 1), ("owner_id", 1)])
            
            logger.info("MongoDB collections and indexes initialized successfully!")
    except Exception as e:
        logger.error(f"Error initializing MongoDB collections: {str(e)}")
        raise

def create_app():
    """Factory function to create and configure the Flask app."""
    app = Flask(__name__)
    
    # Configure app
    app.config["SECRET_KEY"] = os.getenv('FLASK_SECRET_KEY', os.urandom(24))
    
    # Configure MongoDB
    mongodb_uri = os.getenv('MONGO_URI')
    if not mongodb_uri:
        raise ValueError("No MongoDB URI found in environment variables")
    
    try:
        print("MONGO_URI =", mongodb_uri)
        print("🔁 Testing pymongo client...")
        try:
            client = MongoClient(mongodb_uri)
            client.admin.command('ping')
            print("✅ pymongo connected successfully!")
        except Exception as e:
            print("❌ pymongo failed:", e)
        # Configure Flask-PyMongo
        app.config["MONGO_URI"] = mongodb_uri
        mongo.init_app(app)
        
        # Test connection using Flask-PyMongo's connection
        with app.app_context():
            mongo.db.command('ping')
            logger.info("MongoDB connection test successful!")
            
            # Initialize collections and indexes
            init_mongo_collections(app)
            
    except Exception as e:
        logger.error(f"MongoDB configuration error: {str(e)}")
        raise
    
    # Configure Flask-Mail
    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USE_SSL'] = False
    app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
    app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
    app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USERNAME')
    app.config['MAIL_MAX_EMAILS'] = None
    app.config['MAIL_ASCII_ATTACHMENTS'] = False

    # Initialize Flask extensions
    mail.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'account_routes.login'

    # Register blueprints
    from .account_routes import account_routes
    from .file_routes import file_routes
    
    app.register_blueprint(account_routes)
    app.register_blueprint(file_routes)

    return app
