import os
from flask import Flask
from flask_pymongo import PyMongo
from flask_mail import Mail
from flask_login import LoginManager
from dotenv import load_dotenv
import logging
from pymongo import MongoClient
from bson.objectid import ObjectId

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
mongo = PyMongo()
login_manager = LoginManager()

def create_app():
    """Factory function to create and configure the Flask app."""
    app = Flask(__name__)
    
    # Configure app
    app.config["SECRET_KEY"] = os.getenv('FLASK_SECRET_KEY')
    
    # Configure MongoDB
    mongodb_uri = os.getenv('MONGO_URI')
    if not mongodb_uri:
        raise ValueError("No MongoDB URI found in environment variables")
    
    # Configure Flask-PyMongo
    app.config["MONGO_URI"] = mongodb_uri
    
    # Initialize MongoDB connection first
    mongo.init_app(app)
    
    try:
        # Test connection using PyMongo
        with app.app_context():
            # Create collections if they don't exist
            if "users" not in mongo.db.list_collection_names():
                mongo.db.create_collection("users")
                logger.info("Created users collection")
            
            if "files" not in mongo.db.list_collection_names():
                mongo.db.create_collection("files")
                logger.info("Created files collection")
            
            # Create indexes
            mongo.db.users.create_index("email", unique=True)
            mongo.db.users.create_index("username", unique=True)
            mongo.db.files.create_index([("filename", 1), ("owner_id", 1)])
            logger.info("Database indexes created successfully")
            
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

    # User loader callback
    @login_manager.user_loader
    def load_user(user_id):
        if not user_id:
            return None
        from .models import User
        user = mongo.db.users.find_one({"_id": ObjectId(user_id)})
        if user:
            return User(user_id=str(user["_id"]), username=user["username"], email=user["email"])
        return None

    # Register blueprints
    from .account_routes import account_routes
    from .file_routes import file_routes
    
    app.register_blueprint(account_routes)
    app.register_blueprint(file_routes)

    return app
