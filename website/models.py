# ----------------------- Explanation -----------------------
# This file defines the structure of user data (User model)
# which will be stored in MongoDB.
# 
# - generate_password_hash: Hashes passwords for security.
# - datetime: Stores user signup time.
# ----------------------------------------------------------
from werkzeug.security import generate_password_hash
from datetime import datetime
from flask_login import UserMixin
from bson.objectid import ObjectId
from flask import current_app
from . import login_manager



# ✅ Define User Class for Flask-Login
class User(UserMixin):
    def __init__(self, user_id, username, email):
        self.id = str(user_id)  # Ensure ID is a string
        self.username = username
        self.email = email

# ✅ Load User from Database
@login_manager.user_loader
def load_user(user_id):
    """Fetch user from database by ID for session tracking."""
    try:
        user = current_app.mongo.db.users.find_one({"_id": ObjectId(user_id)})
        if user:
            return User(str(user["_id"]), user["username"], user["email"])
    except Exception as e:
        current_app.logger.error(f"Error loading user: {str(e)}")
    return None

# ✅ Function to Create a New User
def create_user(username, email, password):
    """Creates a new user in MongoDB."""
    try:
        # Check if email exists
        if current_app.mongo.db.users.find_one({"email": email}):
            return None

        # Hash password
        hashed_password = generate_password_hash(password)

        # Create user document
        user_data = {
            "username": username,
            "email": email,
            "password_hashed": hashed_password,
            "created_at": datetime.utcnow(),
            "storage_used": 0,
            "max_storage": 5000000000,  # 5GB limit
            "total_uploads": 0,
            "uploads_count": {
                "image": 0,
                "video": 0,
                "document": 0,
                "audio": 0,
                "others": 0
            }
        }

        result = current_app.mongo.db.users.insert_one(user_data)
        return result.inserted_id
    except Exception as e:
        current_app.logger.error(f"Error creating user: {str(e)}")
        return None

# ✅ Function to store file metadata in MongoDB
def save_file_metadata(file_id, filename, file_type, file_extension, file_size, owner_id, privacy, password=None):
    """Saves metadata of uploaded files to MongoDB."""
    try:
        metadata = {
            "_id": file_id,  # This will match the GridFS file ID
            "filename": filename, # e.g. project.document
            "file_type": file_type,  # e.g., image, video, document, audio, others
            "file_extension": file_extension,  # e.g., .jpg, .mp4
            "file_size": file_size, # in byte e.g 2322 bytes
            "owner_id": owner_id, 
            "upload_date": datetime.utcnow(), 
            "password": password,  # Optional: Only for 'Restricted'
            "file_url": ""  # Optional: Can be filled later if serving via static route
        }

        # ✅ Insert into the "files" collection
        current_app.mongo.db.files.insert_one(metadata)
    except Exception as e:
        current_app.logger.error(f"Error saving file metadata: {str(e)}")
        raise
