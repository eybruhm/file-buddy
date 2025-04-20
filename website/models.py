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
from . import mongo, login_manager



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
    user = mongo.db.users.find_one({"_id": ObjectId(user_id)})
    if user:
        return User(str(user["_id"]), user["username"], user["email"])
    return None

# ✅ Function to Create a New User
def create_user(username, email, password):
    """Creates a new user in MongoDB."""
    users_collection = mongo.db.users  

    # Check if email exists
    if users_collection.find_one({"email": email}):
        return None  

    # Hash password
    hashed_password = generate_password_hash(password)

    # Create user document
    user_data = {
        "username": username,
        "email": email,
        "password_hashed": hashed_password,
        "created_at": datetime.utcnow()
    }

    return users_collection.insert_one(user_data).inserted_id
