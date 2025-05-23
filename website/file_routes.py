from flask import Blueprint, request, redirect, url_for, flash, send_file, abort, make_response, current_app, session
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import gridfs
from bson.objectid import ObjectId
from datetime import datetime
import os
import io
from io import BytesIO
from . import mongo
from .models import update_user_file_counts

# Create the blueprint
file_routes = Blueprint("file_routes", __name__)

# Initialize GridFS within a function
def get_gridfs():
    return gridfs.GridFS(mongo.db)

@file_routes.route("/upload", methods=["GET", "POST"])
@login_required
def upload_file():
    if request.method == "POST":
        try:
            # Get uploaded file
            uploaded_file = request.files.get("file")
            if not uploaded_file:
                flash("No file selected", "danger")
                return redirect(request.url)
            
            # Secure the filename (avoids malicious paths)
            filename = secure_filename(uploaded_file.filename)
            file_ext = os.path.splitext(filename)[1].lower()

            # Metadata
            file_type = request.form.get("file_type", "others").lower()
            password = request.form.get("password")
            # Hash password if provided
            password_hashed = generate_password_hash(password) if password else None

            file_size = len(uploaded_file.read())  # get file size in bytes
            uploaded_file.seek(0)  # reset stream to beginning for saving

            # Get GridFS instance
            fs = get_gridfs()

            # Store file in GridFS
            gridfs_id = fs.put(uploaded_file, filename=filename)

            # Store metadata in 'files' collection
            mongo.db.files.insert_one({
                "filename": filename,
                "file_type": file_type,
                "file_extension": file_ext,
                "file_size": file_size,
                "owner_id": current_user.get_id(),
                "upload_date": datetime.utcnow(),
                "password_hashed": password_hashed,  # Store hashed password instead of plain text
                "is_protected": password_hashed is not None,  # Add flag for password protection
                "file_url": str(gridfs_id)
            })

            # Update user's file counts
            update_user_file_counts(current_user.get_id())

            flash("File uploaded successfully", "success")
            return redirect(url_for("file_routes.upload_file"))
        except Exception as e:
            current_app.logger.error(f"Error uploading file: {str(e)}")
            flash("Error uploading file", "danger")
            return redirect(request.url)
    
    return redirect(url_for("account_routes.upload"))

@file_routes.route("/download/<file_id>", methods=["GET"])
def download_file(file_id):
    try:
        # Retrieve file based on the file_id from the URL
        file = mongo.db.files.find_one({"_id": ObjectId(file_id)})
        if not file:
            flash("File not found", "danger")
            return redirect(url_for("account_routes.browse"))

        # Check if file is password protected and user is not the owner
        if file.get("password_hashed") and str(file["owner_id"]) != current_user.get_id():
            # Check if file has been verified (password entered correctly)
            verified_files = session.get('verified_files', [])
            if file_id not in verified_files:
                flash("Please enter password to download this file", "warning")
                return redirect(url_for("account_routes.browse"))

        # Get GridFS instance
        fs = get_gridfs()
        
        file_data = fs.get(ObjectId(file["file_url"]))
        response = make_response(file_data.read())
        response.headers.set("Content-Type", "application/octet-stream")
        response.headers.set("Content-Disposition", f"attachment; filename={file['filename']}")

        # Remove file from verified files after successful download
        if 'verified_files' in session and file_id in session['verified_files']:
            session['verified_files'].remove(file_id)
            session.modified = True

        return response
    except Exception as e:
        current_app.logger.error(f"Error downloading file: {str(e)}")
        flash("Error downloading file", "danger")
        return redirect(url_for("account_routes.browse"))

@file_routes.route("/verify-password", methods=["POST"])
@login_required
def verify_password():
    try:
        file_id = request.form.get("file_id")
        password = request.form.get("password")

        file = mongo.db.files.find_one({"_id": ObjectId(file_id)})

        if not file:
            return {"success": False, "message": "File not found"}, 400

        # Check if file is password protected
        if not file.get("password_hashed"):
            return {"success": False, "message": "File is not password protected"}, 400

        # Verify password using check_password_hash
        if not check_password_hash(file["password_hashed"], password):
            return {"success": False, "message": "Incorrect password"}, 400

        # Store verified file ID in session
        if 'verified_files' not in session:
            session['verified_files'] = []
        if file_id not in session['verified_files']:
            session['verified_files'].append(file_id)

        # If password is correct, send the download URL
        download_url = url_for('file_routes.download_file', file_id=file_id, _external=True)
        return {"success": True, "download_url": download_url}
    except Exception as e:
        current_app.logger.error(f"Error verifying password: {str(e)}")
        return {"success": False, "message": "Server error"}, 500

@file_routes.route("/delete/<file_id>", methods=["POST"])
@login_required
def delete_file(file_id):
    try:
        file = mongo.db.files.find_one({"_id": ObjectId(file_id)})
        if not file:
            flash("File not found", "danger")
            return redirect(url_for("account_routes.browse"))

        if str(file["owner_id"]) != current_user.get_id():
            flash("You don't have permission to delete this file", "danger")
            return redirect(url_for("account_routes.browse"))

        # Get GridFS instance
        fs = get_gridfs()

        # Delete from GridFS and database
        fs.delete(ObjectId(file["file_url"]))
        mongo.db.files.delete_one({"_id": ObjectId(file_id)})

        # Update user's file counts
        update_user_file_counts(current_user.get_id())

        flash("File deleted", "success")
        return redirect(url_for("account_routes.browse"))
    except Exception as e:
        current_app.logger.error(f"Error deleting file: {str(e)}")
        flash("Error deleting file", "danger")
        return redirect(url_for("account_routes.browse"))

