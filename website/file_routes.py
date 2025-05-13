from flask import Blueprint, request, redirect, url_for, flash, send_file, abort, make_response
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
import gridfs
from bson.objectid import ObjectId
from datetime import datetime
import os
import io
from . import mongo  # adjust if your db is imported 
from io import BytesIO


fs = gridfs.GridFS(mongo.db)

file_routes = Blueprint("file_routes", __name__)

@file_routes.route("/upload", methods=["GET", "POST"])
@login_required
def upload_file():
    if request.method == "POST":
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
        password = password if password else None

        file_size = len(uploaded_file.read())  # get file size in bytes
        uploaded_file.seek(0)  # reset stream to beginning for saving

        # Store file in GridFS
        gridfs_id = fs.put(uploaded_file, filename=filename)

        # Store metadata in 'files' collection
        mongo.db.files.insert_one({
            "filename": filename,
            "file_type": file_type,
            "file_extension": file_ext,
            "file_size": file_size,
            "owner_id": current_user.get_id(),  # assumed to be _id as str
            "upload_date": datetime.utcnow(),
            "password": password,  # can be None
            "file_url": str(gridfs_id)
        })

        # Update user's upload stats
        mongo.db.users.update_one(
            {"_id": ObjectId(current_user.get_id())},
            {
                "$inc": {
                    "storage_used": file_size,
                    "total_uploads": 1,
                    f"uploads_count.{file_type}": 1
                }
            }
        )

        flash("File uploaded successfully", "success")
        return redirect(url_for("file_routes.upload_file"))
    
    return redirect(url_for("account_routes.upload"))  # Or render_template("upload.html")

@file_routes.route("/download/<file_id>", methods=["GET"])
def download_file(file_id):
    try:
        # Retrieve file based on the file_id from the URL
        file = mongo.db.files.find_one({"_id": ObjectId(file_id)})
        if not file:
            flash("File not found", "danger")
            return redirect(url_for("account_routes.browse"))

        file_data = fs.get(ObjectId(file["file_url"]))
        response = make_response(file_data.read())
        response.headers.set("Content-Type", "application/octet-stream")
        response.headers.set("Content-Disposition", f"attachment; filename={file['filename']}")
        return response
    except Exception as e:
        flash("Error downloading file", "danger")
        print("Error downloading file:", e)
        return redirect(url_for("account_routes.browse"))




@file_routes.route("/verify-password", methods=["POST"])
@login_required
def verify_password():
    file_id = request.form.get("file_id")
    password = request.form.get("password")

    file = mongo.db.files.find_one({"_id": ObjectId(file_id)})

    if not file:
        return {"success": False, "message": "File not found"}, 400

    if file.get("password") != password:
        return {"success": False, "message": "Incorrect password"}, 400

    # If password is correct, send the download URL
    download_url = url_for('file_routes.download_file', file_id=file_id, _external=True)
    return {"success": True, "download_url": download_url}






@file_routes.route("/delete/<file_id>", methods=["POST"])
@login_required
def delete_file(file_id):
    file = mongo.db.files.find_one({"_id": ObjectId(file_id)})
    if not file:
        flash("File not found", "danger")
        return redirect(url_for("account_routes.browse"))

    if str(file["owner_id"]) != current_user.get_id():
        flash("You don't have permission to delete this file", "danger")
        return redirect(url_for("account_routes.browse"))

    # Delete from GridFS and database
    fs.delete(ObjectId(file["file_url"]))
    mongo.db.files.delete_one({"_id": ObjectId(file_id)})

    flash("File deleted", "success")
    return redirect(url_for("account_routes.browse"))

