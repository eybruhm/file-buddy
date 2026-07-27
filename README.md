# File Buddy

**File Buddy** is a server-rendered Flask web application where users can sign up, upload files to MongoDB GridFS, browse file metadata, and securely download or delete files using password protection and email-based OTP flows.

🔗 **[Live Production Application](https://file-buddy-r1qc.onrender.com/)**

📹 **[Project Demo Video](https://drive.google.com/drive/u/3/folders/1FCIN5OgU1e9eJ_r51DCIQUGeNLz3t8cB)**

---

## 🏗️ Architecture & Tech Stack

The application utilizes a Client–Server architecture with Server-Side Rendering (SSR) via Jinja2 templates, structured using the Application Factory Pattern and Flask Blueprints for modular routing.

*   **Backend Framework:** Python 3, Flask
*   **Database:** MongoDB Atlas (Document Database)
*   **File Storage:** MongoDB GridFS
*   **Authentication:** Flask-Login (Session-Based), Werkzeug (Password Hashing)
*   **Email Services:** Flask-Mail (Gmail SMTP for OTP verification)
*   **Deployment:** WSGI + Gunicorn configured via Procfile for Render

## 🧩 Core Capabilities & Security

*   **Secure Authentication:** Enforces session-based authentication, Werkzeug password hashing, and email-verified One-Time Passwords (OTP) for registration and account recovery.
*   **Scalable File Storage:** Implements MongoDB GridFS to split and store large files into chunks, bypassing standard document size limits.
*   **Protected Distribution:** Allows users to attach specific passwords to individual file uploads, which are validated via a Fetch API endpoint before permitting secure downloads.
*   **Stateful Workflows:** Utilizes server-side session state to manage multi-step processes like password recovery.

## 📂 Repository Structure

| Directory / File | Core Responsibility |
| :--- | :--- |
| `main.py` | The WSGI application entry point that initializes the Flask server in debug mode. |
| `.env` | Stores configuration secrets like the MongoDB URI, email credentials, and Flask secret key. |
| `website/__init__.py` | The Application Factory that initializes MongoDB, Flask-Login, and registers Blueprints. |
| `website/models.py` | Defines the User class, database CRUD operations, and GridFS metadata management. |
| `website/account_routes.py` | Handles all user authentication, profile management, and OTP verification flows. |
| `website/file_routes.py` | Manages GridFS file uploads, secure downloads, deletions, and password verification. |
| `website/templates/` | Contains the Jinja2 HTML views, utilizing template inheritance from `base.html`. |

## 🚀 Local Environment Bootstrapping (Quick Start)

Follow these sequential steps to run the application locally.

**1. Clone and Virtual Environment Setup**
```bash
git clone [https://github.com/eybruhm/file-buddy.git](https://github.com/eybruhm/file-buddy.git)
cd file-buddy
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
