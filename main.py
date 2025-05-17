from website import create_app  # Import the create_app function
import os

# Create the Flask app
app = create_app()

if __name__ == "__main__":
    # Get port from environment variable or default to 5000
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
