from website import create_app  # Import the create_app function

# Create and run the Flask app
app = create_app()

if __name__ == "__main__":
    app.run(debug=True)
