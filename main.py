import os
import logging
from website import create_app

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

try:
    # Create the Flask app
    app = create_app()
    
    if __name__ == "__main__":
        # Get port from environment variable or default to 5000
        port = int(os.environ.get("PORT", 5000))
        logger.info(f"Starting server on port {port}")
        app.run(host='0.0.0.0', port=port)
except Exception as e:
    logger.error(f"Failed to start application: {e}")
    raise
