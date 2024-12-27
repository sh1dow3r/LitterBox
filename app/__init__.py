from flask import Flask
import yaml
import os

def load_config():
    config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config', 'config.yaml')
    with open(config_path, 'r') as config_file:
        return yaml.safe_load(config_file)

def create_app():
    app = Flask(__name__)
    
    # Load configuration from YAML
    config = load_config()
    app.config.update(config)
    
    # Ensure upload and temp directories exist
    for folder in [config['upload']['upload_folder']]:
        os.makedirs(folder, exist_ok=True)
    
    # Register routes
    from app.routes import register_routes
    register_routes(app)
    
    return app
