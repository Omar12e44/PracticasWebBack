from flask import Flask

def create_app():
    app = Flask(__name__)
    app.config.from_mapping(
        SECRET_KEY='your_secret_key',
        # Add other configuration variables here
    )

    from . import routes
    app.register_blueprint(routes.bp)

    return app