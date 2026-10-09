from __future__ import annotations

from flask import Flask

from app.api.routes import api_bp
from app.config import load_config


def create_app() -> Flask:
    app = Flask(__name__)
    app.config.from_mapping(
        FLASK_HOST="127.0.0.1",
        FLASK_PORT=5000,
    )
    try:
        cfg = load_config()
    except ValueError:
        cfg = None
    app.config["APP_CONFIG"] = cfg
    if cfg is not None:
        app.config["FLASK_HOST"] = cfg.flask_host
        app.config["FLASK_PORT"] = cfg.flask_port
    app.register_blueprint(api_bp)
    return app
