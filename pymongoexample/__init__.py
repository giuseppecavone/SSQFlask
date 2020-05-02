import json
import os
from .extensions import mongo, flask_bcrypt, flask_jwt, flask_schedule
from .main import main
import datetime
from flask import Flask
from flask_cors import CORS
import logging


def create_app(config_object='pymongoexample.settings'):
    app = Flask(__name__)
    logging.basicConfig(level=logging.DEBUG)
    app.config.from_object(config_object)
    app.config['JWT_SECRET_KEY'] = os.environ.get('SECRET')
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(days=1)
    app.config['JWT_TOKEN_LOCATION']=['cookies']
    app.config['JWT_COOKIE_CSRF_PROTECT'] = False
  

    CORS(app)
    mongo.init_app(app)
    flask_jwt.init_app(app)
    flask_bcrypt.init_app(app)
    flask_schedule.init_app(app)
    flask_schedule.start()
    app.register_blueprint(main)

    return app
