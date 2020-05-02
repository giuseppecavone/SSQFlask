from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from flask_apscheduler import APScheduler

mongo = PyMongo()
flask_bcrypt = Bcrypt()
flask_jwt = JWTManager()
flask_schedule = APScheduler()