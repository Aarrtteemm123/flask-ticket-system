import os


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'secret_key'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///test_db.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
