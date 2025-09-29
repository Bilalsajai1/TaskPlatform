import os

class Config:
    SECRET_KEY = 'BILAL11'  # Replace with a random string
    SQLALCHEMY_DATABASE_URI = 'sqlite:///site.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'app/uploads')
    CONFIRMATION_FOLDER = os.path.join(os.path.dirname(__file__), 'app/uploads/confirmation')
    MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10MB file size limit