from flask import Flask
from flask_cors import CORS
from blueprint_auth import authentication
from utils import app

app.register_blueprint(authentication, url_prefix="/api/auth")

if __name__ == '__main__':
   app.run(debug=True)