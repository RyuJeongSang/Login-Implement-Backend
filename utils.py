import os
import jwt
from hashlib import pbkdf2_hmac
from flask import Flask
from flask_mysqldb import MySQLdb, MySQL
from settings import JWT_SECRET_KEY

app = Flask(__name__)

db = MySQL(app)

def validate_user_input(input_type, **kwargs):
    if input_type == "authentication":
        if len(kwargs["email"]) <= 255 and len(kwargs["password"]) <= 255:
            return True
        else:
            return False

def generate_salt():
    salt = os.urandom(16)
    return salt.hex()

def generate_hash(plain_password, password_salt):
    password_hash = pbkdf2_hmac(
        "sha256",
        b"%b" % bytes(plain_password, "utf-8"),
        b"%b" % bytes(password_salt, "utf-8"),
        10000,
    )
    return password_hash.hex()

def db_write(query, params):
    cursor = db.connection.cursor()
    try:
        cursor.execute(query, params)
        db.connection.commit()
        cursor.close()
        return True
    except MySQLdb._exceptions.IntegrityError:
        cursor.close()
        return False