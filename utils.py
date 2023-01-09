from flask import Flask, jsonify
import jwt
import os
import datetime
from hashlib import pbkdf2_hmac
from flask_mysqldb import MySQLdb, MySQL
from settings import JWT_SECRET_KEY, MYSQL_USER, MYSQL_PASSWORD, MYSQL_DB, JWT_REFRESH_VERIFY

import logging

app = Flask(__name__)

#MySQL Config
app.config["MYSQL_USER"] = MYSQL_USER
app.config["MYSQL_PASSWORD"] = MYSQL_PASSWORD
app.config["MYSQL_DB"] = MYSQL_DB
app.config["MYSQL_CURSORCLASS"] = "DictCursor"

db = MySQL(app)

def db_read(query, params=None):
    cursor = db.connection.cursor()
    if params:
        cursor.execute(query, params)
    else:
        cursor.execute(query)
    entries = cursor.fetchall()
    cursor.close()
    content = []
    for entry in entries:
        content.append(entry)
    return content

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

def generate_jwt_access_token(content):
    payload = {
        'id': content, # user id
        'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=60 * 30)  # 만료 시간(30분 후)
    }
    token = jwt.encode(payload, JWT_SECRET_KEY, "HS256")
    
    return token

def generate_jwt_refresh_token(content):
    payload = {
        'id': content, # user id
        'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=60 * 60 * 24 * 14)  # 만료 시간(14일 후)
    }
    token = jwt.encode(payload, JWT_SECRET_KEY, "HS256")
    
    return token

def validate_user_input(input_type, **kwargs):
    if input_type == "authentication":
        if len(kwargs["email"]) <= 255 and len(kwargs["password"]) <= 255:
            return True
        else:
            return False


def validate_user(email, password):
    current_user = db_read("""SELECT * FROM users WHERE email = %s""", (email,))
    if len(current_user) == 1:
        saved_password_hash = current_user[0]["password_hash"]
        saved_password_salt = current_user[0]["password_salt"]
        password_hash = generate_hash(password, saved_password_salt)

        if password_hash == saved_password_hash: #user가 있다면
            user_id = current_user[0]["id"]
            jwt_access_token = generate_jwt_access_token(user_id)
            jwt_refresh_token = generate_jwt_refresh_token(user_id)
            return jsonify({"jwt_access_token": jwt_access_token, "jwt_refresh_token": jwt_refresh_token})
        else:
            return False
    else:
        return False

def decode_token(token):
    user_id = jwt.decode(token, JWT_SECRET_KEY, "HS256")["id"]

    jwt_access_token = generate_jwt_access_token(user_id)
    jwt_refresh_token = generate_jwt_refresh_token(user_id)

    return jsonify({"jwt_access_token": jwt_access_token, "jwt_refresh_token": jwt_refresh_token})