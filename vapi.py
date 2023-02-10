#register user: curl -X POST  --header "setuser: test" --header "setpwd: test123" http://192.168.178.58:5000/register

import bcrypt
import os
from flask import Flask, request

app = Flask(__name__)

def check_auth(username, password):
    with open("pass.txt", "r") as f:
        for line in f:
            stored_username, stored_hash = line.strip().split(":")
            if username == stored_username:
                if bcrypt.checkpw(password.encode(), stored_hash.encode()):
                    return line.strip()
    return False

@app.route("/register", methods=["POST"])
def register():
    username = request.headers.get("setuser")
    password = request.headers.get("setpwd").encode()
    hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())
    with open("pass.txt", "a+") as file:
        file.write(f"{username}:{hashed_password.decode()}\n")
    return "oO.", 201

@app.route("/server", methods=["GET"])
def retrieve_certs():
    username = request.headers.get("username")
    password = request.headers.get("password")
    user_and_password = check_auth(username, password)
    if not user_and_password:
        return "Unauthorized: Get LosT.", 401

    with open("server.pem", "r") as file:
            file_contents = file.read()
            return file_contents

@app.route("/passwords", methods=["GET"])
def retrieve_passwords():
    username = request.headers.get("username")
    password = request.headers.get("password")
    if username == "admin" and password == "admin":
        with open("logs.txt", "r") as file:
            file_contents = file.read()
            return file_contents

    user_and_password = check_auth(username, password)
    if not user_and_password:
        return "Unauthorized: Invalid BraIn FunCtion.", 401

    return "User authorized.", 200

if __name__ == "__main__":
    app.run(debug=True, port=5000, host='192.168.178.58')