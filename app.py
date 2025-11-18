from flask import Flask, request, jsonify, send_from_directory, redirect, url_for, session
from flask_cors import CORS
import os, string, json

app = Flask(__name__)
CORS(app)
app.secret_key = os.urandom(24)

import re

def strength_level(password):
    score = 0
    if len(password) >= 8: score += 1
    if re.search(r"[A-Z]", password): score += 1
    if re.search(r"[a-z]", password): score += 1
    if re.search(r"[0-9]", password): score += 1
    if re.search(r"[^A-Za-z0-9]", password): score += 1

    return ["Very Weak","Weak","Medium","Strong","Very Strong"][score-1] if score>0 else "Very Weak"

@app.route("/check_strength", methods=["POST"])
def check_strength():
    pwd = request.get_json()["password"]
    return jsonify({"strength": strength_level(pwd)})


# ---------------- PRIME-BASED ENCRYPTION ---------------- #

charsList=list(string.printable)
charsDict={char: charsList.index(char) for char in charsList}

# Generate first 100 primes
list_primes=[2]
num=3
while len(list_primes) < 100:
    Prime=True
    for i in range(2, num):
        if num%i==0:
            Prime=False
            break
    if Prime:
        list_primes.append(num)
    num+=1


def encrypt_password(password):
    numbers = [charsDict[c] for c in password]

    for i in range(len(numbers)):
        pad_ = numbers[i] + list_primes[i]
        while pad_ > 99:
            pad_ -= 99
        numbers[i] = pad_

    return ''.join(charsList[n] for n in numbers)


def check_password(stored, entered):
    return stored == encrypt_password(entered)

# ---------------- USER FILE I/O ---------------- #

USERS_FILE = "users.txt"

def read_users():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, "r") as f:
        try:
            return json.load(f)
        except:
            return {}

def write_users(data):
    with open(USERS_FILE, "w") as f:
        json.dump(data, f)

# ---------------- ROUTES ---------------- #

@app.route('/')
def home():
    if "username" in session:
        return redirect("/index.html")
    return send_from_directory("static", "login.html")


@app.route('/login.html')
def serve_login():
    return send_from_directory("static", "login.html")


@app.route('/signup.html')
def serve_signup():
    return send_from_directory("static", "signup.html")


@app.route('/index.html')
def serve_index():
    if "username" in session:
        return send_from_directory("static", "index.html")
    return redirect("/")


# ---------------- SIGNUP ---------------- #

@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    username = data["username"]
    password = data["password"]

    users = read_users()

    if username in users:
        return jsonify({"success": False, "message": "Username already exists"})

    users[username] = encrypt_password(password)
    write_users(users)

    return jsonify({"success": True, "message": "Signup successful"})


# ---------------- LOGIN ---------------- #

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data["username"]
    password = data["password"]

    users = read_users()

    if username not in users:
        return jsonify({"success": False, "message": "Invalid credentials"})

    if not check_password(users[username], password):
        return jsonify({"success": False, "message": "Invalid credentials"})

    session["username"] = username
    return jsonify({"success": True})


# ---------------- LOGOUT ---------------- #

@app.route('/logout')
def logout():
    session.pop("username", None)
    return redirect("/")


# ---------------- ROT13 ENCRYPT / DECRYPT ---------------- #

def rot13(text):
    result = []
    for c in text:
        if 'a' <= c <= 'z':
            result.append(chr((ord(c)-97 + 13) % 26 + 97))
        elif 'A' <= c <= 'Z':
            result.append(chr((ord(c)-65 + 13) % 26 + 65))
        else:
            result.append(c)
    return "".join(result)

@app.route("/encrypt", methods=["POST"])
def encrypt_route():
    msg = request.get_json()["message"]
    return jsonify({"result": rot13(msg)})

@app.route("/decrypt", methods=["POST"])
def decrypt_route():
    msg = request.get_json()["message"]
    return jsonify({"result": rot13(msg)})


# ---------------- RUN ---------------- #

if __name__ == "__main__":
    app.run(debug=True)
