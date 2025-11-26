from flask import Flask, request, jsonify, send_from_directory, redirect, session
from flask_cors import CORS
import os, json, string

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

# ---------------- PASSWORD ENCRYPTION ---------------- #

charsList = list(string.printable)
charsDict = {char: charsList.index(char) for char in charsList}

primes = [2]
n = 3
while len(primes) < 100:
    if all(n % i for i in range(2, n)):
        primes.append(n)
    n += 1


def encrypt_password(password):
    nums = [charsDict[c] for c in password]
    for i in range(len(nums)):
        nums[i] = (nums[i] + primes[i]) % 100
    return ''.join(charsList[n] for n in nums)


def check_password(stored, entered):
    return stored == encrypt_password(entered)


# ---------------- USER FILE ---------------- #

USERS = "users.txt"


def read_users():
    if not os.path.exists(USERS):
        return {}
    try:
        with open(USERS, "r") as f:
            txt = f.read().strip()
            if not txt:
                return {}
            return json.loads(txt)
    except Exception:
        return {}


def write_users(data):
    with open(USERS, "w") as f:
        json.dump(data, f)


# ---------------- GLOBAL KEY STORAGE (keys.txt) ---------------- #

KEYS_FILE = "keys.txt"


def read_all_keys():
    """Read the global keys dict from keys.txt, return {} if anything is wrong."""
    if not os.path.exists(KEYS_FILE):
        return {}
    try:
        with open(KEYS_FILE, "r") as f:
            txt = f.read().strip()
            if not txt:
                return {}
            return json.loads(txt)
    except Exception:
        # if file is corrupted, just ignore it and start fresh in memory
        return {}


def write_all_keys(data):
    with open(KEYS_FILE, "w") as f:
        json.dump(data, f)


def get_user_keys(username):
    """Always return a dict with 'keys' for this user, and ensure ROT13 default exists."""
    all_keys = read_all_keys()
    if username not in all_keys:
        all_keys[username] = {"keys": [{"name": "ROT13", "pattern": "rot13"}]}
        write_all_keys(all_keys)
    # in case the user entry exists but has no 'keys' key
    if "keys" not in all_keys[username]:
        all_keys[username]["keys"] = [{"name": "ROT13", "pattern": "rot13"}]
        write_all_keys(all_keys)
    return all_keys[username]


def save_user_keys(username, keydata):
    all_keys = read_all_keys()
    all_keys[username] = keydata
    write_all_keys(all_keys)


# ---------------- USER SESSION ROUTES ---------------- #

@app.route("/user", methods=["POST"])
def user_info():
    if "username" not in session:
        return jsonify({"username": "Guest"})
    return jsonify({"username": session["username"]})


# ---------------- PAGE ROUTES ---------------- #

@app.route("/")
def home():
    if "username" in session:
        return send_from_directory("static", "index.html")
    return send_from_directory("static", "login.html")


@app.route("/<page>")
def serve(page):
    if page.endswith(".html"):
        if "username" not in session and page not in ["login.html", "signup.html"]:
            return redirect("/")
        return send_from_directory("static", page)
    return "Invalid", 404


# ---------------- SIGNUP ---------------- #

@app.route("/signup", methods=["POST"])
def signup():
    data = request.get_json() or {}
    u = data.get("username", "")
    p = data.get("password", "")

    users = read_users()

    if u in users:
        return jsonify({"success": False, "message": "Username exists"})
    if not u.strip() or not p:
        return jsonify({"success": False, "message": "Invalid Username or Password"})

    users[u] = encrypt_password(p)
    write_users(users)

    # create default key entry for this user
    save_user_keys(u, {"keys": [{"name": "ROT13", "pattern": "rot13"}]})

    return jsonify({"success": True, "message": "Account created, Please log in"})


# ---------------- LOGIN ---------------- #

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    u = data.get("username", "")
    p = data.get("password", "")

    users = read_users()
    if u not in users:
        return jsonify({"success": False})
    if not check_password(users[u], p):
        return jsonify({"success": False})

    session["username"] = u
    return jsonify({"success": True})


# ---------------- LOGOUT ---------------- #

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# ---------------- ROT13 ---------------- #

def rot13(text):
    out = ""
    for c in text:
        if c.isalpha():
            base = 65 if c.isupper() else 97
            out += chr((ord(c) - base + 13) % 26 + base)
        else:
            out += c
    return out


# ---------------- CUSTOM SHIFT KEY ---------------- #

def shift_encrypt(text, pattern):
    digits = [int(x) for x in pattern]
    pi = 0
    result = ""

    for c in text:
        if c.isalpha():
            base = 65 if c.isupper() else 97
            result += chr((ord(c) - base + digits[pi]) % 26 + base)
            pi = (pi + 1) % len(digits)
        else:
            result += c
    return result


def shift_decrypt(text, pattern):
    digits = [int(x) for x in pattern]
    pi = 0
    result = ""

    for c in text:
        if c.isalpha():
            base = 65 if c.isupper() else 97
            result += chr((ord(c) - base - digits[pi]) % 26 + base)
            pi = (pi + 1) % len(digits)
        else:
            result += c
    return result


# ---------------- KEY ROUTES ---------------- #

@app.route("/keys", methods=["POST"])
def keys():
    if "username" not in session:
        return jsonify({"keys": []})
    return jsonify(get_user_keys(session["username"]))


@app.route("/create_key", methods=["POST"])
def create_key():
    if "username" not in session:
        # still return JSON so front-end doesn't crash
        return jsonify({"success": False, "message": "Not logged in"})

    data = request.get_json() or {}
    name = (data.get("name") or "").strip()
    pattern = (data.get("pattern") or "").strip()

    k = get_user_keys(session["username"])

    if not name:
        return jsonify({"success": False, "message": "Key name cannot be empty"})
    if not pattern:
        return jsonify({"success": False, "message": "Pattern cannot be empty"})
    if not pattern.isdigit():
        return jsonify({"success": False, "message": "Pattern must be digits only"})
    if any(x["name"] == name for x in k.get("keys", [])):
        return jsonify({"success": False, "message": "Key name already exists"})
    
    # ensure "keys" exists
    if "keys" not in k:
        k["keys"] = []
    k["keys"].append({"name": name, "pattern": pattern})
    save_user_keys(session["username"], k)

    return jsonify({"success": True})


# ---------------- ENCRYPT / DECRYPT ---------------- #

@app.route("/encrypt", methods=["POST"])
def enc():
    if "username" not in session:
        return jsonify({"result": "Not logged in"})

    data = request.get_json() or {}
    msg = data.get("message", "")
    keyname = data.get("key", "")

    keys_dict = get_user_keys(session["username"])
    keys_list = keys_dict.get("keys", [])
    key = next((x for x in keys_list if x["name"] == keyname), None)
    if key is None:
        return jsonify({"result": "Key not found"})

    if key["pattern"] == "rot13":
        return jsonify({"result": rot13(msg)})

    return jsonify({"result": shift_encrypt(msg, key["pattern"])})


@app.route("/decrypt", methods=["POST"])
def dec():
    if "username" not in session:
        return jsonify({"result": "Not logged in"})

    data = request.get_json() or {}
    msg = data.get("message", "")
    keyname = data.get("key", "")

    keys_dict = get_user_keys(session["username"])
    keys_list = keys_dict.get("keys", [])
    key = next((x for x in keys_list if x["name"] == keyname), None)
    if key is None:
        return jsonify({"result": "Key not found"})

    if key["pattern"] == "rot13":
        return jsonify({"result": rot13(msg)})

    return jsonify({"result": shift_decrypt(msg, key["pattern"])})


# ---------------- RUN ---------------- #

if __name__ == "__main__":
    app.run(debug=True)
