from flask import Flask, render_template, request, redirect, jsonify, session,url_for
import json
import os
import uuid
import requests
import base64
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS

app = Flask(__name__)
app.secret_key = "abcdefghijklmn123456789"

CORS(app)

DATA_FILE = "data.json"

# 🔐 ImageKit config (MOVE THIS TO ENV VARIABLES IN PRODUCTION)
PRIVATE_KEY = "private_/YQCB7+gY/QNDue0Y1U07YMp0X8="
UPLOAD_URL = "https://upload.imagekit.io/api/v1/files/upload"

# 👤 User
USER = {
    "username": "farhan",
    "password": generate_password_hash("hikaru6969")
}

# ---------------- IMAGE UPLOAD ----------------
def upload_to_imagekit(file):
    try:
        auth = base64.b64encode(f"{PRIVATE_KEY}:".encode()).decode()

        headers = {
            "Authorization": f"Basic {auth}"
        }

        files = {
            "file": (file.filename, file.stream, file.mimetype)
        }

        data = {
            "fileName": file.filename
        }

        res = requests.post(UPLOAD_URL, headers=headers, files=files, data=data)

        if res.status_code == 200:
            return res.json().get("url")
        else:
            print("Upload failed:", res.text)
            return None
    except Exception as e:
        print("Error uploading:", e)
        return None

# ---------------- DATA ----------------
def load_data():
    if not os.path.exists(DATA_FILE):
        return []
    try:
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    except:
        return []

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=2)

# ---------------- AUTH ----------------
def is_logged_in():
    return "user" in session

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if username == USER["username"] and check_password_hash(USER["password"], password):
            session["user"] = username
            return redirect("/")
        else:
            return "Invalid credentials", 401

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect("/login")

# ---------------- ROUTES ----------------
@app.route("/")
def index():
    shoes = load_data()
    return render_template("index.html", shoes=shoes)

@app.route("/search")
def search():
    query = request.args.get("q", "").lower()
    shoes = load_data()

    if query:
        shoes = [s for s in shoes if query in s["name"].lower()]

    return jsonify({"results": shoes})

@app.route("/add", methods=["GET", "POST"])
def add():
    if not is_logged_in():
        return redirect("/login")

    if request.method == "POST":
        data = load_data()

        file = request.files.get("image")
        image_url = ""

        if file:
            image_url = upload_to_imagekit(file)

        if not image_url:
            return "Image upload failed", 400

        try:
            sizes = list(map(int, request.form.getlist("sizes")))
        except:
            sizes = []

        new_shoe = {
            "id": str(uuid.uuid4()),
            "name": request.form.get("name"),
            "b_id": request.form.get("b_id"),
            "price": request.form.get("price"),
            "image": image_url,
            "desc": request.form.get("desc"),
            "onsale": request.form.get("onsale"),
            "uaq": request.form.get("uaq"),
            "mn": request.form.get("mn"),
            "sizes": sizes
        }

        data.append(new_shoe)
        save_data(data)

        return redirect("/")

    return render_template("add.html")

@app.route("/delete/<id>")
def delete(id):
    if not is_logged_in():
        return redirect("/login")

    data = load_data()
    data = [s for s in data if s["id"] != id]
    save_data(data)

    return redirect("/")

@app.route("/api/shoes")
def get_shoes():
    return jsonify(load_data())
@app.before_request
def require_login():
    allowed_routes = ["login", "static"]

    if request.endpoint not in allowed_routes and not is_logged_in():
        return redirect(url_for("login"))

# ---------------- RUN ----------------
if __name__ == "__main__":
    app.run(debug=True)
