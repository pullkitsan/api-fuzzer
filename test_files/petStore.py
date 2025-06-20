from flask import Flask, jsonify, request, send_file, make_response
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
import os
import json


USERS_FILE = "users.json"
def load_users():
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE, "r") as f:
                data = f.read().strip()
                if not data:
                    return {}
                return json.loads(data)
        except json.JSONDecodeError:
            print("[!] Invalid JSON in users.json, resetting to empty.")
            return {}
    return {}

def save_users(users_dict):
    with open(USERS_FILE, "w") as f:
        json.dump(users_dict, f, indent=2)

users = load_users()


app = Flask(__name__)
UPLOAD_FOLDER = '/tmp/uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# In-memory storage
pets = {}
orders = {}
users = {}

@app.route("/v2/pet", methods=["POST"])
def add_pet():
    pet = request.json
    pet_id = pet.get("id")
    if not pet_id:
        return "Invalid input", 405
    pets[pet_id] = pet
    return jsonify(pet), 200

@app.route("/v2/pet", methods=["PUT"])
def update_pet():
    pet = request.json
    pet_id = pet.get("id")
    if not pet_id or pet_id not in pets:
        return "Pet not found", 404
    pets[pet_id] = pet
    return jsonify(pet), 200

@app.route("/v2/pet/<int:petId>/uploadImage", methods=["POST"])
def upload_image(petId):
    file = request.files.get("file")
    if file:
        filename = secure_filename(file.filename)
        file.save(os.path.join(UPLOAD_FOLDER, filename))
    return jsonify({
        "code": 200,
        "type": "success",
        "message": f"Image uploaded for pet {petId}"
    }), 200

@app.route("/v2/pet/<int:petId>", methods=["GET"])
def get_pet_by_id(petId):
    pet = pets.get(petId)
    if not pet:
        return "Pet not found", 404
    return jsonify(pet), 200

@app.route("/v2/pet/<int:petId>", methods=["DELETE"])
def delete_pet(petId):
    if petId in pets:
        del pets[petId]
        return "Deleted", 200
    return "Pet not found", 404

@app.route("/v2/store/order", methods=["POST"])
def place_order():
    order = request.json
    order_id = order.get("id")
    if not order_id:
        return "Invalid order", 400
    orders[order_id] = order
    return jsonify(order), 200

@app.route("/v2/store/order/<int:orderId>", methods=["GET"])
def get_order_by_id(orderId):
    order = orders.get(orderId)
    if not order:
        return "Order not found", 404
    return jsonify(order), 200

@app.route("/v2/store/order/<int:orderId>", methods=["DELETE"])
def delete_order(orderId):
    if orderId in orders:
        del orders[orderId]
        return "Deleted", 200
    return "Order not found", 404

@app.route("/v2/user", methods=["POST"])
def create_user():
    user = request.json
    username = user.get("username")
    if not username:
        return "Invalid input", 400
    users[username] = user
    save_users(users)  # 👈 persist to file
    return jsonify(user), 200


@app.route("/v2/user/<string:username>", methods=["GET"])
def get_user(username):
    user = users.get(username)
    if not user:
        return "User not found", 404
    return jsonify(user), 200

@app.route("/v2/user/<string:username>", methods=["DELETE"])
def delete_user(username):
    if username in users:
        del users[username]
        return "Deleted", 200
    return "User not found", 404

@app.route("/v2/user/login", methods=["GET"])
def login_user():
    username = request.args.get("username")
    password = request.args.get("password")

    # Load users from file (ensures it's always up to date)
    users = load_users()

    user = users.get(username)
    if user is None or user.get("password") != password:
        return "Invalid username/password supplied", 400

    # Simulated response
    response = make_response(jsonify(f"Logged in user session: {username}"))
    response.headers["X-Expires-After"] = (datetime.utcnow() + timedelta(hours=1)).isoformat() + "Z"
    response.headers["X-Rate-Limit"] = 5000
    return response


if __name__ == "__main__":
    app.run(debug=True, port=5000)
