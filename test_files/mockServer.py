# save as test_api.py
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/api/test', methods=['POST', 'PUT'])
def test_endpoint():
    data = request.get_json()
    username = data.get("username")
    email = data.get("email")
    role = data.get("role")
    
    # Simulate interesting behavior:
    if username == "admin" or username== "alex" or email == "xss@attack.com":
        return jsonify({"error": "forbidden value"}), 500
    
    return jsonify({"received": data}), 200

@app.route("/api/register", methods=["POST"])
def register():
    data = request.json
    print("[*] /api/register called")
    print(f"Body: {data}")
    return jsonify({"message": "User registered"}), 200

@app.route("/api/login", methods=["POST"])
def login():
    data = request.json
    print("[*] /api/login called")
    print(f"Body: {data}")
    return jsonify({"message": "Login successful"}), 200


@app.route("/api/users/<userId>", methods=["GET"])
def get_user(userId):
    verbose = request.args.get("verbose")
    role = request.args.get("role")
    print("[*] GET /api/users/<userId> called")
    print(f"Path param userId: {userId}")
    print(f"Query param verbose: {verbose}")
    print(f"Query param role: {role}")

    if userId == "admin":
        print("[!] Forbidden")
        return jsonify({"error": "Forbidden User Id"}), 403
    return jsonify({
        "id": userId,
        "username": "testuser",
        "email": "test@example.com"
    }), 200

@app.route("/api/users/<userId>", methods=["POST"])
def update_user(userId):
    data = request.json
    print("[*] POST /api/users/<userId> called")
    print(f"Path param userId: {userId}")
    print(f"Body: {data}")
    username=data.get("username")
    password = data.get("password")

    if username=="admin":
        print("[!] Forbidden")
        return jsonify({"error": "Forbidden username"}), 403
    if username=="verify":
        print("[!] Forbidden")
        return jsonify({"error": "verify is not a correct user"}), 403
    if username=="alex" and password=="alex":
        print("[!] Welcome")
        fake_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.fake.payload.signature"
        return jsonify({"token": fake_token}), 200
    
    return jsonify({"message": "Incorrect parameters"}), 403

if __name__ == '__main__':
    app.run(port=5000)
