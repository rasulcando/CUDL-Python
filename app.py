# app.py
from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3, datetime

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'IzraRasul@300991'
app.config['JWT_EXPIRATION_DELTA'] = datetime.timedelta(hours=2)
jwt = JWTManager(app)
# Create a SQLite database connection
conn = sqlite3.connect('users.db')
c = conn.cursor()

# Create a users table if it doesn't exist
c.execute('''
    CREATE TABLE IF NOT EXISTS users (
        name TEXT NOT NULL,
        email TEXT NOT NULL,
        password TEXT NOT NULL 
    )
''')
conn.commit()
conn.close()


# Helper function to convert database rows to dictionaries
def row_to_dict(row):
    return {"name": row[0], "email": row[1], "password": row[2]}


# API endpoint to list all users
@app.route('/users/list', methods=['GET'])
@jwt_required()
def list_users():
    with sqlite3.connect("users.db") as conn:
        c = conn.cursor()
        c.execute('SELECT * FROM users')
        users = [row_to_dict(row) for row in c.fetchall()]
        return jsonify(users)
        conn.close()


# Helper function to insert a new user into the database
def insert_user(name, email, password):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('INSERT INTO users (name, email, password) VALUES (?, ?, ?)', (name, email, password))
    conn.commit()
    conn.close()


# API endpoint to create a new user
@app.route('/users/create', methods=['POST'])
def create_user():
    data = request.get_json()
    if not data or "name" not in data or "email" not in data or "password" not in data:
        return jsonify({"message": "Invalid request data"}), 400
    email = data["email"]
    user_data = get_user_by_email(email)
    if user_data:
        return jsonify({"message": "User Already Exists"}), 404
    name = data["name"]
    password = generate_password_hash(data["password"])  # Hash the password before storing it
    insert_user(name, email, password)
    return jsonify({"message": "User registered successfully"}), 201


# API endpoint to update a user by username
@app.route('/users/update', methods=['PUT'])
@jwt_required()
def update_user():
    with sqlite3.connect("users.db") as conn:
        c = conn.cursor()
        data = request.get_json()
        if not data or "name" not in data or "email" not in data:
            return jsonify({"message": "Invalid request data"}), 400

        c.execute('UPDATE users SET name=?, email=? WHERE email=?', (data["name"], data["email"], data["email"]))
        conn.commit()
        return jsonify({"message": "User updated successfully"}), 200


# API endpoint to delete a user by username
@app.route('/user/delete', methods=['DELETE'])
@jwt_required()
def delete_user():
    with sqlite3.connect("users.db") as conn:
        c = conn.cursor()
        data = request.get_json()
        if not data or "email" not in data:
            return jsonify({"message": "Invalid request data"}), 400
        c.execute('DELETE FROM users WHERE email=?', data["email"])
        conn.commit()
        return jsonify({"message": "User deleted successfully"}), 200


# # API endpoint to check login by username
def get_user_by_email(email):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE email=?', (email,))
    user_data = c.fetchone()
    conn.close()
    return user_data


# Route for user login
@app.route('/login', methods=['POST'])
def login_user():
    data = request.get_json()
    if not data or "email" not in data or "password" not in data:
        return jsonify({"message": "Invalid request data"}), 400

    email = data["email"]
    password = data["password"]

    # Fetch the user by email from the database
    user_data = get_user_by_email(email)
    if not user_data:
        return jsonify({"message": "User not found"}), 404

    # Get the hashed password from the database
    hashed_password = user_data[2]

    # Check if the entered password matches the hashed password
    if check_password_hash(hashed_password, password):
        # Generate a JWT token with the user's email as the identity
        access_token = create_access_token(identity=email)
        return jsonify({"access_token": access_token}), 200
    else:
        return jsonify({"message": "Invalid credentials"}), 401


# Helper function to update the user's password in the database
def update_user_password(email, new_password):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()

    # Generate the hashed password
    hashed_password = generate_password_hash(new_password)

    # Update the user's password in the database
    c.execute('UPDATE users SET password=? WHERE email=?', (hashed_password, email))
    conn.commit()
    conn.close()


# Route for changing user password
@app.route('/changepassword', methods=['POST'])
@jwt_required()
def change_password():
    data = request.get_json()
    if not data or "email" not in data or "old_password" not in data or "new_password" not in data:
        return jsonify({"message": "Invalid request data"}), 400

    email = data["email"]
    old_password = data["old_password"]
    new_password = data["new_password"]

    # Fetch the user by email from the database
    user_data = get_user_by_email(email)
    if not user_data:
        return jsonify({"message": "User not found"}), 404

    # Get the hashed password from the database
    hashed_password = user_data[2]

    # Check if the entered old password matches the stored hashed password
    if not check_password_hash(hashed_password, old_password):
        return jsonify({"message": "Invalid old password"}), 401

    # Update the user's password with the new hashed password
    update_user_password(email, new_password)

    return jsonify({"message": "Password updated successfully"}), 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
