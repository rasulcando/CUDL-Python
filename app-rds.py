# app.py
from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt
from werkzeug.security import generate_password_hash, check_password_hash
from config import Config
import mysql.connector

app = Flask(__name__)
app.config.from_object(Config)
jwt = JWTManager(app)


def connect_to_database():
    return mysql.connector.connect(
        host=app.config['MYSQL_HOST'],
        user=app.config['MYSQL_USER'],
        password=app.config['MYSQL_PASSWORD'],
        database=app.config['MYSQL_DB']
    )


conn = connect_to_database()
c = conn.cursor()

# print(app.config['JWT_SECRET_KEY'])


# Create a users table if it doesn't exist
c.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name TEXT(50) NOT NULL ,
        email TEXT(100) NOT NULL,
        password TEXT(400) NOT NULL,
        role_id INT,
        UNIQUE(email(100))
    )
''')

c.execute('''
    CREATE TABLE IF NOT EXISTS roles (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(50) NOT NULL UNIQUE
    )
''')

c.execute("INSERT IGNORE INTO roles (name) VALUES ('admin')")

admin_user = 'admin'
admin_password = 'admin'
admin_email = 'admin@genesis.com'
admin_hashed_password = generate_password_hash(admin_password)

admin_user_query = "INSERT IGNORE INTO users (name, email, password, role_id) VALUES (%s, %s, %s, (SELECT id FROM roles WHERE name = %s))"

c.execute(admin_user_query, (admin_user, admin_email, admin_hashed_password, 'admin'))
conn.commit()
conn.close()


# Helper function to convert database rows to dictionaries
def row_to_dict(row):
    return {"name": row[1], "email": row[2], "password": row[3], "role_id": row[4]}


# API endpoint to list all users
@app.route('/users/list', methods=['GET'])
@jwt_required()
def list_users():
    conn = connect_to_database()
    c = conn.cursor()
    c.execute('SELECT * FROM users')
    users = [row_to_dict(row) for row in c.fetchall()]
    return jsonify(users)
    conn.close()


# # API endpoint to check login by username
def get_user_by_email(email):
    conn = connect_to_database()
    c = conn.cursor()
    print("Get User By Email Initiated")
    print(email)
    c.execute('SELECT * FROM users WHERE email = %s', (email,))
    user_data = c.fetchone()
    conn.close()
    return user_data


# Helper function to insert a new user into the database
def insert_user(name, email, password, role):
    conn = connect_to_database()
    c = conn.cursor()
    role_query = "INSERT INTO roles (name) VALUES (%s) ON DUPLICATE KEY UPDATE name=%s"
    c.execute(role_query, (role, role))
    user_query = "INSERT INTO users (name, email, password, role_id) VALUES (%s, %s, %s, (SELECT id FROM roles WHERE name = %s))"
    c.execute(user_query, (name, email, password, role))
    conn.commit()
    conn.close()


def get_role_name(role_id):
    conn = connect_to_database()
    c = conn.cursor()
    c.execute('SELECT * FROM roles WHERE id = %s', (role_id,))
    role_name = c.fetchone()
    conn.close()
    return role_name


# API endpoint to create a new user
@app.route('/users/create', methods=['POST'])
@jwt_required()
def create_user():
    jwt_values = get_jwt()
    current_user_role_name = jwt_values["role_name"]
    if current_user_role_name != 'admin':
        return jsonify({"message": "Access denied. Admin role required."}), 403
    data = request.get_json()
    if not data or "name" not in data or "email" not in data or "password" not in data:
        return jsonify({"message": "Invalid request data"}), 400
    email = data["email"]
    print(email)
    user_data = get_user_by_email(email)
    if user_data:
        return jsonify({"message": "User Already Exists"}), 404
    name = data["name"]
    password = generate_password_hash(data["password"])
    role = data.get('role', 'user')
    insert_user(name, email, password, role)
    return jsonify({"message": "User registered successfully"}), 201


# Route for user login
@app.route('/login', methods=['POST'])
def login_user():
    data = request.get_json()
    if not data or "email" not in data or "password" not in data:
        return jsonify({"message": "Invalid request data"}), 400

    email = data["email"]
    password = data["password"]

    # Fetch the user by email from the database
    # print(email)
    user_data = get_user_by_email(email)
    if not user_data:
        return jsonify({"message": "User not found"}), 404
    print(user_data)
    # Get the hashed password from the database
    hashed_password = user_data[3]
    role_id = user_data[4]
    role_info = get_role_name(role_id)
    role_name = role_info[1]
    print(role_info[1])
    print(hashed_password)
    print(password)
    # Check if the entered password matches the hashed password
    if check_password_hash(hashed_password, password):
        # Generate a JWT token with the user's email as the identity
        additional_claims = {'role_name': role_name}
        access_token = create_access_token(identity=email, additional_claims=additional_claims)
        return jsonify({"message": "Login Successful", "access_token": access_token}), 200
    else:
        print(check_password_hash(hashed_password, password))
        return jsonify({"message": "Invalid credentials"}), 401


# API endpoint to update a user email
@app.route('/users/update', methods=['PUT'])
@jwt_required()
def update_user():
    jwt_values = get_jwt()
    current_user_role_name = jwt_values["role_name"]
    if current_user_role_name != 'admin':
        return jsonify({"message": "Access denied. Admin role required."}), 403
    conn = connect_to_database()
    c = conn.cursor()
    data = request.get_json()
    if not data or "name" not in data or "email" not in data:
        return jsonify({"message": "Invalid request data"}), 400
    email = data["email"]
    user_data = get_user_by_email(email)
    if not user_data:
        return jsonify({"message": "User not found"}), 404
    c.execute('UPDATE users SET name=%s, email=%s WHERE email=%s', (data["name"], data["email"], data["email"]))
    conn.commit()
    return jsonify({"message": "User updated successfully"}), 200


# API endpoint to delete a user by username
@app.route('/user/delete', methods=['DELETE'])
@jwt_required()
def delete_user():
    jwt_values = get_jwt()
    current_user_role_name = jwt_values["role_name"]
    if current_user_role_name != 'admin':
        return jsonify({"message": "Access denied. Admin role required."}), 403
    conn = connect_to_database()
    data = request.get_json()
    if not data or "email" not in data:
        return jsonify({"message": "Invalid request data"}), 400
    # print(data["email"])
    email = data["email"]
    user_data = get_user_by_email(email)
    if not user_data:
        return jsonify({"message": "The User not Exists"}), 404
    c = conn.cursor()
    c.execute('DELETE FROM users WHERE email=%s', (data["email"],))
    conn.commit()
    return jsonify({"message": "User deleted successfully"}), 200


# Helper function to update the user's password in the database
def update_user_password(email, new_password):
    conn = connect_to_database()
    c = conn.cursor()

    # Generate the hashed password
    hashed_password = generate_password_hash(new_password)

    # Update the user's password in the database
    c.execute('UPDATE users SET password=%s WHERE email=%s', (hashed_password, email))
    conn.commit()
    conn.close()


# Route for changing user password
@app.route('/changePassword', methods=['POST'])
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
