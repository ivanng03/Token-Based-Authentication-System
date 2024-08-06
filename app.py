import csv
from flask import Flask, request, jsonify, make_response, render_template, session
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta
from functools import wraps
from cryptography.fernet import Fernet

app = Flask(__name__) #For initialize
app.config['SECRET_KEY'] = '_afQftk9Gyj1uwWz' #Set a secret key
app.config['ENCRYPTION_KEY'] = Fernet.generate_key()  #Generate a key for symmetric encryption

fernet = Fernet(app.config['ENCRYPTION_KEY']) #Create For encryption and decryption purpose

users = {}

#read user from CSV file
def read_users_from_csv():
    users = {}
    try:
        with open('users.csv', mode='r', newline='', encoding='utf-8') as file:
            reader = csv.reader(file)
            next(reader)  
            for row in reader:
                if len(row) == 4:
                    username, password_hash, role, permissions = row
                    users[username] = {
                        'password': password_hash,
                        'role': role,
                        'permissions': permissions.split(';')
                    }
    except FileNotFoundError:
        #if user not exist, create it and write header
        with open('users.csv', mode='w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerow(['Username', 'Password', 'Role', 'Permissions'])
    return users


#write new user into CSV file
def write_user_to_csv(username, password_hash, role, permissions):
    with open('users.csv', mode='a', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow([username, password_hash, role, ';'.join(permissions)])


#set the session to false before the first request
@app.before_first_request
def initialize():
    session['logged_in'] = False


#decorator that required a valid JWT token for protected route
def token_required (func):
    @wraps(func)
    def decorated(*args, **kwargs):
        token = request.args.get ('token' )
        if not token:
            return jsonify({'Alert':'Token is missing'}), 403
        try:
            payload = jwt.decode(token, app. config[ 'SECRET_KEY'], algorithms=["HS256"])
            if 'user' in payload and payload['user'] in users:
                return func(*args, **kwargs)
            else:
                raise RuntimeError('User not found')
        except jwt.ExpiredSignatureError:
            return jsonify({'Alert': 'Token expired, please log in again'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'Alert': 'Invalid token, please log in again'}), 403
    return decorated

#home page route
@app.route('/')
def home():
    return render_template('register.html')

#login page route
@app.route('/login')
def login_page():
    if not session.get('logged_in'):
        return render_template('login.html')
    else:
        return 'Logged in successful'

#public route    
@app.route('/public')
def public():
    return'For Public'

#protected route which required valid token
@app.route('/auth')
@token_required 
def auth():
    return 'Verified Succesful. Welcome!'

#user registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        users = read_users_from_csv()
        if username in users:
            return make_response('User already exists', 400)
        else:
            password_hash = generate_password_hash(password)
            write_user_to_csv(username, password_hash, 'user', ['read'])
            return render_template('login.html', message='Successfully registered! Please log in.')
    else:
        return render_template('register.html')

#user login route
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    users = read_users_from_csv()
    user = users.get(username)
    if user and check_password_hash(user['password'], password):
        session['logged_in'] = True
        token = jwt.encode({
            'user': username,
            'role': user['role'],
            'permissions': user['permissions'],
            'system': 'myFlaskApp',
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + timedelta(seconds=120),
            'iss': 'myFlaskApp',
            'aud': 'myFlaskAppUsers'
        }, app.config['SECRET_KEY'], algorithm="HS256")
        
        #Encrypt the token
        encrypted_token = fernet.encrypt(token.encode())
        return jsonify({'message': 'Login Successfully', 'Encrypted Token': encrypted_token.decode()})
    else:
        return make_response('Verify failed', 403, {'WWW.Authenticate': 'Basic realm:"Authentication Failed'})

#decrypt token route
@app.route('/decrypt_token')
def decrypt_token():
    encrypted_token = request.args.get('token')
    if not encrypted_token:
        return jsonify({'error': 'No token provided'}), 400

    try:
        #Decrypt the token
        decrypted_token = fernet.decrypt(encrypted_token.encode()).decode()
        return jsonify({'decrypted_token': decrypted_token})
    except Exception as e:
        return jsonify({'error': 'Failed to decrypt token', 'message': str(e)}), 500

#run Flask app if this file is executed as the main program
if __name__ == "__main__":
    app.run(debug=True)
