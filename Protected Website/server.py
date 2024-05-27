import requests
import base64
import time
from flask import Flask, render_template, request, jsonify, redirect, url_for, Response
import sqlite3
from flask_login import LoginManager, login_required, login_user, logout_user
from flask_cors import CORS
app = Flask(__name__)
app.config['SECRET_KEY'] = 'OTP'
CORS(app)


login_manager = LoginManager()
login_manager.init_app(app)
class User():
    """
    Users
    :param str user: username
    :param str password:  password for the user
    """
    def __init__(self, username, password, authenticated):
        self.username = username
        self.password = password
        self.authenticated = authenticated

    def is_active(self):
        """
        True, as all users are active
        """
        return True
    def get_id(self):
        """
        Return the user to satisfy Flask-Login's requirements
        """
        return self.username

    def is_authenticated(self):
        """
        Return True if the user is authenticated
        """
        return self.authenticated

    def is_anonymous(self):
        """
        False, as anonymous users aren't supported
        """
        return False
def get_db_connection():
    return sqlite3.connect('database.db')

@login_manager.user_loader
def load_user(user_id):
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute('SELECT * FROM t_users WHERE uname = ?', (user_id,))
    user_data = cursor.fetchone()
    connection.close()

    if user_data:
        return User(user_data[0], user_data[1], True)  
    else:
        return None


def create_database():
    connection = sqlite3.connect('database.db')
    cursor = connection.cursor()

    CREATE_USER_TABLE = '''
        CREATE TABLE IF NOT EXISTS t_users (
            uname TEXT,
            password TEXT
        )
    '''

    cursor.execute(CREATE_USER_TABLE)
    cursor.execute("INSERT INTO t_users (uname, password) VALUES ('otp@email.com', 'password')")
    
    connection.commit()
    connection.close()



global USER_LOGGED_IN
USER_LOGGED_IN = False
global OTP_AUTHENTICATED
OTP_AUTHENTICATED = False
global user

create_database()

@app.route("/", methods=['GET'])
def login_page():
    return render_template('index.html')

@app.route("/logging", methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    print(username,password)
    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute('SELECT * FROM t_users WHERE uname = ? AND password = ?', (username, password))
    global user
    user = cursor.fetchone()
    connection.close()

    if user:
        #login_user(user_obj, remember=True)
        print("[SUCCESS] Logged in")
        global USER_LOGGED_IN
        USER_LOGGED_IN = True
        return jsonify({"success": True})  # Return success JSON response
    else:
        print("[FAILED] tried to login but failed")
        return jsonify({"success": False})  # Return failure JSON response

@app.route("/otp")
def otp():
    if USER_LOGGED_IN:
        return render_template('otp.html')
    else:
        return redirect('/')

@app.route("/otp_auth", methods=['POST'])
def otp_check():
    data = request.json
    otp = data.get('accept')
    if otp == 'TRUE':
        user_obj = User(user[0], user[1], True)
        print(user_obj.is_authenticated())
        print("[SUCCESS] Logged in with OTP")
        return jsonify({"success": True})  # Return success JSON response

    else:
        print("[FAILED] tried to login but failed")
        return jsonify({"success": False})  # Return failure JSON response

@app.route("/directsuccess")
def route():
    global OTP_AUTHENTICATED
    global USER_LOGGED_IN
    if OTP_AUTHENTICATED and USER_LOGGED_IN:
        user_obj = User(user[0], user[1], True)
        login_user(user_obj,remember=True)
        return redirect("/loggedin")
    else:
        return redirect("/")

@app.route("/loggedin")
@login_required
def secret():
    print("rendering template")
    return render_template('logged.html')

@app.route("/logout", methods=['POST'])
@login_required
def logout():
    print("Logging out")
    global USER_LOGGED_IN
    global OTP_AUTHENTICATED
    OTP_AUTHENTICATED = False
    USER_LOGGED_IN = False

    logout_user()
    return jsonify({"success": True})  # Return success JSON response

@app.route("/validate", methods=["POST"])
def trigger_challenge():
    import ssl
    print(ssl.OPENSSL_VERSION)
    user = "frankuman"
    serial = "TOTP00001E11"
    totp = request.form.get("code")
    data = {
        "user": user,
        "serial": serial,
    }
    
    # Prepare the headers for the POST request
    headers = {
        "Host": "127.0.0.1:5000",
        "Accept": "application/json",
        "PI-Authorization": "YOUR API KEY", #insert api here
        "Content-Type": "application/x-www-form-urlencoded"  # Specify content type
    }
    # Make the POST request to the PrivacyIDEA server
    response = requests.post("http://127.0.0.1:5000/validate/triggerchallenge", data=data, headers=headers)
    data = response.json()  # Use response.json() to parse JSON response    user = data.get("user")
    print(data)
    if not response.ok:
        print("Failed to trigger")
        return jsonify({"error": "Failed to trigger challenge"}), 500
        
    transaction_id = data.get("transaction_id")
    credentialid = data.get("credentialid")
    clientdata = "test_otp"
    signaturedata = "test_sign"
    authenticatordata = "test_auth"
    userhandle = data.get("userhandle")
    assertionclientextensions = "test"
    totp = "123"+totp
    payload = {
        "user": user,
        "pass": totp,
        "transaction_id": transaction_id,
        "credentialid": credentialid,
        "clientdata": clientdata,
        "signaturedata": signaturedata,
        "authenticatordata": authenticatordata,
        "userhandle": userhandle,
        "assertionclientextensions": assertionclientextensions
    }

    # Make a POST request to the PrivacyIDEA server
    privacyidea_server_url = "http://127.0.0.1:5000/validate/check"
    response = requests.post(privacyidea_server_url, json=payload)
    data = response.json()  # Use response.json() to parse JSON response    user = data.get("user")
    print(data)
    # Check if the request was successful
    if response.ok:
        # Return the response from the PrivacyIDEA server
        message = response.json().get('detail', {}).get('message')
        if message == 'wrong otp pin':
            return jsonify({"result": "wrong"})  # Return wrong response
        else:
            global OTP_AUTHENTICATED
            OTP_AUTHENTICATED = True

            return jsonify({"result": "success"})  # Return success response
        
    else:
        # Return an error response if the request failed
        print("Failed to validate")
        return jsonify({"result": "fail"})  # Return fail response

    
if __name__ == "__main__":
    app.run(debug=True, port=8080, host='10.0.2.15')