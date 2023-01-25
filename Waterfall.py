import sqlite3
from flask import Flask,render_template,request,redirect,jsonify
from flask_login import login_required, current_user, login_user, logout_user
from models import UserModel,db,login
import re
from flask import request
import datetime 
import random

app = Flask(__name__)
app.secret_key = 'yuewei'
ADMIN_USERNAME = "admin@bernice"
ADMIN_PASSWORD = "iloveyuewei"
EMAIL_HOST = "smtp.gmail.com"
EMAIL_PORT = 587
EMAIL_HOST_USER = "bernicelim584@gmail.com"
EMAIL_HOST_PASSWORD = ""
EMAIL_USE_TLS = True 


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
login.init_app(app)
login.login_view = 'login'

 
@app.before_first_request
def create_all():
    db.create_all()
     
@app.route('/home')
@login_required
def home():
    return render_template('home.html')
 
 
@app.route('/login', methods = ['POST', 'GET'])
def login():
    if current_user.is_authenticated:
        return redirect('/home')

    if request.method == 'POST':
        email = request.form['email']
        user = UserModel.query.filter_by(email = email).first()
        if user is not None:
            if user.locked_until and user.locked_until > datetime.datetime.now():
                return render_template('login.html', password_error="Invalid credentials. Please try again.")
            if user is not None and request.form['password'] == ADMIN_PASSWORD and request.form['email'] == ADMIN_USERNAME:
                user.failed_attempts = 0
                db.session.commit()
                login_user(user)
                return redirect('/admin')
            if user is not None and user.check_password(request.form['password']):
                user.failed_attempts = 0
                db.session.commit()
                login_user(user)
                return redirect('/home')
            else:
                user.failed_attempts += 1
                if user.failed_attempts >= 3:
                    user.locked_until = datetime.datetime.now() + datetime.timedelta(minutes=3)
                    db.session.commit()
                    return render_template('login.html', password_error="Error: Your account is locked for 3 minutes due to too many failed login attempts.")
                db.session.commit()
                return render_template('login.html', password_error="Invalid credentials. Please try again.")
    else:
        return render_template('login.html')

     
    return render_template('login.html')


@app.route('/register', methods=['POST', 'GET'])
def register():
    if current_user.is_authenticated:
        return redirect('/home')
     
    if request.method == 'POST':
        email = request.form['email']
        username = request.form['username']
        security_answer1 = request.form['security_answer1']
        security_answer2 = request.form['security_answer2']
        security_answer3 = request.form['security_answer3']
        password = request.form['password']
        has_uppercase = bool(re.search(r'[A-Z]', password))
        has_lowercase = bool(re.search(r'[a-z]', password))
        has_special = bool(re.search(r'[!@#\$%^&*]', password))
        is_long_enough = len(password) >= 8

        if username.lower() in password.lower():
            return render_template('register.html', email=email, username=username, password_error='password cannot contain username.')
        else:
            if has_uppercase and has_lowercase and has_special and is_long_enough:
                if UserModel.query.filter_by(email=email).first():
                    return ('Email already Present')
                
                user = UserModel()
                user.set_password(password)
                user.set_email(email)
                user.set_username(username)
                user.set_security_answer1(security_answer1)
                user.set_security_answer2(security_answer2)
                user.set_security_answer3(security_answer3)
                db.session.add(user)
                db.session.commit()
                return redirect('/login')
            else:
                return render_template('register.html', email=email, username=username, password_error='password does not meet the requirements. It must have at least one uppercase letter, one lowercase letter, one special character and must be at least 8 characters long.')
        
    return render_template('register.html')
 


@app.route('/logout')
def logout():
    logout_user()
    return redirect('/home')

if __name__ == '__main__':
   app.run(host="localhost", port=1306, debug=True)


#not complete, random password generator
@app.route('/register', methods=['POST'])
def register():
    # Get the user's credentials from the request
    username = request.json['username']

    # Generate a random password based on the username
    password = ''.join(random.choices(string.ascii_letters + string.digits, k=8)) + username[:2]
    # Save the user's credentials (username, hashed_password) to the database
    # ...
    return jsonify({'message': 'Registration successful. Your password is: '+password}), 201