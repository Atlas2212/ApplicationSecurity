from datetime import datetime
from flask import redirect, render_template
from flask import  url_for
from flask import request, request, flash
from flask import session as user_session
from flask_login import  login_user,logout_user, login_required
from tools.random_key import get_random_string
from __main__ import app
from main import Users_db, db,bcrypt,mail
from flask_mail import Message
import re
import pyotp
from datetime import datetime,timedelta

def flash_msg(msg):
  user_session.pop('_flashes', None)
  flash(msg)

@app.route("/login")
def login():
  return render_template('frontend/login.html')

@app.route("/signup")
def signup():
  return render_template("/frontend/signup.html",error="")

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("main"))
    
@app.route("/login/signin",methods=["GET","POST"])
def signin():
  current_user = ""
  try: #attempts to get username and password from html form, checks if username exist in database
    username = request.form.get("username")
    password = request.form.get("password")
    exists = db.session.query(Users_db.username).filter_by(username=username).first() is not None
  except:
    flash_msg("Invalid username or password was entered")
    return(redirect(url_for("login")))

  try:
    if exists == True:
        current_user = Users_db.query.get(username) #get user object using username as primary key
        if current_user.login_attempt > 3 or current_user.active == False: #checks if user account is active or has login too many times
            current_user.active = False
            db.session.commit()
            flash_msg("Login too many times,account has been deactivated")
            return redirect(url_for("login"))

        if bcrypt.check_password_hash(current_user.password,password): #Compares password hashes of the password inputed and the password stored
            if current_user.two_fa == True:
              user_session["username"] = username
              return(redirect(url_for("two_factor_site")))
            login_user(current_user)
            current_user.token = get_random_string(8)
            current_user.login_attempt = 0 #reset login attempt
            db.session.commit()
            user_session["token"] = current_user.token
            user_session["admin"] = current_user.admin
            if current_user.admin == True:
              return(redirect(url_for("main_admin")))
            else:
              return(redirect(url_for("main")))
        else: #invalid password
          current_user.login_attempt += 1 #add login attempt
          db.session.commit()
          flash_msg("Invalid username or password was entered")
          return redirect(url_for("login"))
  except:
    return(redirect(url_for("internal_server_error")))
  flash_msg("Invalid username or password was entered")
  return(redirect(url_for("login")))
@app.route("/signup/create",methods=["GET","POST"])
def create_account():
  try:
    new_username = request.form.get("username") #retrieve username,password,confirm_password,email from html form
    new_password = request.form.get("password")
    new_email = request.form.get("email")
    confirm_password = request.form.get("confirm_password")
    exists = db.session.query(Users_db.username).filter_by(username=new_username).first() is not None #checks if username exists
  except:
    return redirect(url_for("internal_server_error")) #if error 
  try:
    if exists == True:
      flash_msg('Username already exists') #reject username that already exists
      return redirect(url_for("signup"))
    if new_password != confirm_password:
      flash_msg("Passwords do not match") #reject if password is not the same as the confirm password field
      return redirect(url_for("signup"))
    if len(new_username) > 15 or len(new_username) < 8:
      flash_msg('Username length should be within 8-15 letters')
      return redirect(url_for("signup"))
    
    regex_password = "^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{8,}$"
    if re.search(regex_password,new_password) == None: #checks if password meets minimum requirements
      flash_msg('''Password requires:
At least one upper case English letter,
At least one lower case English letter,
At least one digit,
At least one special character,
Minimum eight characters''')
      return redirect(url_for("signup"))

    regex_email = '^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$'
    if (re.search(regex_email,new_email) == None): #checks if email is in a valid format
      flash_msg("Invalid email address")
      return redirect(url_for("signup"))
    # passed all validation checks
    new_password_hash = bcrypt.generate_password_hash(new_password) #generate password hash of inputed password
    new_user = Users_db(new_username,new_password_hash,new_email) #create new user object with inputed details
    db.session.add(new_user)
    db.session.commit()
    return redirect(url_for("login"))
  except:
    return(redirect(url_for("internal_server_error")))

@app.route("/api/reset_password",methods=["GET","POST"])
def password_reset():
  try:
    username = request.form.get("username")
    exists = db.session.query(Users_db.username).filter_by(username=username).first() is not None
    if exists:
        current_user = Users_db.query.get(username)
        temp = get_random_string(12)
        username = current_user.username
        email = current_user.email
        current_user.password = bcrypt.generate_password_hash(temp) #hash randomly generated password
        msg = Message('Reset password for La Rose fanée', sender =   'smtp.gmail.com', recipients = [email])
        msg.body = f"Hey {username}, your new password is {temp}"
        mail.send(msg)
        db.session.commit()
        return(redirect(url_for("login")))
    else:
        return(redirect(url_for("login")))
  except:
    return(redirect(url_for("login")))
    
@app.route("/reset_password")
def reset_password_site():
  return(render_template("frontend/reset_password.html"))

@app.route("/change_password")
def change_password_site():
  return(render_template("frontend/change_password.html"))

@app.route("/api/change_password", methods=["POST","GET"])
@login_required
def change_password():
  try:
    token = user_session["token"]
    old_password = request.form.get("old_password")
    new_password = request.form.get("new_password")
    confirm_password = request.form.get("confirm_password")
  except:
    flash_msg("please input a valid passsword or new password")
    return(redirect(url_for("change_password_site")))
  try:
    exists = db.session.query(Users_db.token).filter_by(token=token).first() is not None
    if exists:
      current_user = Users_db.query.filter_by(token=token).first()
      if new_password != confirm_password:
        flash_msg("Password and confirm password do not match")
        return(redirect(url_for("change_password_site")))
      if bcrypt.check_password_hash(current_user.password,old_password) :
        current_user.password = bcrypt.generate_password_hash(new_password)
        db.session.commit()
        flash_msg("Password changed sucessfully")
        email = current_user.email
        username = current_user.username
        msg = Message('Change password for La Rose fanée', sender =   'smtp.gmail.com', recipients = [email])
        msg.body = f"Hey {username}, your Password was changed, if this is not done by you, please immediately change your password and contact us"
        mail.send(msg)

      else:
        flash_msg("Old password is invalid")
        return(redirect(url_for("change_password_site")))
    return redirect(url_for("change_password_site"))
  except:
    return(redirect(url_for("internal_server_error")))

@app.route("/2FA")
def two_factor_site():
  try:
    username = user_session["username"]
    if Users_db.query.get(username) is None:
      return(redirect(url_for("login")))
    current_user = Users_db.query.get(username)
    secret = pyotp.TOTP('base32secret3232').now()
    current_user.otp = secret
    current_user.otp_expire = datetime.now() + timedelta (minutes=15)
    email = current_user.email
    db.session.commit()
    msg = Message('OTP for La Rose fanée', sender =   'smtp.gmail.com', recipients = [email])
    msg.body = f"Hey {username}, your otp is {secret}. Do not share your otp with others"
    mail.send(msg)
  except:
    return(redirect(url_for("login")))
  return render_template("frontend/two_factor.html")

@app.route("/api/2FA" ,methods=["POST","GET"])
def two_factor():
  try:
    otp = request.form.get("otp")
    username = user_session["username"]
    current_user = Users_db.query.get(username)
    secret = current_user.otp
    if current_user.otp_expire is None or secret == "":
      del user_session["username"]
      return(redirect(url_for("login")))
    if datetime.now() > current_user.otp_expire:
      flash_msg("OTP has expired")
      del user_session["username"]
      return(redirect(url_for("login")))
  except:
    return(redirect(url_for("login")))
  if secret == otp:
    current_user = Users_db.query.get(username)
    login_user(current_user)
    current_user.token = get_random_string(8)
    current_user.login_attempt = 0 #reset login attempt
    db.session.commit()
    user_session["token"] = current_user.token
    user_session["admin"] = current_user.admin
    current_user.otp_expire = None
    current_user.otp = ""
    db.session.commit()
    if current_user.admin == True:
      return(redirect(url_for("main_admin")))
    else:
      return(redirect(url_for("main")))
  else:
    flash_msg("Invalid OTP entered")
    return(redirect(url_for("two_factor_site")))
  
