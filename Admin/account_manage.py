from __main__ import app
from flask import render_template, flash
from flask import redirect, url_for, request
from flask_login import login_required
from tools.random_key import get_random_string
from main import db, Users_db,mail,bcrypt
from flask_mail import Message
from flask import session as user_session

def flash_msg(msg):
  user_session.pop('_flashes', None)
  flash(msg)

@app.route("/admin/account_manage")
@login_required
def account_manage():
  try:
    is_admin = user_session["admin"]
  except:
    return redirect(url_for("internal_server_error"))
  if is_admin == None:
    return redirect(url_for("login"))
  elif is_admin == True:
    account_dict = {}
    raw_account_lst = Users_db.query.all()
    for i in raw_account_lst:
      account_dict[i.username] = [i.admin,i.token,i.login_attempt]
    return(render_template("admin/account_manage.html",account_dict=account_dict))
  else:
    return redirect(url_for("main"))

@app.route("/admin/api/delete_account",methods=["DELETE","POST"])
@login_required
def delete_account():
  try:
    is_admin = user_session["admin"]
  except:
    return redirect(url_for("main"))
  if is_admin == None:
    return redirect(url_for("login"))
  elif is_admin == True:
    try:
      username = request.form.get("username")
      user_exists = db.session.query(Users_db.username).filter_by(username=username).first() is not None
      if user_exists:
        Users_db.query.filter_by(username=username).delete()
        db.session.commit()
      else:
        flash_msg("invalid username")
        return(redirect(url_for("account_manage")))
    except:
      return(redirect(url_for("account_manage")))
    return(redirect(url_for("account_manage")))

@app.route("/admin/api/modify_account",methods=["POST"])
@login_required
def modify_account():
  try:
    is_admin = user_session["admin"]
  except:
    return redirect(url_for("main"))
  if is_admin == None:
    return redirect(url_for("login"))
  elif is_admin == True:
    try:
      username = request.form.get("username")
      login_attempt = request.form.get("login_attempt")
      login_attempt = int(login_attempt)
      role = request.form.get("role")
      reset_password = request.form.get("reset_password")
      target_user = Users_db.query.get(username)

      if role != "admin" and role != "user": #validation to check if inputs are valid
        flash_msg("Please input a valid role")
        return(redirect(url_for("account_manage")))
      if int(login_attempt) < 0:
        flash_msg("Please input a valid login_attempt")
        return(redirect(url_for("account_manage")))
      if reset_password != "Yes" and reset_password != "No":
        flash_msg("Please input a valid reset password input")
        return(redirect(url_for("account_manage")))
  
      target_user.admin = admin 
      target_user.login_attempt = login_attempt
      email = target_user.email
      if role == "admin":
        admin = True
      else:
        admin = False
      if email == "":
        flash_msg("Please input an email for this account")
        return(redirect(url_for("account_manage")))
      if reset_password == "Yes":
        temp = get_random_string(12)
        target_user.password = bcrypt.generate_password_hash(temp) #hash randomly generated password
        msg = Message('Reset password for La Rose fanée', sender =   'smtp.gmail.com', recipients = [email])
        msg.body = f"Hey {username}, your new password is {temp}"
        mail.send(msg)
      db.session.commit()
    except:
      return(redirect(url_for("internal_server_error")))
    return(redirect(url_for("account_manage")))
    