from flask import redirect, render_template
from flask import  url_for
from flask import request, request
from flask import session as user_session
from flask_login import login_required
from __main__ import app
from main import Users_db, db
import tools.MyAes as MyAes

@app.route("/api/add_card",methods=["GET","POST"])
@login_required
def add_card():
      # encode plaintext, then encrypt
  try:
    card_detail = request.form.get("card_number")
    card_name = request.form.get("full_name")
    card_detail = int(card_detail)
    card_expiry_date = int(request.form.get("expiry_date_month") + "/" + request.form.get("expiry_date_year"))
    card_cvv = request.form.get("cvv")
    card_cvv = int(card_cvv)
    token = user_session["token"]
    exists = db.session.query(Users_db.token).filter_by(token=token).first() is not None
    if exists == True:
      current_user = Users_db.query.filter_by(token=token).first() #get current user
      key = MyAes.get_fixed_key()
      ciphertext = MyAes.encrypt(key, card_detail.encode("utf8")) #encrypt card number and expiry date
      expiry_date_ciphertext = MyAes.encrypt(key, card_expiry_date.encode("utf8"))
      current_user._Users_db__card_number = ciphertext
      current_user._Users_db__card_expiry_date = expiry_date_ciphertext
      current_user.full_name = card_name
      db.session.commit()
  except:
    return(redirect(url_for("internal_server_error")))
  return(redirect(url_for("card_details")))

@app.route("/card_details")
@login_required
def card_details():
  try:
    token = user_session["token"]
    exists = db.session.query(Users_db.token).filter_by(token=token).first() is not None
    if exists == True:
      current_user = Users_db.query.filter_by(token=token).first()
      ciphertext = current_user._Users_db__card_number
      cvv_ciphertext = current_user._Users_db__cvv
      expiry_date_ciphertext = current_user._Users_db__card_expiry_date
      if ciphertext == "" or cvv_ciphertext == "" or expiry_date_ciphertext == "":
        return(render_template("frontend/card_details.html"))
      key = MyAes.get_fixed_key()
      full_name = current_user.fullname
      decryptedtext_string = MyAes.decrypt(key, ciphertext).decode("utf8")
      decryptedtext_string_cvv = MyAes.decrypt(key, cvv_ciphertext).decode("utf8")
      decryptedtext_string_expiry_date = MyAes.decrypt(key, expiry_date_ciphertext).decode("utf8")
      return(render_template("frontend/card_details.html",card_details=[full_name,decryptedtext_string,decryptedtext_string_cvv,decryptedtext_string_expiry_date]))
  except:
    return(redirect(url_for("internal_server_error")))