import re
from flask import redirect, render_template
from flask import  url_for
from flask import request, request,flash
from flask import session as user_session
from flask_login import login_required
from __main__ import app
from main import Users_db, db
import tools.MyAes as MyAes
import datetime

def flash_msg(msg):
  user_session.pop('_flashes', None)
  flash(msg)

@app.route("/api/add_card",methods=["GET","POST"])
@login_required
def add_card():
      # encode plaintext, then encrypt
  try:
    card_detail = request.form.get("card_number")
    card_name = request.form.get("full_name")
    expiry_month = int(request.form.get("expiry_date_month"))
    expiry_year = int(request.form.get("expiry_date_year"))
    card_expiry_date = str(expiry_month) + "/" + str(expiry_year)
    card_cvv = request.form.get("cvv")
    card_detail_regex = "^(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})$"
    if re.search(card_detail_regex,card_detail) == None:
      flash_msg("card number is invalid")
      return(redirect(url_for("card_details")))
    if card_cvv.isdigit() != True or len(str(card_cvv)) != 3:
      flash_msg("Invalid card CVV")
      return(redirect(url_for("card_details")))
    if len(str(expiry_month)) == 2 and len(str(expiry_year)) == 2:
      if int(str(datetime.date.today().year)[2:]) > expiry_year:
        flash_msg("Invalid date entered")
        return(redirect(url_for("card_details")))
      elif datetime.date.today().month > expiry_month and int(str(datetime.date.today().year)[2:]) == expiry_year:
        flash_msg("Invalid date entered")
        return(redirect(url_for("card_details")))
    else:
      flash_msg("Invalid date entered")
      return(redirect(url_for("card_details")))
    token = user_session["token"]
    exists = db.session.query(Users_db.token).filter_by(token=token).first() is not None
    if exists == True:
      current_user = Users_db.query.filter_by(token=token).first() #get current user
      key = MyAes.get_fixed_key()
      ciphertext = MyAes.encrypt(key, card_detail.encode("utf8")) #encrypt card number and expiry date
      expiry_date_ciphertext = MyAes.encrypt(key, card_expiry_date.encode("utf8"))
      current_user._Users_db__card_number = ciphertext
      current_user._Users_db__card_expiry_date = expiry_date_ciphertext
      current_user.fullname = card_name
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
      expiry_date_ciphertext = current_user._Users_db__card_expiry_date
      if ciphertext == "" or expiry_date_ciphertext == "":
        return(render_template("frontend/card_details.html"))
      key = MyAes.get_fixed_key()
      full_name = current_user.fullname
      decryptedtext_string = MyAes.decrypt(key, ciphertext).decode("utf8")
      decryptedtext_string_expiry_date = MyAes.decrypt(key, expiry_date_ciphertext).decode("utf8")
      return(render_template("frontend/card_details.html",card_details=[full_name,decryptedtext_string,decryptedtext_string_expiry_date]))
  except:
    return(redirect(url_for("internal_server_error")))