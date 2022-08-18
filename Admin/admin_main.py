from __main__ import app
from flask import render_template
from flask import redirect, url_for, flash
from flask_login import login_required
from main import db, Users_db, Item_db
from flask import session as user_session
import defusedxml.ElementTree as ET
import pickle
from Offsite_Database.check_signature import check_signature

def flash_msg(msg):
  user_session.pop('_flashes', None)
  flash(msg)

@app.route("/make_admin")
@login_required
def make_admin():
  token = user_session["token"]
  exists = db.session.query(Users_db.token).filter_by(token=token).first() is not None #testing purposes only
  if exists == True:
    current_user = db.session.query(Users_db).filter_by(token=token).first()
    current_user.admin = True
    db.session.commit()
    user_session["admin"] = current_user.admin
  return(redirect(url_for("main")))

@app.route("/admin")
@login_required
def main_admin(): 
  try:
    is_admin = user_session["admin"]
  except:
    return redirect(url_for("main"))
  if is_admin == None:
    return redirect(url_for("login"))
  elif is_admin == True:
    tree=ET.parse("admin/info.xml")
    root=tree.getroot()
    XML_dict = {}
    headers = []
    for child in root:
      for item in child:
        lst = []
        if child.attrib["id"] not in XML_dict:
          lst.append(item.text)
          XML_dict[child.attrib["id"]] = lst
        else:
          temp_lst = XML_dict[child.attrib["id"]]
          temp_lst.append(item.text)
          XML_dict[child.attrib["id"]] = temp_lst
        if item.tag not in headers:
          headers.append(item.tag)

    return render_template("/admin/homepage.html",xml_lst=XML_dict,headers=headers)
  elif is_admin == False:
    return redirect(url_for("main"))
  

@app.route("/api/get_pickle_file",methods=["GET","POST"])
@login_required
def get_pickle_file():
  try:
    is_admin = user_session["admin"]
  except:
    return redirect(url_for("main"))
  if is_admin == None:
    return redirect(url_for("login"))
  elif is_admin == True:
    try:
      valid_signature = False
      modified_valid_signature = False
      product_lst = []
      product_lst_modified = []
      valid_signature,modified_valid_signature = check_signature("public_key.der","offsite_database_signature.txt","offsite_database.txt","offsite_database_modified.txt")
      
      if valid_signature:
        with open("offsite_database.txt","rb") as m:
          for i in range(3):
            product_lst.append(pickle.load(m))
      else:
        flash_msg("Invalid signature, offsite database file is not safe to deserialise")

      if modified_valid_signature:
        with open("offsite_database_modified.txt","rb") as m:
          for i in range(3):
            product_lst_modified.append(pickle.load(m))
      else:
        flash_msg("Invalid signature, offsite database modified file is not safe to deserialise")
      for i in product_lst:
        exists = db.session.query(Item_db.item_id).filter_by(item_id=i.item_id).first() is not None
        if exists == False:
          db.session.add(i)
        db.session.commit()
      return(redirect(url_for("manage")))
    except:
      return(redirect(url_for("internal_server_error")))
  elif is_admin == False:
    return redirect(url_for("main"))