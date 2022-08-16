from __main__ import app
from flask import render_template, flash
from flask import redirect, url_for, request
from flask_login import login_required
from main import Item_db, db
from flask import session as user_session

def flash_msg(msg):
  user_session.pop('_flashes', None)
  flash(msg)

@app.route("/admin/manage")
@login_required
def manage():
  product_lst = []
  try:
    is_admin = user_session["admin"]
  except:
    return(redirect(url_for("main")))
  if is_admin == None:
    return redirect(url_for("login"))
  elif is_admin == True:
    object_product_lst = Item_db.query.all()
    for item in object_product_lst:
      product_lst.append({"item_id":item.item_id,"price":item.price,"name":item.name})
    return render_template("/admin/manage.html",product_lst=product_lst)
  elif is_admin == False:
    return redirect(url_for("main"))

@app.route("/admin/api/add_item")
@login_required
def add_item():
  try:
    is_admin = user_session["admin"]
  except:
    return redirect(url_for("login"))
  if is_admin == None:
    return redirect(url_for("login"))
  elif is_admin == True:
    try:
      name = request.args.get("name")
      price = int(request.args.get("price"))
      if price < 0 or price > 9999:
        flash_msg("Invalid price")
        return(redirect(url_for("manage")))
      product = Item_db(name,price)
      db.session.add(product)
      db.session.commit()
      flash_msg("item sucessfully added")
      return redirect(url_for("manage"))
    except:
      return(redirect(url_for("internal_server_error")))
  else:
    return redirect(url_for("main"))

@app.route("/admin/api/delete_item")
@login_required
def delete_item():
  try:
    is_admin = user_session["admin"]
  except:
    return redirect(url_for("main"))
  if is_admin == None:
    return redirect(url_for("login"))
  elif is_admin == True:
    try:
      item_id = request.args.get("item_id")
      item_exists = db.session.query(Item_db.item_id).filter_by(item_id=item_id).first() is not None
      if item_exists:
        Item_db.query.filter_by(item_id=item_id).delete()
        db.session.commit()
        flash_msg("item succesfully deleted")
        return redirect(url_for("manage"))
      else:
        flash_msg("Invalid item id")
        return redirect(url_for("manage"))
    except:
      return(redirect(url_for("manage")))
  else:
    return redirect(url_for("main"))
