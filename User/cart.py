from flask import redirect, render_template
from flask import url_for
from flask import request, request
from flask import session as user_session
from flask_login import login_required, logout_user
from __main__ import app
from main import Users_db, db, Item_db, Cart_db
import pickle
# @app.route("/api/getcart")
# def get_cart():
#   try:
#     token = user_session["token"]
#     exists = db.session.query(Users_db.token).filter_by(token=token).first() is not None
#     if exists == True:
#       current_user = db.session.query(Users_db).filter_by(token=token).first()
#       user_cart = current_user.cart
#       return {"usercart":user_cart}
#     elif token == None or token == "" or token == NULL:
#       response = make_response(redirect(url_for("login")))
#       return response
#     else:
#       return redirect(url_for("internal_server_error"))
#   except:
#     return redirect(url_for("/internal_server_error"))

@app.route("/cart")
@login_required
def cart():
    cart = Cart_db("Test12345!","","")
    serialized = pickle.dumps(cart)
    filename = "cart.file"
    with open(filename, "wb") as file_object:
      file_object.write(serialized)
    with open(filename, "rb") as file_object:
      raw_data = file_object.read()
    deserialized_data = pickle.loads(raw_data)
    try:
      token = user_session["token"] #get current user identifying token
      exists = db.session.query(Users_db.token).filter_by(token=token).first() is not None #checks if token exists in database and is a valid token
      if exists == True:
        current_user = Users_db.query.filter_by(token=token).first() #get current user object and details from database
        username = current_user.username
        current_user_cart_obj = Cart_db.query.filter_by(username=username).all() #get all cart details from database, search using username
        current_user_cart = []
        for i in current_user_cart_obj:
          item = Item_db.query.get({i.item_id}) #get details about item using item id stored in cart
          # prevents changing of price through form manipulation
          current_user_cart.append([item.name,item.price,i.quantity,i.item_id]) # add items details as well as cart details 
        return render_template("frontend/cart.html",user_cart=current_user_cart,deserialized_data=deserialized_data.username)
      elif token == None or token == "":
        return redirect(url_for("login")) #lf token dont exist, get user to login
      else:
        logout_user()       
        return redirect(url_for("internal_server_error")) #token exists but is invalid
    except:
      return redirect(url_for("internal_server_error"))
    
@app.route("/cart/api/add_to_cart")
@login_required
def add_to_cart():
  try:
    token = user_session["token"]
    item_id = request.args.get("item_id")
    quantity = request.args.get("quantity")
    quantity = int(quantity)
    exists = db.session.query(Users_db.token).filter_by(token=token).first() is not None
    item_exists = db.session.query(Item_db.item_id).filter_by(item_id=item_id).first() is not None
    if exists == True and item_exists == True:
      current_user = Users_db.query.filter_by(token=token).first()
      username = current_user.username
      item_in_cart = Cart_db.query.filter_by(username=username,item_id=item_id).first() #checks if item is in cart
      if item_in_cart is not None:
        item_in_cart.quantity += quantity #if item is in cart add quantity to the existing item object
        db.session.commit()
      else:
        new_item = Cart_db(username,item_id,quantity) #if item not in cart add the a new item object to the cart
        db.session.add(new_item)
        db.session.commit()
      return(redirect(url_for("cart")))
  except:
    return redirect(url_for("internal_server_error"))

@app.route("/cart/api/remove_from_cart")
@login_required
def remove_from_cart():
    try:
      token = user_session["token"]
      item_id = request.args.get("item_id")
      quantity_deleted = request.args.get("quantity")
      quantity_deleted = int(quantity_deleted)
      exists = db.session.query(Users_db.token).filter_by(token=token).first() is not None
      item_exists = db.session.query(Item_db.item_id).filter_by(item_id=item_id).first() is not None
      item_in_cart = db.session.query(Cart_db.item_id).filter_by(item_id=item_id).first() is not None
    except:
      return(redirect(url_for("internal_server_error")))
    try:
      if exists == True and item_exists == True and item_in_cart == True:
        current_user = Users_db.query.filter_by(token=token).first()
        username = current_user.username
        cart_item = Cart_db.query.filter_by(username=username,item_id=item_id).first()
        if (cart_item.quantity - quantity_deleted) <= 0:
          db.session.delete(cart_item)
        else:
          cart_item.quantity -= quantity_deleted
        db.session.commit()
      return(redirect(url_for("cart")))
    except:
      return(redirect(url_for("internal_server_error")))