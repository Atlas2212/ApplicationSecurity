from flask import redirect, render_template
from flask import url_for
from flask import request, request
from flask import jsonify
from __main__ import app
from main import Item_db

@app.route("/")
def main():
  return render_template('/frontend/homepage.html')

@app.route("/500")
def internal_server_error():
  return render_template("frontend/error500.html")

@app.route("/productPage")
def product_page():
  try:
    product_info_lst = []
    product_lst = Item_db.query.all()
    for i in product_lst:
      product_info_lst.append([i.name,i.price,i.item_id])
    return render_template("frontend/productPage.html",product_info=product_info_lst)
  except:
    return redirect(url_for("internal_server_error"))
   
@app.route("/is_xml",methods=['GET', 'POST'])
def is_xml():
  if request.method == "POST":
        passwords = request.get_json()
        if passwords["password"] == passwords["confirm_password"]:
          same_password = True
        else:
          same_password = False
        return jsonify({"same_password":same_password})
