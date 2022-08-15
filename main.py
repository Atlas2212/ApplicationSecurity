from flask import Flask
from flask import request
from datetime import timedelta
from flask import session as user_session
from flask_sqlalchemy import SQLAlchemy
from tools.random_key import get_random_string
from flask_login import LoginManager
from urllib.parse import urlparse, urljoin
from flask_bcrypt import Bcrypt
from flask_mail import Mail





login_manager = LoginManager()
app = Flask(__name__)
app.config.from_pyfile('config.py')
db = SQLAlchemy(app)
mail = Mail(app)
login_manager.init_app(app)
bcrypt = Bcrypt(app)

class Users_db(db.Model):
  
  username = db.Column("username",db.String, primary_key=True)
  password = db.Column(db.String)
  token = db.Column(db.String)
  admin = db.Column(db.Boolean)
  login_attempt = db.Column(db.Integer)
  active = db.Column(db.Boolean)
  fullname = db.Column(db.String)
  __card_number = db.Column(db.String)
  __card_expiry_date = db.Column(db.String)
  __full_name = db.Column(db.String)
  email = db.Column(db.String)
  two_fa = db.Column(db.Boolean)
  otp = db.Column(db.String)
  otp_expire = db.Column(db.DateTime)
  
  def __init__(self,username,password,email):
    self.username = username
    self.password = password
    self.token = get_random_string(8)
    self.admin = False
    self.active = True
    self.login_attempt = 0
    self.__full_name == ""
    self.__card_number = ""
    self.__card_expiry_date = ""
    self.email = email
    self.fullname = ""
    self.two_fa = True
    self.otp = ""
    self.otp_expire = None

  def is_active(self):
    if self.login_attempt > 3:
      return(False)
    else:
      return(True)

  def get_id(self):
    return(self.username)

  def is_authenticated():
    return(True) 

  def is_anonymous():
    return(False)

  def get_card_number(self):
    return(self.__card_number)

  def get_card_expiry_date(self):
    return(self.__card_expiry_date)

  def set_card_number(self,card_number):
    self.__card_number = card_number
    return

  def set_card_expiry_date(self,expiry_date):
    self.__card_expiry_date = expiry_date
    return 

class Item_db(db.Model):
  __bind_key__ = 'product'
  item_id = db.Column("item_id",db.String, primary_key=True)
  price = db.Column(db.Integer)
  name = db.Column(db.String)

  def __init__(self,name,price):
     self.name = name
     self.price = price
     self.item_id = get_random_string(12)

class Cart_db(db.Model):
  __bind_key__ = "cart"
  cart_item_id = db.Column("cart_item_id",db.Integer,primary_key =True)
  username = db.Column("username",db.String )
  item_id = db.Column(db.String)
  quantity = db.Column(db.Integer)
  
  def __init__(self,username,item_id,quantity):
    self.username = username
    self.item_id = item_id 
    self.quantity = quantity


@login_manager.user_loader
def load_user(user_id):
    return Users_db.query.get(user_id)

@app.before_request
def before_request():
    user_session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=45)

login_manager.login_view = "login"
def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and \
           ref_url.netloc == test_url.netloc
    
import User.frontend
import User.login_system
import User.cart
import User.card_system
import Admin.admin_main
import Admin.product_manage
import Admin.account_manage

if __name__ == "__main__":
      db.create_all()
      app.run(debug=True,ssl_context=('localhost+2.pem', 'localhost+2-key.pem'))



