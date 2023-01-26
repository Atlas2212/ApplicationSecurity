from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager
 
login = LoginManager()
db = SQLAlchemy()
 
class UserModel(UserMixin, db.Model):
    __tablename__ = 'users'
 
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(80), unique=True)
    username = db.Column(db.String(100))
    password_hash = db.Column(db.String())
    security_answer1 = db.Column(db.String(255))
    security_answer2 = db.Column(db.String(255))
    security_answer3 = db.Column(db.String(255))
    failed_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime)
 
    def set_password(self,password):
        self.password_hash = generate_password_hash(password)
     
    def check_password(self,password):
        return check_password_hash(self.password_hash,password)

    def set_email(self,email):
        self.email = email
    
    def set_username(self,username):
        self.username = username
    
    def set_security_answer1(self,security_answer1):
        self.security_answer1 = security_answer1

    def set_security_answer2(self,security_answer2):
        self.security_answer2 = security_answer2

    def set_security_answer3(self,security_answer3):
        self.security_answer3 = security_answer3
        
    

 
 
@login.user_loader
def load_user(id):
    return UserModel.query.get(int(id))