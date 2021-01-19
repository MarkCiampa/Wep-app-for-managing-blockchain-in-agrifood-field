from flask import Flask
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask_login import UserMixin, LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail
import os
app = Flask(__name__)
app.config['SECRET_KEY'] = '9OLWxND4o83j4K4iuopO'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
db = SQLAlchemy(app)
app.config.update(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=465,
    MAIL_USE_SSL=True,
    MAIL_USERNAME = '',
    MAIL_PASSWORD = '')
'''app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 
app.config['MAIL_USERNAME']
app.config['MAIL_PASSWORD']
app.config['MAIL_USE_TLS']
app.config['MAIL_USE_SSL']'''

mail = Mail(app)



class User(UserMixin, db.Model):
    p_iva = db.Column(db.Integer, primary_key=True) # primary keys are required by SQLAlchemy
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))
    info= db.Column(db.String(2000))
    sede=db.Column(db.String(100))

    def get_reset_token(self, expires_sec=18000):
        s = Serializer(app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'user_id': self.p_iva}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)
    

from app import views

login_manager = LoginManager()
login_manager.login_view = 'login.html'
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    # since the user_id is just the primary key of our user table, use it in the query for the user
    return User.query.get(int(user_id))
