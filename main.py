from flask import Flask,redirect, url_for,render_template, flash,get_flashed_messages, jsonify, session,request
from flask_sqlalchemy import SQLAlchemy
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor,CKEditorField
from flask_login import login_manager,login_user,login_required,logout_user,UserMixin,LoginManager,current_user
from flask_wtf import FlaskForm
from datetime import datetime,timedelta
from wtforms import StringField,SubmitField, DateField
# pip install email_validator
from wtforms.validators import  Email,DataRequired
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
from flask_mail import Mail,Message
import os
import json
from google_auth_oauthlib.flow import InstalledAppFlow
from google.oauth2.credentials import Credentials
GMAIL_SCOPES =['https://www.googleapis.com/auth/gmail.compose']

app=Flask(__name__)

app.config['SECRET_KEY'] ="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"
Bootstrap(app)
app.config['SQLALCHEMY_DATABASE_URI']="sqlite:///app.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=False
app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS']= True
app.config['MAIL_PASSWORD']="xhghldnmltdgpopw"
app.config['MAIL_USERNAME']= "johny.achkar01@gmail.com"
db=SQLAlchemy(app)
ckeditor=CKEditor(app)
migrate=Migrate(app,db)


mail=Mail(app)

def get_gmail_credentials():
    creds = None
    current_script_path = os.path.abspath(__file__)
    current_script_directory = os.path.dirname(current_script_path)
    resources = os.path.join(current_script_directory, "resources")
    credentials_file = f"{resources}/json_file.json"


    if os.path.exists('token.json'):
        with open('token.json', 'r') as token_file:
            credentials_data = token_file.read()
            creds = Credentials.from_authorized_user_info(json.loads(credentials_data))

    if not creds or not creds.valid:
        flow = InstalledAppFlow.from_client_secrets_file(credentials_file, GMAIL_SCOPES)
        creds = flow.run_local_server(port=0)

        # Save credentials to token.json
        with open('token.json', 'w') as token_file:
            token_file.write(creds.to_json())

    return creds

class User(UserMixin,db.Model):
    __tablename__="user"
    id=db.Column(db.Integer,primary_key=True)
    name=db.Column(db.String())
    email = db.Column(db.String, unique=True)
    password=db.Column(db.String())
    date=db.Column(db.Date,default=datetime.utcnow)


class Blog(db.Model):
    __tablename__='blog'
    id=db.Column(db.Integer,primary_key=True)
    title=db.Column(db.String(),unique=True)
    subtitle=db.Column(db.String())
    body=db.Column(db.String())
    author=db.Column(db.String())
    date=db.Column(db.Date,default=datetime.utcnow)

class Comment(db.Model):
    __tablename__='comment'
    id=db.Column(db.Integer,primary_key=True)
    author=db.Column(db.String())
    date=db.Column(db.Date,default=datetime.utcnow)
    text = db.Column(db.String())

class Contact(db.Model):
    __tablename__='contact'
    message_id=db.Column(db.Integer,primary_key=True)
    email=db.Column(db.String())
    name=db.Column(db.String())
    message=db.Column(db.String())
    date=db.Column(db.Date,default=datetime.utcnow)

# with app.app_context():
#     db.create_all()
# now define class forms
class ContactForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()], render_kw={'autocomplete': 'off'})
    email = StringField('Email', validators=[DataRequired(), Email()], render_kw={'autocomplete': 'off'})
    message = CKEditorField('Message', validators=[DataRequired()], render_kw={'autocomplete': 'off'})
    submit = SubmitField('Submit')

class UserForm(FlaskForm):
    name=StringField('Name',validators=[DataRequired()], render_kw={'autocomplete':'off'})
    email=StringField('Email',validators=[DataRequired(),Email()], render_kw={'autocomplete':'off'})
    password=StringField('Password',validators=[DataRequired()],render_kw={'autocomplete':'off'})
    submit = SubmitField('Sign In')
    sign_up=SubmitField('Sign Up')

@app.route('/register',methods=['GET','POST'])
def register():
    form =UserForm()
    email=request.form.get('email')
    user=User.query.filter_by(email=email).first()
    if request.method=='POST'and form.validate_on_submit():
        if user:

            flash("Email already exists")
            return redirect(url_for('home'))
        hash_and_salted_password=generate_password_hash(
            request.form.get('password'),
            method='pbkdf2:sha256',
            salt_length=8
        )
        new_user=User(
            name=request.form.get('name'),
            email=email,
            password=hash_and_salted_password,
        )
        db.session.add(new_user)
        db.session.commit()
        flash('Congratulations, you are registered')
        return redirect(url_for('home'))
    return render_template('register.html',form=form)


@app.route('/',methods=['GET','POST'])
def home():
    form=UserForm()
    if request.method=='POST':
        email = request.form.get('email')
        password=request.form.get('password')
        user= User.query.filter_by(email=email).first()
        if not user:
            flash("Incorrect Email. Please verify your email")
            return redirect(url_for('home'))
        elif not check_password_hash(user.password,password):
            flash("Incorrect Password")
            return redirect(url_for('home'))
        else:
            return redirect(url_for('estimation'))
    return render_template('index.html',form=form)


@app.route('/contact', methods=['GET', 'POST'])
def contact():
    form = ContactForm()
    if request.method == 'POST' and form.validate_on_submit():
        gmail_creds = get_gmail_credentials()
        email = request.form.get('email')
        message_content = request.form.get('message')
        name = request.form.get('name')

        new_message = Contact(
            email=email,
            name=name,
            message=message_content,
        )
        db.session.add(new_message)
        db.session.commit()

        subject = "New Contact Form Submission"
        sender_email = email  # Use the user's email as the sender
        company_email = "johny.achkar01@gmail.com"  # Replace with your company's email

        msg = Message(subject=subject, sender=sender_email, recipients=[company_email])
        msg.body = f"Name:{name}\nEmail: {email}\nMessage: {message_content}"

        try:
            mail.init_app(app)
            mail.send(msg)
            flash('Email sent successfully')
            return redirect(url_for('home'))
        except Exception as e:
            print(f"Error sending email: {str(e)}")
            return redirect(url_for('home'))
    return render_template('contact.html', form=form)

# @app.route('/estimation',methods=['GET','POST'])
# def estimation():





if __name__=="__main__":
    app.run(debug=True)