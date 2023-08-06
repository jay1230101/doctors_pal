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
import random
import openai
import secrets
import string
import os
import json
import requests
from google_auth_oauthlib.flow import InstalledAppFlow
from google.oauth2.credentials import Credentials
GMAIL_SCOPES =['https://www.googleapis.com/auth/gmail.compose']

app=Flask(__name__)

# secret_key is a random characters that enable saving data from the session
app.config['SECRET_KEY'] ="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"
Bootstrap(app)
app.config['SQLALCHEMY_DATABASE_URI']="sqlite:///app.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=False
app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS']= True
# we need to create app password after 2 step veritification to be able to generate a new app password
app.config['MAIL_PASSWORD']="xhghldnmltdgpopw"
app.config['MAIL_USERNAME']= "johny.achkar01@gmail.com"
db=SQLAlchemy(app)
ckeditor=CKEditor(app)
migrate=Migrate(app,db)
# the login manager will redirect non-users who are trying to access restricted pages to login
login_manager= LoginManager()
login_manager.init_app(app)
login_manager.login_view='home'
# the below login_manager.user_loader is mandatory for the login_manager
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
# API for chat GPT FOR JOHNY.ACHKAR01@GMAIL.COM
# api_key=os.environ.get("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")
# openai.api_key=api_key
# API for chat GPT FOR JOHNY.ACHKAR03@GMAIL.COM
# api_key=os.environ.get("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")
openai.api_key="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"


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
    image = db.Column(db.String())

class Blog(db.Model):
    __tablename__='blog'
    id=db.Column(db.Integer,primary_key=True)
    title=db.Column(db.String(),unique=True)
    body=db.Column(db.String())
    author=db.Column(db.String())
    date=db.Column(db.Date,default=datetime.utcnow)
    image=db.Column(db.String())

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

class Token(db.Model):
    __tablename__='token'
    id=db.Column(db.Integer,primary_key=True)
    token_content=db.Column(db.String(),unique=True)
    email = db.Column(db.String())
    expiry_time=db.Column(db.DateTime,nullable=False,default=datetime.utcnow() + timedelta(seconds=120))

# update user table by adding an image
def update_user_image():
    with app.app_context():
        user = User.query.filter_by(email='johny.achkar03@gmail.com').first()
        if user:
            user.image = './static/bassem.png'
            db.session.commit()
            print('User image updated successfully')
        else:
            print('User not found')



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
            session['user_email1']=email
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

@app.route('/send_token',methods=['GET','POST'])
def send_token():
    form=UserForm()
    if request.method=='POST':
        gmail_creds = get_gmail_credentials()
        email=request.form.get('email')
        user=User.query.filter_by(email=email).first()
        if user:
            alphabet= string.ascii_letters + string.digits
            # function call that uses the secrets module in python to randomly select one character from the alphabet string
            # it loops 9 times to get 9 characters, each loop it gets one character, the result is a string of length 9
            token = ''.join(secrets.choice(alphabet) for _ in range(9))
            company_email="johny.achkar01@gmail.com"
            email_content = "Dear User, this is your token to reset your password , please make sure to reset your password within 2 minutes"
            email_subject = "Password change"
            msg = Message(subject=email_subject, sender=company_email, recipients=[email])
            msg.body = f"{email_content}\nToken: {token}"

            expiry_time = datetime.utcnow() + timedelta(seconds=120)
            new_token = Token(
                token_content=token,
                email=email,
                expiry_time=expiry_time,
            )
            # to store token in Token table, you need to commit before sending the email
            db.session.add(new_token)
            db.session.commit()
            session['reset_email'] = email
            session['token']= token
            try:
                mail.init_app(app)
                mail.send(msg)
                return redirect(url_for('insert_token'))
            except Exception as e:
                flash(f"Error sending your token:{str(e)}")
                return redirect(url_for('home'))

            return redirect(url_for('insert_token'))

        else:
            flash('Email not in our database, Please sign up')
            return redirect(url_for('register'))
    return render_template('send_token.html',form=form)

class Token_Form(FlaskForm):
    token_content=StringField('Token Content',validators=[DataRequired()])
    submit=SubmitField('Submit')

@app.route('/insert_token',methods=['GET','POST'])
def insert_token():
    form=Token_Form()
    if request.method=='POST':
        token_con=request.form.get('token_content')
        token_valid = Token.query.filter_by(token_content=token_con).first()
        if token_valid:
            if token_valid.expiry_time>datetime.utcnow():
                return redirect(url_for('change_password'))
            else:
                flash('Token Expired')
                return redirect(url_for('send_token'))
        else:
            flash('Incorrect Token')
            return redirect(url_for('send_token'))
    return render_template('insert_token.html',form=form)

class Password_Form(FlaskForm):
    password1=StringField('Password',validators=[DataRequired()],render_kw={'autocomplete':'off'})
    password2=StringField('Confirm Password',validators=[DataRequired()],render_kw={'autocomplete':'off'})
    submit = SubmitField('Reset Password')
@app.route('/change_password',methods=['GET','POST'])
def change_password():
    form = Password_Form()
    reset_email=session.get('reset_email')
    if not reset_email:
        flash('Invalid request')
        return redirect(url_for('send_token'))
    user = User.query.filter_by(email=reset_email).first()
    if not user:
        flash('Email does not match')
        return redirect(url_for('register'))
    if request.method=='POST':
        password = request.form.get('password1')
        password2=request.form.get('password2')

        if password != password2:
            flash("Passwords are not similar, please password should be similar")
            return redirect(url_for('change_password'))
        else:
            # this is how we update or change the password
            user.password= generate_password_hash(password,
                                                         method='pbkdf2:sha256',
                                                         salt_length=8)
            db.session.commit()
            flash("password successfuly updated")
            return redirect(url_for('home'))
    return render_template('change_password.html',form=form)

# @app.route('/add_blog',methods=['GET','POST'])
# def add_blog():


@app.route('/estimation',methods=['GET','POST'])
def estimation():
    response = requests.get("https://type.fit/api/quotes")
    data = response.json()
    quotes_except_last = data[:-1]
    rand=random.randint(0,len(quotes_except_last)-1)
    text = quotes_except_last[rand]['text']
    author = quotes_except_last[rand]['author'].split(',')[0]
    email=session.get('user_email1')
    user=User.query.filter_by(email=email).first()
    if request.method=='GET':
        if user:
            image=user.image
    return render_template('estimation.html',image=image,text=text,author=author)


class Report_Form(FlaskForm):
    patient_name=StringField('Patient Name',validators=[DataRequired()],render_kw={'autocomplete':'off'})
    patient_age=StringField('Patient Age',validators=[DataRequired()],render_kw={'autocomplete':'off'})
    chief_complaint=StringField('Chief Complaint',validators=[DataRequired()],render_kw={'autocomplete':'off'})
    medication=StringField('Medication',validators=[DataRequired()],render_kw={'autocomplete':'off'})
    dosage = StringField('Dosage',validators=[DataRequired()],render_kw={'autocomplete':'off'})
    others=StringField('Others',validators=[DataRequired()],render_kw={'autocomplete':'off'})
    generate = SubmitField('Generate')
@app.route('/ask_ai',methods=['GET','POST'])
def ask_ai():
    form = Report_Form()
    if request.method=='POST':
        patient_name=request.form.get('patient_name')
        patient_age=request.form.get('patient_age')
        chief_complaint=request.form.get('chief_complaint')
        standard_question="Please write a medical report for patient:"
        final_question= standard_question + patient_name + f" who is{patient_age}" + f"and is complaining from{chief_complaint}"

        response=openai.ChatCompletion.create(
        model="gpt-3.5-turbo-0301",messages=[{"role":"user","content":final_question}]
        )
        answer=response['choices'][0]['message']['content']
        session['final_q']=final_question
        session['ans']=answer
        session['patient_name']=patient_name
        session['patient_age']=patient_age
        return redirect(url_for('result'))
    return render_template('ask_ai.html',form=form)


class BlogForm(FlaskForm):
    title=StringField('Add A Catchy Title',validators=[DataRequired()],render_kw={'autocomplete':'off'})
    body = CKEditorField('Create Content',validators=[DataRequired()],render_kw={'autocomplete':'off'})
    publish = SubmitField('Publish')

@app.route('/add_blog',methods=['GET','POST'])
def add_blog():
    form=BlogForm()
    user_email = session.get('user_email1')
    name=current_user.name if current_user.is_authenticated else None
    if request.method=='POST':
        user = User.query.filter_by(email=user_email).first()
        if not user:
            flash('Email not authenticated,you cannot write a blog')
            return redirect(url_for('home'))
        else:

            new_blog=Blog(
                title=request.form.get('title'),
                body=request.form.get('text'),
                author=user_email,
                date=datetime.utcnow(),
                image=request.form.get('image')
            )
            db.session.add(new_blog)
            db.session.commit()
            return redirect(url_for('see_blog'))
    return render_template('add_blog.html',form=form,name=name)


@app.route('/result')
def result():
    question=session.get('final_q')
    answer=session.get('ans')
    patient_name=session.get('patient_name')
    patient_age=session.get('patient_age')
    current_date=datetime.now().strftime("%Y-%m-%d")
    return render_template('result.html',question=question,answer=answer,name=patient_name,age=patient_age,current_date=current_date)

@app.route('/save_report',methods=['POST','GET'])
def save_report():
    report_content=request.form.get('report')
    return render_template('save_report.html',report_content=report_content)

if __name__=="__main__":
    with app.app_context():
        db.create_all()
        update_user_image()
    app.run(debug=True)