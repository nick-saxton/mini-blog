from flask import Flask, render_template, request, redirect, session, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_session import Session
from passlib.hash import sha256_crypt

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_TYPE'] = 'filesystem'
db = SQLAlchemy(app)
Session(app)

from models.user import User

@app.route('/')
def index():
    user = None
    if session.get('current_user') is not None:
        user = session['current_user']
    return render_template('index.html', user=user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()

        if user is not None:
            if sha256_crypt.verify(request.form.get('password'), user.password):
                session['current_user'] = user
                return redirect(url_for('index'))

        return redirect(url_for('failure'))
    else:
        return render_template('login.html')

@app.route('/logout')
def logout():
    if session.get('current_user') is not None:
        session['current_user'] = None
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    errors = []
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')

        if request.form.get('password') != request.form.get('confirm'):
            errors.append('Passwords do not match')
            return redirect(url_for('index'))

        new_user = User(username=username, email=email, password=sha256_crypt.encrypt(request.form.get('password')))

        db.session.add(new_user)
        db.session.commit()

        if len(errors) == 0:
            return redirect(url_for('index'))

    return render_template('register.html', errors=errors)

@app.route('/failure')
def failure():
    return render_template('failure.html')
