from .config import app, db, bcrypt, User
from flask import Flask, render_template, redirect, url_for, request
from flask_login import login_user, current_user, logout_user, login_required
import forms
from backend.forms import LoginForm, RegistrationForm


@app.route('/', methods = ['GET','POST'])
@app.route('/home', methods = ['GET','POST'])
def home():
    if RegistrationForm().validate_on_submit():
        register_form = RegistrationForm()
        hashed_password =   bcrypt.generate_password_hash(register_form.password.data).decode('utf-8')
        user = User(username = register_form.username.data, email = register_form.email.data, password = hashed_password)
        db.session.add(user)
        db.session.commit()

        user = User.query.filter_by(
            email=RegistrationForm().email.data).first()

        if user and bcrypt.check_password_hash(
                user.password, RegistrationForm().password.data):
            login_user(user)

        return redirect(url_for('hello_world'))
    return render_template('Home.html', login_form=LoginForm(), register_form=RegistrationForm())