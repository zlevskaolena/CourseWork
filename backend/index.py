from backend.config import User, app, db, bcrypt
from flask import render_template, redirect, url_for, request
from flask_login import login_user, logout_user
from backend.forms import LoginForm, RegistrationForm


@app.route('/', methods=['GET', 'POST'])
@app.route('/home', methods=['GET', 'POST'])
def register_and_login():
    register_form = RegistrationForm()
    if register_form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(register_form.password.data).decode('utf-8')

        user = User(username=register_form.username.data, email=register_form.email.data, password=hashed_password)

        db.session.add(user)
        db.session.commit()

        user = User.query.filter_by(email=register_form.email.data).first()

        if user and bcrypt.check_password_hash(user.password, register_form.password.data):
            login_user(user)

        return redirect(url_for('register_and_login'))

    if (request.method == "POST") & (request.form.get('post_header') == 'log out'):

        logout_user()

        return redirect(url_for('register_and_login'))

    if LoginForm().validate_on_submit():

        login_form = LoginForm()
        user = User.query.filter_by(email=
                                    login_form.email.data).first()

        if user and bcrypt.check_password_hash(user.password,
                                               login_form.password.data):
            login_user(user, remember=login_form.remember.data)

        return redirect(url_for('register_and_login'))

    return render_template('Home.html', login_form=LoginForm(), register_form=register_form)

