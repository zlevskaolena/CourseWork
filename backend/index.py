from backend.config import User, app, db, bcrypt, mail, Card
from flask import render_template, redirect, url_for, request, flash, session, jsonify
from flask_login import login_user, current_user, logout_user
from backend.forms import LoginForm, RegistrationForm, RequestResetForm, ResetPasswordForm
from flask_mail import Message
import random
from sqlalchemy import func


@app.route('/', methods=['GET', 'POST'])
@app.route('/home', methods=['GET', 'POST'])
def register_and_login():
    register_form = RegistrationForm()
    login_form = LoginForm()

    if register_form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(register_form.password.data).decode('utf-8')
        user = User(username=register_form.username.data, email=register_form.email.data, password=hashed_password)
        db.session.add(user)
        try:
            db.session.commit()
            login_user(user)
            return redirect(url_for('register_and_login'))

        except Exception as e:
            db.session.rollback()
            flash("Виникла помилка при реєстрації користувача. Можливо, електронна пошта вже використовується.", 'danger')

    if login_form.validate_on_submit():
        user = User.query.filter_by(email=login_form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, login_form.password.data):
            login_user(user, remember=login_form.remember.data)
            return redirect(url_for('register_and_login'))
        else:
            flash("Не вдалося увійти. Будь ласка, перевірте електронну пошту та пароль.", 'danger')

    if request.method == "POST" and request.form.get('post_header') == 'log out':
        logout_user()
        return redirect(url_for('register_and_login'))

    return render_template('Home.html', login_form=login_form, register_form=register_form)


def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Password Reset Request',
                  sender='zalevskaalena25@gmail.com',
                  recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link:
{url_for('reset_token', token=token, _external=True)}

If you did not make this request then simply ignore this email and no changes will be made.
'''
    mail.send(msg)


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            send_reset_email(user)
        flash('An email has been sent with instructions to reset your password.', 'info')
        return redirect(url_for('login'))
    return render_template('reset_request.html', title='Reset Password', form=form, register_form=RegistrationForm(), login_form=LoginForm())


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    user = User.verify_reset_token(token)
    if not user:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('reset_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password = hashed_password
        db.session.commit()
        flash('Your password has been updated! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('reset_token.html', title='Reset Password', form=form, register_form=RegistrationForm())


@app.route('/cards')
def play_game():
    if 'random_cards' not in session:
        session['random_cards'] = get_random_cards()
    if 'current_index' not in session:
        session['current_index'] = 0

    current_index = session['current_index']
    random_cards = session['random_cards']

    if isinstance(random_cards, dict) and random_cards.get('response'):
        random_cards = random_cards['response']

    if current_index < len(random_cards):
        current_card = random_cards[current_index]
        session['current_index'] += 1
    else:
        session.pop('random_cards', None)
        session.pop('current_index', None)
        return jsonify({'message': 'No more cards'}), 200

    return jsonify(current_card), 200


@app.route('/game_over')
def game_over():
    score = session.get('score', 0)
    session.pop('random_cards', None)
    session.pop('current_card_index', None)
    session.pop('score', None)
    return render_template('games/cards_over.html', score=score)


def get_random_cards():
    cards = Card.query.all()
    random.shuffle(cards)
    return [card.to_dict() for card in cards]
