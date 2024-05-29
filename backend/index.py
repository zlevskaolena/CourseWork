from backend.config import User, app, db, bcrypt, mail, Card, CardResult
from flask import render_template, redirect, url_for, request, flash, session, jsonify
from flask_login import login_user, current_user, logout_user
from backend.forms import LoginForm, RegistrationForm, RequestResetForm, ResetPasswordForm
from flask_mail import Message
import random


@app.route('/')
@app.route('/home')
def home():
    return render_template('home.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    register_form = RegistrationForm()
    if register_form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(register_form.password.data).decode('utf-8')
        user = User(username=register_form.username.data, email=register_form.email.data, password=hashed_password)
        db.session.add(user)
        try:
            db.session.commit()
            login_user(user)
            return redirect(url_for('home'))
        except Exception as e:
            db.session.rollback()
            flash("Виникла помилка при реєстрації користувача. Можливо, електронна пошта вже використовується.", 'danger')
    return render_template('register.html', form=register_form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        user = User.query.filter_by(email=login_form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, login_form.password.data):
            login_user(user, remember=login_form.remember.data)
            return redirect(url_for('home'))
        else:
            flash("Не вдалося увійти. Будь ласка, перевірте електронну пошту та пароль.", 'danger')
    return render_template('login.html', form=login_form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


def send_reset_email(user):
    try:
        token = user.get_reset_token()
        msg = Message('LOCUS. Оновлення паролю.',
                      sender='zalevskaalena25@gmail.com',
                      recipients=[user.email])
        msg.body = f'''Для того, щоб оновити пароль, перейдіть за посиланням:
        {url_for('reset_token', token=token, _external=True)}
        Якщо це НЕ Ви намагаєтесь оновити пароль - проігноруйте це повідомлення.
        '''
        mail.send(msg)
        flash('На вашу електронну пошту відправлено лист з інструкціями для скидання паролю.', 'info')
        return redirect(url_for('login'))
    except Exception as e:
        flash('Під час відправлення листа сталася помилка. Будь ласка, спробуйте ще раз пізніше.', 'danger')
        return redirect(url_for('reset_request'))


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            send_reset_email(user)
        else:
            flash('Користувача з цією електронною адресою не існує.', 'danger')
    return render_template('reset_request.html', title='Скидання паролю', form=form)


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    user = User.verify_reset_token(token)
    if not user:
        flash('Недійсний або прострочений токен', 'warning')
        return redirect(url_for('reset_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password = hashed_password
        db.session.commit()

        flash('Ваш пароль було оновлено! Тепер ви можете увійти.', 'success')
        return redirect(url_for('login'))
    return render_template('reset_token.html', title='Скидання паролю', form=form)


@app.route('/home/cards', methods=['GET', 'POST'])
def play_game():
    if 'random_cards' not in session:
        session['random_cards'] = get_random_cards()
    if 'current_index' not in session:
        session['current_index'] = 0

    if request.method == 'POST' and request.headers.get('Content-Type') == 'application/json':
        user_answer = request.json.get('user_answer')

        current_index = session['current_index']
        if current_index >= len(session['random_cards']):
            return jsonify({'message': 'No more cards'}), 200

        current_card = session['random_cards'][current_index]
        correct_answer = current_card['correct_answer']

        if user_answer == correct_answer:
            session['score'] = session.get('score', 0) + 1
            print("ПЕРЕВІРКА: Результат в сесії:", session['score'])

        session['current_index'] += 1
        if session['current_index'] >= len(session['random_cards']):
            score = session.get('score', 0)
            session['final_score'] = score
            print("ПЕРЕВІРКА: Кінцевий результат:", score)
            if current_user.is_authenticated:
                result = CardResult(user_id=current_user.id, score=score)
                db.session.add(result)
                db.session.commit()
            return jsonify({'message': 'Game Over', 'score': score}), 200

        return jsonify({'message': 'Next card'}), 200

    elif request.method == 'GET' and request.headers.get('Content-Type') == 'application/json':
        if session['current_index'] >= len(session['random_cards']):
            return jsonify({'message': 'No more cards'}), 200

        current_index = session['current_index']
        current_card = session['random_cards'][current_index]
        return jsonify(current_card)
    else:
        return render_template('games/cards_game.html')


@app.route('/home/cards/cards_over', methods=['GET', 'POST'])
def cards_over():
    score = session.pop('final_score', None)
    show_button = current_user.is_authenticated
    if score is not None:
        if request.method == 'POST' and current_user.is_authenticated:
            result = CardResult(user_id=current_user.id, score=score)
            db.session.add(result)
            db.session.commit()
            flash('Результат збережено!', 'success')
        return render_template('games/cards_over.html', score=score, show_button=show_button)
    else:
        score = request.args.get('score')
        return render_template('games/cards_over.html', score=score, show_button=show_button)


def get_random_cards():
    cards = Card.query.all()
    random.shuffle(cards)
    return [card.to_dict() for card in cards]


@app.route('/user_results', methods=['GET'])
def view_results():
    if not current_user.is_authenticated:
        flash('Будь ласка, увійдіть, щоб переглянути свої результати.', 'info')
        return redirect(url_for('login'))

    results = CardResult.query.filter_by(user_id=current_user.id).order_by(CardResult.timestamp.desc()).all()
    return render_template('games/results.html', results=results)
