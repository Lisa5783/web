import os
from flask import Flask, flash, redirect, render_template, request, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, current_user, login_user, logout_user, login_required
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import re
from flask_wtf.csrf import CSRFProtect


app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-unique-secret-key'
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///lab4.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
csrf = CSRFProtect(app)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False, unique=True)
    description = db.Column(db.String(200), nullable=True)

    def __repr__(self):
        return f'<Role {self.name}>'



class UserInfo(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(50),nullable=False, unique=True)
    password_hash = db.Column(db.String(100), nullable=False)
    lastname = db.Column(db.String(50), nullable=True)
    firstname = db.Column(db.String(50), nullable=False)
    middlename = db.Column(db.String(50), primary_key=False)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'), nullable=True)
    date_registration = db.Column(db.DateTime, default=datetime.utcnow)

    role = db.relationship('Role', backref=db.backref('users', lazy=True))

    def __repr__(self):
        return f'<UserInfo {self.login}>'

@app.route('/')
def index():
    users = UserInfo.query.order_by(UserInfo.date_registration).all()
    return render_template('index.html', users = users)

@app.route('/<int:id>')
def index_show(id):
    user = UserInfo.query.get(id)
    return render_template('index_show.html', user = user)

@app.route('/<int:id>/delete', methods=['POST'])
def index_delete(id):
    user = UserInfo.query.get_or_404(id)
    try:
        db.session.delete(user)
        db.session.commit()
        flash('Пользователь успешно удалён.', 'success')
    except Exception as e:
        flash(f'Ошибка при удалении пользователя: {e}', 'danger')
    return redirect(url_for('index'))


@app.route('/<int:id>/update', methods=['POST', 'GET'])
def index_update(id):
    user = UserInfo.query.get_or_404(id)
    roles = Role.query.all()  

    if request.method == "POST":
        user.login = request.form['login']
        password = request.form['password']
        if password:  
            user.password_hash = generate_password_hash(password)
        user.lastname = request.form['lastname'] or None
        user.firstname = request.form['firstname']
        user.middlename = request.form['middlename'] or None

        role_name = request.form['role'].strip()
        if role_name:
            role_obj = Role.query.filter_by(name=role_name).first()
            if not role_obj:
                flash("Указанная роль не найдена. Обратитесь к администратору.", "danger")
                return "Указанная роль не найдена. Обратитесь к администратору."
            user.role_id = role_obj.id
        else:
            user.role_id = None

        try:
            db.session.commit()
            flash("Пользователь успешно обновлён.", "success")
            return redirect('/')
        except Exception as e:
            db.session.rollback()
            flash(f"При обновлении произошла ошибка: {e}", "danger")
            return redirect(request.url)
    else:
        return render_template('index_update.html', user=user, roles=roles)


@app.route('/CreateRole', methods = ['POST', 'GET'])
def CreateRole():
    if request.method == "POST":
        name = request.form['name']
        description = request.form['description']
        
        role = Role(
            name = name,
            description = description
        )

        try:
            db.session.add(role)
            db.session.commit()
            return redirect('/')
        except:
            return "При создании произошла ошибка"
    else:
        return render_template('CreateRole.html')


@app.route('/registration', methods=['POST', 'GET'])
def registration():
    roles = Role.query.all()
    if request.method == "POST":
        login = request.form['login'].strip()
        password = request.form['password']
        firstname = request.form['firstname'].strip()
        lastname = request.form.get('lastname', '').strip() or None
        middlename = request.form.get('middlename', '').strip() or None
        role_id = request.form.get('role')

        errors = {}
        form_data = request.form.to_dict()

        # Валидация логина
        if len(login) < 5:
            errors['login'] = 'Логин должен содержать не менее 5 символов'
        elif not re.match(r'^[A-Za-z0-9]+$', login):
            errors['login'] = 'Допустимы только латинские буквы и цифры'
        else:
            existing_user = UserInfo.query.filter_by(login=login).first()
            if existing_user:
                errors['login'] = 'Логин уже занят'

        # Валидация пароля
        if len(password) < 8 or len(password) > 128:
            errors['password'] = 'Длина пароля должна быть 8-128 символов'
        elif ' ' in password:
            errors['password'] = 'Пароль не должен содержать пробелов'
        elif not re.search(r'[A-ZА-Я]', password):
            errors['password'] = 'Добавьте хотя бы одну заглавную букву'
        elif not re.search(r'[a-zа-я]', password):
            errors['password'] = 'Добавьте хотя бы одну строчную букву'
        elif not re.search(r'\d', password):
            errors['password'] = 'Добавьте хотя бы одну цифру'
        elif not re.fullmatch(r'[A-Za-zА-Яа-я\d~!?@#$%^&*_\-+()\[\]{}><\/\\|"\',.:;]+', password):
            errors['password'] = 'Недопустимые символы'

        # Валидация имени
        if not firstname:
            errors['firstname'] = 'Поле обязательно для заполнения'

        if errors:
            return render_template('registration.html', 
                                 roles=roles, 
                                 errors=errors,
                                 form_data=form_data)

        # Создание пользователя
        try:
            password_hash = generate_password_hash(password)
            user = UserInfo(
                login=login,
                password_hash=password_hash,
                firstname=firstname,
                lastname=lastname,
                middlename=middlename,
                role_id=int(role_id) if role_id else None
            )
            db.session.add(user)
            db.session.commit()
            return redirect('/')
        except Exception as e:
            db.session.rollback()
            errors['db'] = f'Ошибка базы данных: {str(e)}'
            return render_template('registration.html',
                                 roles=roles,
                                 errors=errors,
                                 form_data=form_data)

    return render_template('registration.html', roles=roles, errors={}, form_data={})


@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        old_password = request.form['old_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        errors = []

        # Проверка старого пароля
        if not check_password_hash(current_user.password_hash, old_password):
            errors.append('Неверный текущий пароль')
        
        # Проверка совпадения новых паролей
        if new_password != confirm_password:
            errors.append('Новые пароли не совпадают')
        
        # Валидация нового пароля (используем ту же логику, что и при регистрации)
        if len(new_password) < 8 or len(new_password) > 128:
            errors.append('Длина пароля должна быть 8-128 символов')
        elif ' ' in new_password:
            errors.append('Пароль не должен содержать пробелов')
        elif not re.search(r'[A-ZА-Я]', new_password):
            errors.append('Добавьте хотя бы одну заглавную букву')
        elif not re.search(r'[a-zа-я]', new_password):
            errors.append('Добавьте хотя бы одну строчную букву')
        elif not re.search(r'\d', new_password):
            errors.append('Добавьте хотя бы одну цифру')
        elif not re.fullmatch(r'[A-Za-zА-Яа-я\d~!?@#$%^&*_\-+()\[\]{}><\/\\|"\',.:;]+', new_password):
            errors.append('Недопустимые символы')

        if errors:
            for error in errors:
                flash(error, 'danger')
            return redirect(url_for('change_password'))
        
        # Обновление пароля
        try:
            current_user.password_hash = generate_password_hash(new_password)
            db.session.commit()
            flash('Пароль успешно изменён!', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            flash(f'Ошибка при изменении пароля: {str(e)}', 'danger')
    
    return render_template('change_password.html')


@login_manager.user_loader
def load_user(user_id):
    return UserInfo.query.get(int(user_id))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login = request.form['login']
        password = request.form['password']
        remember = 'remember' in request.form

        user = UserInfo.query.filter_by(login=login).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user, remember=remember)
            flash('Вы успешно вошли в систему!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Неверный логин или пароль.', 'danger')
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Вы вышли из системы.', 'info')
    return redirect(url_for('login'))


# @app.route('/secret')
# @login_required
# def secret():
#     return render_template('secret.html')

if __name__=='__main__':
    app.run(debug=True)