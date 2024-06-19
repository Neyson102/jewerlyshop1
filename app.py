from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///shop.db'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.secret_key = 'supersecretkey'
db = SQLAlchemy(app)

# Models
class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)

class Good(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    price = db.Column(db.Float, nullable=False)
    description = db.Column(db.Text, nullable=True)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    category = db.relationship('Category', backref=db.backref('goods', lazy=True))
    image = db.Column(db.String(120), nullable=True)

class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    good_id = db.Column(db.Integer, db.ForeignKey('good.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.Text, nullable=False)
    username = db.Column(db.String(80), nullable=False)
    good = db.relationship('Good', backref=db.backref('reviews', lazy=True))

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False, unique=True)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(10), nullable=False, default='user')  # 'user' or 'manager'

class Cart(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    items = db.relationship('CartItem', backref='cart', lazy=True)

class CartItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cart_id = db.Column(db.Integer, db.ForeignKey('cart.id'), nullable=False)
    good_id = db.Column(db.Integer, db.ForeignKey('good.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=1)
    good = db.relationship('Good', backref='cart_items')

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    first_name = db.Column(db.String(80), nullable=False)
    last_name = db.Column(db.String(80), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    address = db.Column(db.Text, nullable=False)
    order_items = db.relationship('OrderItem', backref='order', lazy=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), nullable=False, default='new')
    payment_method = db.Column(db.String(20), nullable=False)
    total_price = db.Column(db.Float, nullable=False)

class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    good_id = db.Column(db.Integer, db.ForeignKey('good.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    good = db.relationship('Good')

# Create the database
with app.app_context():
    db.create_all()

@app.route('/', methods=['GET', 'POST'])
def catalog():
    category_id = request.args.get('category_id')
    min_price = request.args.get('min_price')
    max_price = request.args.get('max_price')

    categories = Category.query.all()
    goods_query = Good.query

    if category_id:
        goods_query = goods_query.filter_by(category_id=category_id)
    if min_price:
        goods_query = goods_query.filter(Good.price >= float(min_price))
    if max_price:
        goods_query = goods_query.filter(Good.price <= float(max_price))

    goods = goods_query.all()

    return render_template('catalog.html', goods=goods, categories=categories, category_id=category_id, min_price=min_price, max_price=max_price)

@app.route('/good/<int:good_id>', methods=['GET', 'POST'])
def good_detail(good_id):
    good = Good.query.get_or_404(good_id)
    if request.method == 'POST':
        if 'username' not in session:
            flash('Спочатку увійдіть до системи!')
            return redirect(url_for('login'))

        rating = int(request.form['rating'])
        comment = request.form['comment']
        username = session.get('username')
        if not username:
            flash('Щоб залишити відгук авторизуйтесь будь ласка до аккаунту.')
            return redirect(url_for('login'))

        new_review = Review(good_id=good_id, rating=rating, comment=comment, username=username)
        db.session.add(new_review)
        db.session.commit()
        flash('Відгук додано успішно!')
        return redirect(url_for('good_detail', good_id=good_id))
    reviews = Review.query.filter_by(good_id=good_id).all()
    return render_template('good_detail.html', good=good, reviews=reviews)


@app.route('/manage')
def manage():
    if 'username' not in session or session['role'] != 'manager':
        flash('Недостатньо прав для доступу до управління!')
        return redirect(url_for('catalog'))
    goods = Good.query.all()
    categories = Category.query.all()
    users = User.query.all()
    return render_template('manage.html', goods=goods, categories=categories, users=users)


@app.route('/add_good', methods=['POST'])
def add_good():
    if 'username' not in session or session['role'] != 'manager':
        flash('Недостатньо прав для виконання цієї дії!')
        return redirect(url_for('catalog'))
    name = request.form['name']
    price = request.form['price']
    description = request.form['description']
    category_id = request.form['category_id']
    image = request.files['image']
    filename = secure_filename(image.filename)
    image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    new_good = Good(name=name, price=price, description=description, category_id=category_id, image=filename)
    db.session.add(new_good)
    db.session.commit()
    return redirect(url_for('manage'))

@app.route('/add_category', methods=['POST'])
def add_category():
    if 'username' not in session or session['role'] != 'manager':
        flash('Недостатньо прав для виконання цієї дії!')
        return redirect(url_for('catalog'))
    name = request.form['name']
    new_category = Category(name=name)
    db.session.add(new_category)
    db.session.commit()
    return redirect(url_for('manage'))

@app.route('/delete_good/<int:good_id>', methods=['POST'])
def delete_good(good_id):
    if 'username' not in session or session['role'] != 'manager':
        flash('Недостатньо прав для виконання цієї дії!')
        return redirect(url_for('catalog'))
    good = Good.query.get_or_404(good_id)
    db.session.delete(good)
    db.session.commit()
    flash('Товар видалено успішно!')
    return redirect(url_for('manage'))

@app.route('/delete_category/<int:category_id>', methods=['POST'])
def delete_category(category_id):
    if 'username' not in session or session['role'] != 'manager':
        flash('Недостатньо прав для виконання цієї дії!')
        return redirect(url_for('catalog'))
    category = Category.query.get_or_404(category_id)
    db.session.delete(category)
    db.session.commit()
    flash('Категорія видалена успішно!')
    return redirect(url_for('manage'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['username'] = user.username
            session['role'] = user.role
            flash('Вхід успішний!')
            return redirect(url_for('catalog'))
        flash('Неправильний логін або пароль!')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user:
            flash('Користувач з таким логіном вже існує!')
        else:
            hashed_password = generate_password_hash(password)
            new_user = User(username=username, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Реєстрація успішна!')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/change_role', methods=['POST'])
def change_role():
    if 'username' not in session or session['role'] != 'manager':
        flash('Недостатньо прав для виконання цієї дії!')
        return redirect(url_for('catalog'))
    user_id = request.form['user_id']
    new_role = request.form['role']
    user = User.query.get(user_id)
    if user:
        user.role = new_role
        db.session.commit()
        flash('Роль користувача оновлено успішно!')
    else:
        flash('Користувача не знайдено!')
    return redirect(url_for('manage'))


@app.route('/add_to_cart/<int:good_id>', methods=['POST'])
def add_to_cart(good_id):
    if 'username' not in session:
        flash('Спочатку увійдіть до системи!')
        return redirect(url_for('login'))

    # Отримання або створення корзини користувача
    user = User.query.filter_by(username=session['username']).first()
    if not user:
        flash('Користувача не знайдено!')
        return redirect(url_for('catalog'))

    cart = Cart.query.filter_by(user_id=user.id).first()
    if not cart:
        cart = Cart(user_id=user.id)
        db.session.add(cart)
        db.session.commit()

    # Додавання товару до корзини
    cart_item = CartItem.query.filter_by(cart_id=cart.id, good_id=good_id).first()
    if cart_item:
        cart_item.quantity += 1
    else:
        cart_item = CartItem(cart_id=cart.id, good_id=good_id)
        db.session.add(cart_item)

    db.session.commit()
    flash('Товар додано до корзини!')
    return redirect(url_for('good_detail', good_id=good_id))


@app.route('/cart')
def cart():
    if 'username' not in session:
        flash('Спочатку увійдіть до системи!')
        return redirect(url_for('login'))

    user = User.query.filter_by(username=session['username']).first()
    if not user:
        flash('Користувача не знайдено!')
        return redirect(url_for('catalog'))

    cart = Cart.query.filter_by(user_id=user.id).first()
    if not cart:
        flash('Корзина порожня!')
        return render_template('cart.html', cart_items=[], total_price=0)

    cart_items = CartItem.query.filter_by(cart_id=cart.id).all()
    total_price = sum(item.good.price * item.quantity for item in cart_items)
    return render_template('cart.html', cart_items=cart_items, total_price=total_price)


@app.route('/remove_from_cart/<int:item_id>', methods=['POST'])
def remove_from_cart(item_id):
    if 'username' not in session:
        flash('Спочатку увійдіть до системи!')
        return redirect(url_for('login'))

    cart_item = CartItem.query.get_or_404(item_id)
    db.session.delete(cart_item)
    db.session.commit()
    flash('Товар видалено з корзини!')
    return redirect(url_for('cart'))


@app.route('/checkout', methods=['GET', 'POST'])
def checkout():
    if 'username' not in session:
        flash('Спочатку увійдіть до системи!')
        return redirect(url_for('login'))

    user = User.query.filter_by(username=session['username']).first()
    if not user:
        flash('Користувача не знайдено!')
        return redirect(url_for('catalog'))

    cart = Cart.query.filter_by(user_id=user.id).first()
    if not cart or not cart.items:
        flash('Корзина порожня!')
        return redirect(url_for('catalog'))

    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        phone = request.form['phone']
        address = request.form['address']
        payment_method = request.form['payment_method']

        total_price = sum(item.good.price * item.quantity for item in cart.items)

        new_order = Order(
            user_id=user.id,
            first_name=first_name,
            last_name=last_name,
            phone=phone,
            address=address,
            payment_method=payment_method,
            total_price=total_price
        )
        db.session.add(new_order)
        db.session.commit()

        for item in cart.items:
            order_item = OrderItem(
                order_id=new_order.id,
                good_id=item.good_id,
                quantity=item.quantity
            )
            db.session.add(order_item)
            db.session.delete(item)

        db.session.delete(cart)
        db.session.commit()

        return redirect(url_for('thank_you'))

    total_price = sum(item.good.price * item.quantity for item in cart.items)
    return render_template('checkout.html', cart=cart, total_price=total_price)


@app.route('/manage_orders', methods=['GET', 'POST'])
def manage_orders():
    if 'username' not in session or session['role'] != 'manager':
        flash('Недостатньо прав для доступу до управління!')
        return redirect(url_for('catalog'))

    status_filter = request.args.get('status', 'all')
    if status_filter == 'all':
        orders = Order.query.all()
    else:
        orders = Order.query.filter_by(status=status_filter).all()

    return render_template('manage_orders.html', orders=orders, status_filter=status_filter)

@app.route('/update_order_status/<int:order_id>', methods=['POST'])
def update_order_status(order_id):
    if 'username' not in session or session['role'] != 'manager':
        flash('Недостатньо прав для виконання цієї дії!')
        return redirect(url_for('catalog'))
    order = Order.query.get_or_404(order_id)
    new_status = request.form['status']
    order.status = new_status
    db.session.commit()
    flash('Статус замовлення оновлено успішно!')
    return redirect(url_for('manage_orders'))

@app.route('/thank_you')
def thank_you():
    return render_template('thank_you.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('role', None)
    flash('Ви вийшли з системи!')
    return redirect(url_for('catalog'))

if __name__ == '__main__':
    app.run(debug=True)
