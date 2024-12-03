import os
import random
import smtplib
from flask import Flask, url_for, redirect, request, flash, session
from flask.templating import render_template
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, login_required, current_user, logout_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, EmailField, TextAreaField
from wtforms.validators import InputRequired, Length, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from datetime import datetime
from werkzeug.utils import secure_filename
import stripe

UPLOAD_FOLDER = 'static/images/'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
SECRET_KEY = os.urandom(32)
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587
SMTP_USERNAME = '20e51a6602@hitam.org'
SMTP_PASSWORD = 'jithenderadupa'

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
bcrypt = Bcrypt(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = SECRET_KEY

stripe.api_key = 'sk_test_51QS0kOLm644OBICnlQhEun0AEzhJvNAbrmsCpaCyMfdUFYDRdKiBsTdoS1NniMdNaQCNMGZfQmAog7iglMNojedO00f5tTGmTa'
app.config['STRIPE_PUBLIC_KEY'] = 'pk_test_51QS0kOLm644OBICn0l9QeOiHAnjRi7RzqEIf11RWBx2eVGiHHyl2sSMoF07R1WKEVh4ItBkiE6j3FC0fEjuS6Ht1001H5Woryn'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def send_otp(email, otp):
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            subject = 'Your OTP Code'
            body = f'Your OTP code is {otp}'
            msg = f'Subject: {subject}\n\n{body}'
            server.sendmail(SMTP_USERNAME, email, msg)
    except Exception as e:
        print(f'Failed to send email: {e}')

class PaymentForm(FlaskForm):
    address = TextAreaField(validators=[InputRequired(), Length(min=10)], render_kw={"placeholder": "Address"})
    card_name = StringField(validators=[InputRequired()], render_kw={"placeholder": "Name on Card"})
    submit = SubmitField("Proceed to Payment")

class ProductsInfo(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    author = db.Column(db.String(200), nullable=False)
    description = db.Column(db.String(200), nullable=False)
    price = db.Column(db.Integer)
    link = db.Column(db.String(200), nullable=False)
    dateaddes = db.Column(db.DateTime, default=datetime.utcnow)
    imageName = db.Column(db.Text, nullable=True)

    def __repr__(self):
        return f'<Task : {self.id}>'

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('products_info.id'), nullable=False)
    address = db.Column(db.String(200), nullable=False)
    order_date = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Order {self.id}>'

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(20), nullable=False, unique=True)
    mobile = db.Column(db.String(20), nullable=False, unique=True)
    is_verified = db.Column(db.Boolean, default=False)

class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    email = EmailField(validators=[InputRequired(), Length(min=4, max=40)], render_kw={"placeholder": "Email"})
    mobile = StringField(validators=[InputRequired(), Length(min=10, max=15)], render_kw={"placeholder": "Mobile no."})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    password2 = PasswordField(validators=[InputRequired()], render_kw={"placeholder": "Confirm Password"})
    submit = SubmitField("Register")

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError('User with this username already exists.')

    def validate_email(self, email):
        existing_user_email = User.query.filter_by(email=email.data).first()
        if existing_user_email:
            raise ValidationError('User with this email already exists.')

    def validate_mobile(self, mobile):
        existing_user_mobile = User.query.filter_by(mobile=mobile.data).first()
        if existing_user_mobile:
            raise ValidationError('User with this mobile number already exists.')

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Login")

class OtpForm(FlaskForm):
    otp = StringField(validators=[InputRequired(), Length(min=4, max=6)], render_kw={"placeholder": "Enter OTP"})
    submit = SubmitField("Verify")

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/search')
def search():
    query = request.args.get('query', '')
    if query:
        results = ProductsInfo.query.filter(ProductsInfo.name.contains(query)).all()
    else:
        results = []
    return render_template('search_results.html', results=results, query=query)
@app.route('/product/<int:productid>')
def product_detail(productid):
    product = ProductsInfo.query.get_or_404(productid)
    return render_template('product_detail.html', product=product)

@app.route('/payment/<int:productid>', methods=['GET', 'POST'])
@login_required
def payment(productid):
    if 'username' in session and session['username'] != 'None':
        form = PaymentForm()
        product = ProductsInfo.query.get_or_404(productid)

        if form.validate_on_submit():
            try:
                stripe_session = stripe.checkout.Session.create(
                    payment_method_types=['card'],
                    line_items=[{
                        'price_data': {
                            'currency': 'usd',
                            'product_data': {
                                'name': product.name,
                            },
                            'unit_amount': product.price * 100,
                        },
                        'quantity': 1,
                    }],
                    mode='payment',
                    success_url=url_for('payment_success', productid=productid, address=form.address.data, _external=True),
                    cancel_url=url_for('payment_cancel', _external=True),
                )
                return redirect(stripe_session.url, code=303)
            except stripe.error.StripeError as e:
                flash(f'Error in payment processing: {str(e)}', 'danger')
                return redirect(url_for('payment', productid=productid))

        return render_template('payment.html', form=form, product=product, stripe_public_key=app.config['STRIPE_PUBLIC_KEY'])
    else:
        flash('To buy, you need to be signed up!', 'danger')
        return redirect('/login')

@app.route('/payment/success')
def payment_success():
    productid = request.args.get('productid')
    address = request.args.get('address')

    try:
        new_order = Order(user_id=current_user.id, product_id=productid, address=address)
        db.session.add(new_order)
        db.session.commit()
        flash('Payment was successful!', 'success')
        return redirect('/')
    except Exception as e:
        flash(f'Error recording order: {str(e)}', 'danger')
        return redirect('/')

@app.route('/payment/cancel')
def payment_cancel():
    flash('Payment was cancelled.', 'danger')
    return redirect('/')

@app.route('/orders')
@login_required
def orders():
    user_orders = Order.query.filter_by(user_id=current_user.id).all()
    orders_details = []

    for order in user_orders:
        product = ProductsInfo.query.get(order.product_id)
        orders_details.append({
            'order_id': order.id,
            'product_name': product.name,
            'product_author': product.author,
            'product_price': product.price,
            'address': order.address,
            'order_date': order.order_date
        })

    return render_template('orders.html', orders=orders_details)

@app.route('/admin', methods=['GET', 'POST'])
def adminHome():
    if 'username' in session and session['username'] == 'admin':
        if request.method == 'POST':
            image = request.files['productImage']
            if image and allowed_file(image.filename):
                filename = secure_filename(image.filename)
                image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

            newItem = ProductsInfo(
                name=request.form['productName'],
                author=request.form['productAuthor'],
                description=request.form['productDescription'],
                price=request.form['productPrice'],
                link=request.form['productLink'],
                imageName=image.filename
            )
            try:
                session['productName'] = request.form['productName']
                db.session.add(newItem)
                db.session.commit()
                flash('Product added successfully', 'success')
                return redirect('/admin')
            except:
                return "There was an issue pushing to database"

        else:
            products = ProductsInfo.query.order_by(ProductsInfo.name).all()
            return render_template('Admin/adminPanel.html', products=products)
    else:
        return render_template('Error.html', title='Access Denied', msg="Unable to access admin Homepage. Please signin to continue.")

@app.route('/delete/<int:id>')
def deleteProduct(id):
    if 'username' in session and session['username'] == 'admin':
        toDelete = ProductsInfo.query.get_or_404(id)
        try:
            db.session.delete(toDelete)
            db.session.commit()
            flash('Product deleted', 'danger')
            return redirect('/admin')
        except:
            return "Some error occurred while deleting the file"
    else:
        return render_template('Error.html', title="Access Denied!", msg="You need admin privileges to perform this action!")

@app.route('/update/<int:id>', methods=['GET'])
def updateProduct(id):
    if request.method == 'GET':
        if 'username' in session and session['username'] == 'admin':
            toUpdate = ProductsInfo.query.get_or_404(id)
            return render_template('Admin/update.html', toUpdate=toUpdate, product_id=id)
        else:
            return render_template('Error.html', title="Access Denied!", msg="You need admin privileges to perform this action!")

@app.route('/updateproduct', methods=['POST'])
def UpdateProducts():
    if 'username' in session and session['username'] == 'admin':

        name = request.form['productName']
        author = request.form['productAuthor']
        description = request.form['productDescription']
        price = request.form['productPrice']
        link = request.form['productLink']
        image = request.files['productImage']
        if image and allowed_file(image.filename):
            filename = secure_filename(image.filename)
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

            image = image.filename
            db.session.query(ProductsInfo).filter(ProductsInfo.id == request.form['product_id']).update(
                {'name': name, 'author': author, 'description': description, 'price': price, 'link': link, 'imageName': image})
            db.session.commit()
            flash('Product updated successfully', 'success')

        else:
            db.session.query(ProductsInfo).filter(ProductsInfo.id == request.form['product_id']).update(
                {'name': name, 'author': author, 'description': description, 'price': price, 'link': link})
            db.session.commit()
            flash('Product updated successfully', 'success')

        return redirect('/admin')
    else:
        return render_template('Error.html', title="Access Denied!", msg="You need admin privileges to perform this action!")

@app.route('/')
def home():
    allProducts = []
    if 'username' not in session:
        session['username'] = 'None'
        session['logged_in'] = False

    try:
        allProducts = ProductsInfo.query.all()
    except:
        pass
    return render_template('home.html', allProducts=allProducts)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'username' not in session:
        session['username'] = 'None'
        session['logged_in'] = False

    form = LoginForm()
    if form.username.data and form.username.data == 'admin':
        if form.password.data == 'admin':
            session['username'] = request.form['username']
            session['logged_in'] = True
            return redirect('/admin')
        else:
            flash('Your credentials did not match. Please try again', 'danger')
            return redirect('/login')

    else:
        if form.validate_on_submit():
            user = User.query.filter_by(username=form.username.data).first()
            if user:
                if bcrypt.check_password_hash(user.password, form.password.data):
                    session['username'] = request.form['username']
                    session['logged_in'] = True
                    login_user(user)
                    return redirect('/')
                else:
                    flash('Your credentials did not match. Please try again', 'danger')
                    return redirect(url_for('login'))
            else:
                flash('Your credentials did not match. Please try again', 'danger')
                return redirect(url_for('login'))
        return render_template('login.html', form=form)

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    form = OtpForm()
    if form.validate_on_submit():
        if 'otp' in session and form.otp.data == session['otp']:
            user = User.query.filter_by(email=session['email']).first()
            if user:
                user.is_verified = True
                db.session.commit()
                flash('Your account has been verified. Please login.', 'success')
                return redirect(url_for('login'))
            else:
                flash('User does not exist.', 'danger')
                return redirect(url_for('signup'))
        else:
            flash('Invalid OTP. Please try again.', 'danger')
            return redirect(url_for('verify_otp'))
    return render_template('verify_otp.html', form=form)

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    logout_user()
    session['username'] = 'None'
    session['logged_in'] = False
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()
    if form.validate_on_submit():
        if (form.username.data).lower() == 'admin' or (form.username.data).lower() == 'none':
            flash('Username not allowed. Please choose any other username.', 'danger')
            return redirect(url_for('signup'))
        elif form.password.data != form.password2.data:
            flash('Password mismatch.', 'danger')
            return redirect(url_for('signup'))

        hashed_password = bcrypt.generate_password_hash(form.password.data, 12)
        otp = str(random.randint(1000, 9999))
        session['otp'] = otp
        session['email'] = form.email.data
        new_user = User(username=form.username.data, password=hashed_password, email=form.email.data, mobile=form.mobile.data)

        try:
            db.session.add(new_user)
            db.session.commit()
            send_otp(form.email.data, otp)
            flash('OTP has been sent to your email. Please verify your account.', 'info')
            return redirect(url_for('verify_otp'))
        except Exception as e:
            flash(f'An error occurred while creating the user: {str(e)}', 'danger')
            return redirect(url_for('signup'))

    return render_template('register.html', form=form)

@app.route('/order/<int:productid>')
def order(productid):
    if 'username' in session and session['username'] != 'None':
        try:
            productDetails = ProductsInfo.query.get_or_404(productid)
            return render_template('order.html', productDetails=productDetails)
        except:
            return redirect('/')
    else:
        flash('To buy, you need to be signed up!', 'danger')
        return redirect('/login')

def getApp():
    return app

if __name__ == '__main__':
    app.run(debug=True)