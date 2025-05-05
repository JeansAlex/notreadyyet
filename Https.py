import random
import string
import json
import secrets
import webbrowser
import logging
from flask import Flask, redirect, url_for, session, render_template, request, flash
from authlib.integrations.flask_client import OAuth
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import (
    LoginManager, login_user, logout_user,
    login_required, current_user, UserMixin
)
import ssl
import time
from threading import Thread

# Initialize Flask app
app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# Configure SQLAlchemy database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///bank.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Luhn's Algorithm
def luhn_check(account_number):
    digits = [int(d) for d in account_number]
    checksum = 0
    reverse_digits = digits[::-1]
    for i, digit in enumerate(reverse_digits):
        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0

def generate_account_number():
    while True:
        number = random.randint(100000000, 999999999)
        if luhn_check(str(number)):
            return str(number)

# Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    name = db.Column(db.String(120), nullable=False)
    password_hash = db.Column(db.String(120), nullable=True)
    account_number = db.Column(db.String(20), unique=True, nullable=False, default=generate_account_number)
    balance = db.Column(db.Float, default=1000.0)
    credit_score = db.Column(db.Integer, nullable=False, default=650)
    income = db.Column(db.Float, nullable=False, default=40000.0)
    pending_loan_amount = db.Column(db.Float, nullable=True)
    loan_interest_rate = db.Column(db.Float, nullable=True)
    transactions = db.relationship('Transaction', backref='user', lazy=True)

class LoanHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    loan_amount = db.Column(db.Float, nullable=False)
    interest_rate = db.Column(db.Float, nullable=False)
    date_accepted = db.Column(db.DateTime, default=db.func.now())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('loan_histories', lazy=True))


class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(120), nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.now())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Load OAuth credentials
with open(r'C:\Users\mitchellalexand\Desktop\Secret\client_secret_989028034934-k8sclvu73i82uv49mgni1spg1sukmbf7.apps.googleusercontent.com.json') as f:
    creds = json.load(f)['web']

oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=creds['client_id'],
    client_secret=creds['client_secret'],
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'},
    redirect_uri='https://127.0.0.1:5000/auth/callback',
)

# Routes
@app.route('/accept_loan', methods=['POST'])
@login_required
def accept_loan():
    if current_user.loan_interest_rate is not None:
        # User already has an active loan
        flash("You already have an active loan. Repay it before accepting a new one.")
        return redirect('/loan_history')  # Redirect to loan history

    if current_user.pending_loan_amount:
        # Add the loan history entry
        loan_history = LoanHistory(
            loan_amount=current_user.pending_loan_amount,
            interest_rate=current_user.loan_interest_rate,
            user_id=current_user.id
        )
        db.session.add(loan_history)

        # Update user balance and clear the pending loan
        current_user.balance += current_user.pending_loan_amount
        db.session.add(Transaction(
            action=f"Accepted loan of ${current_user.pending_loan_amount:.2f} at {current_user.loan_interest_rate:.2f}%",
            user_id=current_user.id
        ))
        current_user.pending_loan_amount = None
        current_user.loan_interest_rate = None
        db.session.commit()

        return redirect('/')

    return "No loan to accept."


@app.route('/loan_history', methods=['GET', 'POST'])
@login_required
def loan_history():
    if request.method == 'POST':
        payment = float(request.form.get('payment_amount', 0))
        if current_user.loan_interest_rate is None or payment <= 0 or payment > current_user.balance:
            flash("Invalid payment.")
        else:
            current_user.balance -= payment
            # Reduce the loan amount in LoanHistory instead of adjusting interest
            active_loan = LoanHistory.query.filter_by(user_id=current_user.id).order_by(LoanHistory.date_accepted.desc()).first()

            if active_loan:
                if payment >= active_loan.loan_amount:
                    flash("Loan fully repaid.")
                    db.session.delete(active_loan)  # Delete the loan from loan history if paid off
                else:
                    active_loan.loan_amount -= payment  # Deduct payment from the loan amount
                    flash(f"Paid ${payment:.2f} toward your loan. Remaining loan: ${active_loan.loan_amount:.2f}")

                db.session.add(Transaction(
                    action=f"Paid ${payment:.2f} toward loan",
                    user_id=current_user.id
                ))
                db.session.commit()

    # Display all loan history for the user
    loans = LoanHistory.query.filter_by(user_id=current_user.id).all()
    return render_template('loan_history.html', loans=loans, user=current_user)


@app.route('/pay_loan', methods=['POST'])
@login_required
def pay_loan():
    if current_user.loan_interest_rate is None:
        return "No active loan to pay."

    payment = float(request.form['payment_amount'])
    if payment <= 0 or payment > current_user.balance:
        return "Invalid payment amount."

    # Reduce the loan amount in LoanHistory instead of adjusting interest
    active_loan = LoanHistory.query.filter_by(user_id=current_user.id).order_by(LoanHistory.date_accepted.desc()).first()
    if active_loan:
        current_user.balance -= payment

        if payment >= active_loan.loan_amount:
            active_loan.loan_amount = 0
            flash("Loan fully repaid.")
            db.session.delete(active_loan)  # Delete the loan from history if paid off
        else:
            active_loan.loan_amount -= payment  # Deduct payment from the loan amount
            flash(f"Paid ${payment:.2f} toward your loan. Remaining loan: ${active_loan.loan_amount:.2f}")

        db.session.add(Transaction(
            action=f"Paid ${payment:.2f} toward loan",
            user_id=current_user.id
        ))

        db.session.commit()
    return redirect('/')

@app.route('/')
def index():
    if current_user.is_authenticated:
        transactions = Transaction.query.filter_by(user_id=current_user.id).order_by(Transaction.timestamp.desc()).all()
        return render_template('bank.html', user_db=current_user, transactions=transactions)
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        name = request.form['name']
        password = request.form['password']
        if User.query.filter_by(email=email).first():
            return "Email is already registered."
        user = User(
            email=email,
            name=name,
            password_hash=generate_password_hash(password),
            account_number=generate_account_number()
        )
        db.session.add(user)
        db.session.commit()
        login_user(user)
        return redirect('/')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and user.password_hash and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect('/')
        return render_template('login.html', error_message="Invalid credentials.")
    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect('/')

@app.route('/login/google')
def google_login():
    nonce = secrets.token_hex(16)
    session['nonce'] = nonce
    return google.authorize_redirect(url_for('google_authorized', _external=True), nonce=nonce)

@app.route('/auth/callback')
def google_authorized():
    token = google.authorize_access_token()
    nonce = session.get('nonce')
    try:
        user_info = google.parse_id_token(token, nonce=nonce)
    except Exception as e:
        return f"Error: {str(e)}", 500

    email = user_info['email']
    name = user_info['name']

    user = User.query.filter_by(email=email).first()
    if not user:
        user = User(email=email, name=name, account_number=generate_account_number())
        db.session.add(user)
        db.session.commit()

    login_user(user)
    return redirect('/')

@app.route('/deposit', methods=['POST'])
@login_required
def deposit():
    amount = float(request.form['amount'])
    current_user.balance += amount
    db.session.add(Transaction(action=f"Deposited ${amount:.2f}", user_id=current_user.id))
    db.session.commit()
    return redirect('/')

@app.route('/transfer', methods=['GET', 'POST'])
@login_required
def transfer():
    if request.method == 'POST':
        recipient_account = request.form['recipient_account']
        amount = float(request.form['amount'])
        recipient = User.query.filter_by(account_number=recipient_account).first()

        if not recipient:
            return render_template('transfer.html', error_message="Recipient not found")
        if current_user.balance < amount:
            return render_template('transfer.html', error_message="Insufficient balance")

        current_user.balance -= amount
        recipient.balance += amount
        db.session.add(Transaction(action=f"Transferred ${amount:.2f} to {recipient_account}", user_id=current_user.id))
        db.session.add(Transaction(action=f"Received ${amount:.2f} from {current_user.account_number}", user_id=recipient.id))
        db.session.commit()
        return redirect('/')
    return render_template('transfer.html')

@app.route('/loan_offer', methods=['GET', 'POST'])
@login_required
def loan_offer():
    # Block users who already have an active loan
    if current_user.loan_interest_rate is not None:
        flash("You already have an active loan. Repay it before applying for another.")
        return redirect('/loan_history')  # Redirect to loan history

    if request.method == 'POST':
        try:
            income = float(request.form.get('income', 0))
            credit_score = int(request.form.get('credit_score', 0))
        except ValueError:
            flash("Invalid input format.")
            return redirect('/loan_apply')

        # Update the user's income and credit score
        current_user.income = income
        current_user.credit_score = credit_score
        db.session.commit()

        # Check if the user qualifies
        if credit_score > 500 and income > 30000:
            base_offer = (income // 20) // 250 * 250  # Round down to nearest 250
            steps = (850 - credit_score) // 50
            interest = 3.5 + (3.5 * steps)

            # Set the loan offer for the user
            current_user.pending_loan_amount = base_offer
            current_user.loan_interest_rate = interest
            db.session.commit()

            return render_template("loan_offer.html", amount=base_offer, interest=interest, has_offer=True, user=current_user)
        else:
            flash("You do not qualify for a loan.")
            return redirect('/loan_apply')

    # If the user already has a pending loan offer, show the offer details
    if current_user.pending_loan_amount:
        return render_template("loan_offer.html", 
                               amount=current_user.pending_loan_amount, 
                               interest=current_user.loan_interest_rate, 
                               has_offer=True, user=current_user)

    # If no pending offer exists, show the form for loan application
    return render_template("loan_offer.html", has_offer=False, user=current_user)

@app.route('/reject_loan', methods=['POST'])
@login_required
def reject_loan():
    current_user.pending_loan_amount = None
    current_user.loan_interest_rate = None
    db.session.commit()
    return redirect('/')

@app.route('/loan_apply')
@login_required
def loan_apply():
    return render_template("loan_apply.html", user=current_user)

# Suppress debug logs
logging.basicConfig(level=logging.WARNING)

# Run app
if __name__ == '__main__':
    with app.app_context():
        db.create_all()

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(
        certfile=r'C:\Users\mitchellalexand\Desktop\OpenSSL\cert.pem',
        keyfile=r'C:\Users\mitchellalexand\Desktop\OpenSSL\key.pem'
    )

    # Start the Flask app in a background thread
    def run_app():
        app.run(
            host='127.0.0.1',
            port=5000,
            ssl_context=context
        )

    # Start the Flask app in a background thread
    Thread(target=run_app).start()

    # Give the Flask server a moment to start
    time.sleep(2)

    # Open the browser automatically
    webbrowser.open('https://localhost:5000')
