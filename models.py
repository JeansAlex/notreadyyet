from flask_sqlalchemy import SQLAlchemy
import random

# Initialize SQLAlchemy
db = SQLAlchemy()

# Luhn's Algorithm to validate/generate account numbers
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

# Define Models
class User(db.Model):
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

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(120), nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.now())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Loan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    interest_rate = db.Column(db.Float, nullable=False)
    approved = db.Column(db.Boolean, default=False)
    user = db.relationship('User', backref='loans', lazy=True)

