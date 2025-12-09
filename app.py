from flask import Flask, request, jsonify, session, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from apscheduler.schedulers.background import BackgroundScheduler
import requests
from bs4 import BeautifulSoup
import json
import stripe
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import smtplib
from openai import OpenAI  # Assume installed; fallback to requests if not
import re
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///hub.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Stripe
stripe.api_key = os.environ.get('STRIPE_SECRET_KEY')

# OpenAI
openai_client = OpenAI(api_key=os.environ.get('OPENAI_API_KEY')) if os.environ.get('OPENAI_API_KEY') else None

# SendGrid API Key
SENDGRID_KEY = os.environ.get('SENDGRID_API_KEY')

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    radius = db.Column(db.Integer, default=10)  # km
    trades = db.Column(db.String(200), default='')  # JSON list as str
    is_premium = db.Column(db.Boolean, default=False)
    stripe_id = db.Column(db.String(100))

class Lead(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200))
    reference = db.Column(db.String(50), unique=True)
    status = db.Column(db.String(100))
    category = db.Column(db.String(100))
    address = db.Column(db.String(200))
    site_area = db.Column(db.Float)
    storeys = db.Column(db.Integer)
    homes = db.Column(db.Integer)
    floor_area = db.Column(db.Float)
    description = db.Column(db.Text)
    image_url = db.Column(db.String(200))
    postcode = db.Column(db.String(10))  # Extracted
    tags = db.Column(db.String(200))  # JSON str
    scraped_at = db.Column(db.DateTime, default=datetime.utcnow)

with app.app_context():
    db.create_all()
    # Seed mock data if empty (for demo; replace with real scrape)
    if Lead.query.count() == 0:
        mock_leads = [
            {
                'title': 'Land at Rainbow Industrial Estate',
                'reference': '3805B/APP/2025/2613',
                'status': 'Awaiting Mayor comment',
                'category': 'Residential',
                'address': 'Rainbow and Kirby Industrial Estates, Trout Road, Yiewsley UB7 7XT',
                'site_area': 2.3,
                'storeys': 11,
                'homes': 433,
                'floor_area': 2286.3,
                'description': 'New residential development with plumbing and electrical works required.',
                'image_url': '',
                'postcode': 'UB7 7XT',
                'tags': json.dumps(['plumber', 'electrician'])
            },
            {
                'title': 'Office Redevelopment in Shoreditch',
                'reference': 'LBC/2025/4567',
                'status': 'Approved',
                'category': 'Commercial',
                'address': '123 Brick Lane, London E1 6SE',
                'site_area': 0.5,
                'storeys': 5,
                'homes': 0,
                'floor_area': 1500.0,
                'description': 'Demolition and structural rebuild with roofing needs.',
                'image_url': '',
                'postcode': 'E1 6SE',
                'tags': json.dumps(['builder', 'roofer'])
            },
            {
                'title': 'Residential Block in Croydon',
                'reference': 'CRO/2025/7890',
                'status': 'Awaiting Decision',
                'category': 'Residential',
                'address': '45 High Street, Croydon CR0 1AA',
                'site_area': 1.2,
                'storeys': 8,
                'homes': 120,
                'floor_area': 800.5,
                'description': 'New build including civil engineering for parking.',
                'image_url': '',
                'postcode': 'CR0 1AA',
                'tags': json.dumps(['civil engineer'])
            }
        ]
        for lead_data in mock_leads:
            lead = Lead(**lead_data)
            db.session.add(lead)
        db.session.commit()

# Pre-seed test user as premium
with app.app_context():
    if not User.query.filter_by(email='test@contractor.com').first():
        test_user = User(
            email='test@contractor.com',
            password_hash=generate_password_hash('test123'),
            radius=10,
            trades=json.dumps(['plumber', 'electrician']),
            is_premium=True
        )
        db.session.add(test_user)
        db.session.commit()

# Keyword mapping for tags
TAG_MAPPING = {
    'plumbing': 'plumber', 'pipes': 'plumber',
    'electrical': 'electrician', 'wiring': 'electrician',
    'demolition': 'builder', 'structural': 'builder',
    'roofing': 'roofer',
    'parking': 'civil engineer', 'servicing': 'civil engineer'
}

def extract_tags(description):
    tags = set()
    desc_lower = description.lower()
    for keyword, tag in TAG_MAPPING.items():
        if keyword in desc_lower:
            tags.add(tag)
    return json.dumps(list(tags))

def scrape_leads():
    # Mock scrape; in prod, use Selenium for JS site
    print("Scrape task ran; using mock data due to site access issues.")

def send_daily_emails():
    users = User.query.all()
    for user in users:
        leads = Lead.query.filter(Lead.scraped_at > datetime.utcnow() - timedelta(days=1)).limit(5 if user.is_premium else 1).all()
        body = "<h1>Your Daily London Leads</h1><div class='grid'>"
        for lead in leads:
            body += f"<div class='card'>{lead.title} - {lead.address}</div>"
        body += "</div>"
        if SENDGRID_KEY:
            requests.post('https://api.sendgrid.com/v3/mail/send', headers={'Authorization': f'Bearer {SENDGRID_KEY}'}, json={
                'personalizations': [{'to': [{'email': user.email}]}],
                'from': {'email': 'leads@londonleaddrop.com'},
                'content': [{'type': 'text/html', 'value': body}]
            })

# Scheduler
scheduler = BackgroundScheduler()
scheduler.add_job(func=scrape_leads, trigger="cron", hour=6, minute=0)
scheduler.add_job(func=send_daily_emails, trigger="cron", hour=7, minute=0)
scheduler.start()

# Routes
@app.route('/')
def landing():
    return render_template('landing.html')

@app.route('/register', methods=['POST'])
def register():
    email = request.form['email']
    password = generate_password_hash(request.form['password'])
    radius = int(request.form['radius'])
    trades = json.dumps(request.form.getlist('trades'))
    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email exists'}), 400
    user = User(email=email, password_hash=password, radius=radius, trades=trades, is_premium=False)
    db.session.add(user)
    db.session.commit()
    return jsonify({'success': 'Registered'})

@app.route('/login', methods=['POST'])
def login():
    user = User.query.filter_by(email=request.form['email']).first()
    if user and check_password_hash(user.password_hash, request.form['password']):
        session['user_id'] = user.id
        return jsonify({'success': 'Logged in'})
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/leads')
def get_leads():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    user = User.query.get(session['user_id'])
    leads = Lead.query.all()  # Apply filters from query params later
    if not user.is_premium:
        leads = leads[:1]
        for l in leads: l.description = l.description[:50] + '... Upgrade!'
    return jsonify([{
        'title': l.title, 'reference': l.reference, 'status': l.status, 'category': l.category,
        'address': l.address, 'site_area': l.site_area, 'storeys': l.storeys, 'homes': l.homes,
        'floor_area': l.floor_area, 'description': l.description, 'image_url': l.image_url,
        'postcode': l.postcode,
        'tags': json.loads(l.tags) if l.tags else []
    } for l in leads])

@app.route('/api/chat', methods=['POST'])
def chat():
    if 'user_id' not in session: return jsonify({'error': 'Unauthorized'}), 401
    query = request.json['query']
    # Mock reply if no OpenAI
    if not openai_client:
        reply = "Based on your query, here are top matches: Mock lead 1, Mock lead 2."
    else:
        response = openai_client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "system", "content": "You are LeadBot, filter leads by query (location, trade). Respond with 3-5 card summaries."},
                      {"role": "user", "content": query}]
        )
        reply = response.choices[0].message.content
    leads = Lead.query.limit(3).all()
    return jsonify({'reply': reply, 'leads': [l.title for l in leads]})

@app.route('/upgrade', methods=['POST'])
def upgrade():
    if 'user_id' not in session: return jsonify({'error': 'Unauthorized'}), 401
    user = User.query.get(session['user_id'])
    session = stripe.checkout.Session.create(
        payment_method_types=['card'],
        line_items=[{'price': 'price_1ABC123', 'quantity': 1}],  # Replace with real price ID
        mode='subscription',
        success_url=url_for('dashboard', _external=True) + '?success=1',
        cancel_url=url_for('dashboard', _external=True) + '?cancel=1',
        customer_email=user.email
    )
    user.stripe_id = session.customer
    db.session.commit()
    return jsonify({'url': session.url})

@app.route('/webhook', methods=['POST'])
def stripe_webhook():
    payload = request.data
    event = stripe.Webhook.construct_event(payload, request.headers['Stripe-Signature'], 'whsec_...')
    if event['type'] == 'checkout.session.completed':
        stripe_id = event['data']['object']['customer']
        user = User.query.filter_by(stripe_id=stripe_id).first()
        if user:
            user.is_premium = True
            db.session.commit()
    return jsonify(success=True)

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session: return redirect(url_for('landing'))
    return render_template('dashboard.html')

if __name__ == '__main__':
    app.run(debug=True)
