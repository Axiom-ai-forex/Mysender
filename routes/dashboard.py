# routes/dashboard.py
from flask import Blueprint, render_template, session, redirect, url_for, flash
from functools import wraps

dashboard_bp = Blueprint('dashboard', __name__)

def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('auth_routes.login'))
        return f(*args, **kwargs)
    return decorated_function

@dashboard_bp.route('/')
@require_auth
def index():
    return render_template('dashboard/index.html')

@dashboard_bp.route('/analytics')
@require_auth  
def analytics():
    return render_template('dashboard/analytics.html')

@dashboard_bp.route('/campaigns')
@require_auth
def campaigns():
    return render_template('dashboard/campaigns.html')

