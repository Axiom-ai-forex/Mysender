# routes/dashboard.py
from flask import Blueprint, render_template, session, redirect, url_for, jsonify
from core.security_manager import require_auth

dashboard_bp = Blueprint('dashboard', __name__)

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

