from flask import Blueprint, render_template, request, jsonify, session, redirect, url_for
from functools import wraps

campaigns_bp = Blueprint('campaigns', __name__)

def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function

@campaigns_bp.route('/')
@require_auth
def list_campaigns():
    return render_template('campaigns/create.html')

@campaigns_bp.route('/create')
@require_auth
def create_campaign():
    return render_template('campaigns/create.html')

@campaigns_bp.route('/edit/<campaign_id>')
@require_auth
def edit_campaign(campaign_id):
    return render_template('campaigns/edit.html', campaign_id=campaign_id)

@campaigns_bp.route('/preview/<campaign_id>')
@require_auth
def preview_campaign(campaign_id):
    return render_template('campaigns/preview.html', campaign_id=campaign_id)

@campaigns_bp.route('/results/<campaign_id>')
@require_auth
def campaign_results(campaign_id):
    return render_template('campaigns/results.html', campaign_id=campaign_id)
