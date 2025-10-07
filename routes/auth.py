from flask import Blueprint, render_template, request, redirect, url_for, session, flash

auth_routes_bp = Blueprint('auth_routes', __name__)

@auth_routes_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if username == 'admin' and password == 'password':
            session['user_id'] = '1'
            session['username'] = username
            flash('Login successful! Welcome to Email Sender Pro.', 'success')
            return redirect(url_for('dashboard.index'))
        else:
            flash('Invalid username or password. Try admin/password', 'error')
    
    return render_template('auth/login.html')

@auth_routes_bp.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('auth_routes.login'))

@auth_routes_bp.route('/forgot-password')
def forgot_password():
    return render_template('auth/forgot_password.html')

@auth_routes_bp.route('/setup-2fa')
def setup_2fa():
    if 'user_id' not in session:
        return redirect(url_for('auth_routes.login'))
    return render_template('auth/setup_2fa.html')

