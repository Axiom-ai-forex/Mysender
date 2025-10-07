from flask import Blueprint, render_template, request, redirect, url_for, session, flash

auth_routes_bp = Blueprint('auth_routes', __name__)

@auth_routes_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # For now, simple test login
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username == 'admin' and password == 'password':
            session['user_id'] = '1'
            session['username'] = username
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard.index'))
        else:
            flash('Invalid credentials', 'error')
    
    return render_template('auth/login.html')

@auth_routes_bp.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully', 'info')
    return redirect(url_for('auth_routes.login'))

@auth_routes_bp.route('/forgot-password')
def forgot_password():
    return render_template('auth/forgot_password.html')

@auth_routes_bp.route('/setup-2fa')
def setup_2fa():
    return render_template('auth/setup_2fa.html')
