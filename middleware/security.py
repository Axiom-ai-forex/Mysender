# middleware/security.py
"""
Security Middleware for Request Processing
"""

from flask import request, jsonify, session, g
from functools import wraps
import logging
from datetime import datetime, timedelta

from core.security_manager import security_manager

logger = logging.getLogger(__name__)


def security_headers(response):
    """Add security headers to all responses"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
    
    return response


def require_auth(f):
    """Decorator to require authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            security_manager.log_security_event('unauthorized_access_attempt', {
                'endpoint': request.endpoint,
                'method': request.method
            })
            return jsonify({'error': 'Authentication required'}), 401
        
        # Update last activity
        session['last_activity'] = datetime.utcnow().isoformat()
        
        return f(*args, **kwargs)
    return decorated_function


def require_csrf(f):
    """Decorator to require CSRF token"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method in ['POST', 'PUT', 'DELETE', 'PATCH']:
            csrf_token = request.headers.get('X-CSRF-Token')
            session_csrf = session.get('csrf_token')
            
            if not csrf_token or csrf_token != session_csrf:
                security_manager.log_security_event('csrf_violation', {
                    'endpoint': request.endpoint,
                    'provided_token': csrf_token[:10] + '...' if csrf_token else None
                })
                return jsonify({'error': 'CSRF token validation failed'}), 403
        
        return f(*args, **kwargs)
    return decorated_function


def rate_limit(limit_type='api'):
    """Decorator for rate limiting"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Use IP address or user ID as key
            key = session.get('user_id', request.remote_addr)
            
            allowed, limit_info = security_manager.check_rate_limit(key, limit_type)
            
            if not allowed:
                security_manager.log_security_event('rate_limit_exceeded', {
                    'endpoint': request.endpoint,
                    'key': key,
                    'limit_type': limit_type
                })
                return jsonify({
                    'error': 'Rate limit exceeded',
                    'reset_in': limit_info.get('reset_in', 60)
                }), 429
            
            # Add rate limit headers
            response = f(*args, **kwargs)
            if hasattr(response, 'headers'):
                response.headers['X-RateLimit-Limit'] = str(limit_info.get('limit', 0))
                response.headers['X-RateLimit-Remaining'] = str(limit_info.get('remaining', 0))
            
            return response
        return decorated_function
    return decorator


def security_scan():
    """Middleware to scan requests for security threats"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Prepare request data for scanning
            request_data = {}
            
            # Scan JSON data
            if request.is_json and request.json:
                request_data.update(request.json)
            
            # Scan form data
            if request.form:
                request_data.update(request.form.to_dict())
            
            # Scan query parameters
            if request.args:
                request_data.update(request.args.to_dict())
            
            # Detect threats
            threats = security_manager.detect_threats(request_data)
            
            if threats:
                # Log security violations
                for threat in threats:
                    security_manager.log_security_event('security_threat_detected', {
                        'threat_type': threat.violation_type,
                        'severity': threat.severity.value,
                        'endpoint': request.endpoint,
                        'details': threat.details
                    })
                
                # Block high severity threats
                high_threats = [t for t in threats if t.severity in ['HIGH', 'CRITICAL']]
                if high_threats:
                    return jsonify({'error': 'Security violation detected'}), 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

