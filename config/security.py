# config/security.py
"""
Security Configuration for Fedora 41 Deployment
"""

import os
import secrets
from datetime import timedelta


class SecurityConfig:
    """Security configuration settings"""
    
    # Encryption settings
    ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY') or secrets.token_urlsafe(32)
    
    # Session settings
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_urlsafe(32)
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)
    
    # Rate limiting
    RATELIMIT_STORAGE_URL = 'redis://localhost:6379/4'
    RATELIMIT_STRATEGY = 'fixed-window'
    RATELIMIT_HEADERS_ENABLED = True
    
    # CSRF protection
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600  # 1 hour
    
    # Content Security Policy
    CSP_POLICY = {
        'default-src': "'self'",
        'script-src': "'self' 'unsafe-inline'",
        'style-src': "'self' 'unsafe-inline'",
        'img-src': "'self' data: https:",
        'connect-src': "'self'",
        'font-src': "'self'",
        'object-src': "'none'",
        'base-uri': "'self'",
        'form-action': "'self'"
    }
    
    # Security headers
    SECURITY_HEADERS = {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Permissions-Policy': 'camera=(), microphone=(), geolocation=()'
    }
    
    # Audit settings
    AUDIT_LOG_RETENTION_DAYS = 90
    AUDIT_LOG_LEVEL = 'INFO'
    
    # 2FA settings
    TOTP_ISSUER_NAME = 'Email Sender Pro'
    TOTP_VALIDITY_WINDOW = 1
    
    # File upload security
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB
    UPLOAD_EXTENSIONS = {'.txt', '.csv', '.json', '.html'}
    
    # Database security
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,
        'pool_recycle': 300,
        'connect_args': {
            'check_same_thread': False,
            'timeout': 20
        }
    }


class FedoraSecurityConfig(SecurityConfig):
    """Fedora 41 specific security configuration"""
    
    # SELinux settings
    SELINUX_ENABLED = True
    SELINUX_CONTEXT = 'system_u:system_r:httpd_t:s0'
    
    # Systemd integration
    SYSTEMD_WATCHDOG = True
    SYSTEMD_NOTIFY_SOCKET = os.environ.get('NOTIFY_SOCKET')
    
    # Firewall settings
    FIREWALL_ZONES = ['public', 'trusted']
    ALLOWED_PORTS = [80, 443, 587, 465]
    
    # Log settings for journald
    LOG_FORMAT = '%(levelname)s:%(name)s:%(message)s'
    LOG_TO_SYSLOG = True
    SYSLOG_ADDRESS = '/dev/log'

