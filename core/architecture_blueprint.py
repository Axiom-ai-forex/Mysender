# architecture_blueprint.py

"""
Modern system architecture blueprint for an advanced web email sender
optimized for Fedora 41 with a strong security focus.

Technology selections reflect best practices as of 2025, including async support,
secure authentication, and monitoring integration.
"""

ARCHITECTURE = {
    'backend': {
        'framework': 'Flask 3.0+ with Werkzeug 3.0+',
        'async_support': 'Celery 5.3+ with Redis broker',
        'database': 'SQLAlchemy 2.0+ with PostgreSQL or SQLite fallback',
        'security': 'Flask-Login + Flask-WTF + CSRF protection',
    },
    'email_processing': {
        'smtp_client': 'aiosmtplib for asynchronous SMTP operations',
        'validation': 'email-validator with py3dns for robust MX checks',
        'templating': 'Jinja2 with built-in XSS protection',
        'authentication': 'OAuth2 authentication with STARTTLS mandatory',
    },
    'monitoring': {
        'logging': 'Python standard logging integrated with systemd journal',
        'metrics': 'Prometheus-compatible metrics endpoint exposure',
        'health_checks': 'Built-in HTTP health endpoints for uptime monitoring',
    }
}

