# app.py
"""
Production-Ready Flask Application Factory for Enterprise Email Marketing Platform
Optimized for Fedora 41 with comprehensive security, monitoring, and scalability features

This application factory integrates all existing modules and provides:
- Secure session management with Redis backend
- Real-time analytics via SocketIO
- Async email processing with Celery
- Comprehensive error handling and logging
- Health monitoring and metrics
- Security middleware and CSRF protection
- Environment-based configuration management
"""

import os
import sys
import logging
import logging.handlers
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import asyncio
import signal
import atexit
from pathlib import Path

# Flask and extensions
from flask import Flask, request, jsonify, g, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_socketio import SocketIO
from flask_cors import CORS
from flask_wtf.csrf import CSRFProtect
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.exceptions import HTTPException

# Database and caching
import redis
from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.pool import QueuePool

# Celery and async processing
from celery import Celery
from kombu import Queue

# Security and monitoring
import secrets
from datetime import timezone

# Import existing modules
try:
    from core.database_models import Base
    from core.security_manager import SecurityManager, init_security_manager
    from core.template_engine import SecureTemplateEngine
    from services.analytics import analytics_service
    from api.auth import auth_bp
    from api.analytics import analytics_bp, init_socketio
    from middleware.security import security_headers, require_auth, security_scan
    from tasks.email_sender import celery_app
    from config.security import SecurityConfig, FedoraSecurityConfig
except ImportError as e:
    print(f"Critical import error: {e}")
    print("Ensure all required modules are available in the Python path")
    sys.exit(1)

try:
    from routes.dashboard import dashboard_bp
    from routes.campaigns import campaigns_bp  
    from routes.auth import auth_routes_bp
    ROUTES_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Route imports failed: {e}")
    ROUTES_AVAILABLE = False

# Then in the register_blueprints function, add:
if ROUTES_AVAILABLE:
    app.register_blueprint(dashboard_bp, url_prefix='/dashboard')
    app.register_blueprint(campaigns_bp, url_prefix='/campaigns') 
    app.register_blueprint(auth_routes_bp, url_prefix='/auth')

# Configure logging for systemd journal integration
def setup_fedora_logging(app: Flask) -> None:
    """
    Configure logging optimized for Fedora 41 systemd journal integration
    
    This setup provides:
    - Structured logging compatible with journald
    - Multiple log levels and handlers
    - Security event logging
    - Performance monitoring integration
    """
    # Remove default Flask handlers to avoid duplicate logs
    app.logger.handlers.clear()
    
    # Create custom formatters for different contexts
    journal_formatter = logging.Formatter(
        fmt='%(name)s[%(process)d]: %(levelname)s %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    detailed_formatter = logging.Formatter(
        fmt='%(asctime)s %(name)-20s %(levelname)-8s %(funcName)-15s:%(lineno)-4d %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Configure root logger level
    log_level = getattr(logging, app.config.get('LOG_LEVEL', 'INFO').upper())
    app.logger.setLevel(log_level)
    
    # Systemd journal handler (primary for production)
    try:
        import systemd.journal
        journal_handler = systemd.journal.JournalHandler()
        journal_handler.setFormatter(journal_formatter)
        journal_handler.setLevel(log_level)
        app.logger.addHandler(journal_handler)
        app.logger.info("Systemd journal logging enabled")
    except ImportError:
        app.logger.warning("systemd.journal not available, falling back to syslog")
        
        # Fallback to syslog for development/testing
        syslog_handler = logging.handlers.SysLogHandler(
            address='/dev/log' if os.path.exists('/dev/log') else ('localhost', 514)
        )
        syslog_handler.setFormatter(journal_formatter)
        syslog_handler.setLevel(log_level)
        app.logger.addHandler(syslog_handler)
    
    # File handler for detailed debugging (development only)
    if app.config.get('FLASK_ENV') == 'development':
        log_dir = Path('/var/log/email-sender')
        log_dir.mkdir(exist_ok=True, parents=True)
        
        file_handler = logging.handlers.RotatingFileHandler(
            log_dir / 'email-sender.log',
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        file_handler.setFormatter(detailed_formatter)
        file_handler.setLevel(logging.DEBUG)
        app.logger.addHandler(file_handler)
    
    # Suppress verbose third-party logs in production
    if not app.debug:
        logging.getLogger('werkzeug').setLevel(logging.WARNING)
        logging.getLogger('socketio').setLevel(logging.WARNING)
        logging.getLogger('engineio').setLevel(logging.WARNING)


def create_redis_clients(app: Flask) -> Dict[str, redis.Redis]:
    """
    Create Redis clients for different purposes with optimized configurations
    
    Returns:
        Dictionary containing Redis clients for:
        - sessions: User session storage
        - cache: Application caching
        - celery: Celery broker and result backend
        - rate_limit: Rate limiting storage
        - analytics: Real-time analytics data
    """
    redis_config = {
        'host': app.config.get('REDIS_HOST', 'localhost'),
        'port': app.config.get('REDIS_PORT', 6379),
        'decode_responses': True,
        'socket_connect_timeout': 5,
        'socket_timeout': 5,
        'retry_on_timeout': True,
        'health_check_interval': 30
    }
    
    # Create separate Redis databases for different purposes
    clients = {
        'sessions': redis.Redis(db=0, **redis_config),
        'cache': redis.Redis(db=1, **redis_config), 
        'celery': redis.Redis(db=2, **redis_config),
        'rate_limit': redis.Redis(db=3, **redis_config),
        'analytics': redis.Redis(db=4, **redis_config)
    }
    
    # Test Redis connectivity
    for name, client in clients.items():
        try:
            client.ping()
            app.logger.info(f"Redis {name} client connected successfully")
        except redis.ConnectionError as e:
            app.logger.error(f"Redis {name} connection failed: {e}")
            if app.config.get('REDIS_REQUIRED', True):
                raise
    
    return clients


def configure_database(app: Flask) -> SQLAlchemy:
    """
    Configure SQLAlchemy 2.0 with async support and production optimizations
    
    Features:
    - Connection pooling for high concurrency
    - Query optimization and monitoring
    - Health checks and reconnection logic
    - Performance logging for slow queries
    """
    # Database URL with connection pooling parameters
    database_url = app.config.get('DATABASE_URL', 'sqlite:///email_sender.db')
    
    # Configure SQLAlchemy engine with production settings
    engine_options = {
        'poolclass': QueuePool,
        'pool_size': app.config.get('DB_POOL_SIZE', 20),
        'max_overflow': app.config.get('DB_MAX_OVERFLOW', 30),
        'pool_pre_ping': True,  # Verify connections before use
        'pool_recycle': 3600,   # Recycle connections every hour
        'echo': app.debug,      # Log SQL queries in debug mode
        'future': True,         # Enable SQLAlchemy 2.0 mode
    }
    
    # Add PostgreSQL-specific optimizations
    if 'postgresql' in database_url:
        engine_options.update({
            'connect_args': {
                'options': '-c default_transaction_isolation=read_committed',
                'application_name': 'email_sender',
                'connect_timeout': 10,
            }
        })
    
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = engine_options
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # Initialize SQLAlchemy
    db = SQLAlchemy()
    db.init_app(app)
    
    # Configure database event listeners for monitoring
    @event.listens_for(Engine, "before_cursor_execute")
    def receive_before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
        """Log slow queries for performance monitoring"""
        context._query_start_time = datetime.now()
    
    @event.listens_for(Engine, "after_cursor_execute")  
    def receive_after_cursor_execute(conn, cursor, statement, parameters, context, executemany):
        """Log completion of slow queries"""
        total = (datetime.now() - context._query_start_time).total_seconds()
        if total > app.config.get('SLOW_QUERY_THRESHOLD', 1.0):
            app.logger.warning(f"Slow query ({total:.2f}s): {statement[:100]}...")
    
    app.logger.info(f"Database configured: {database_url.split('@')[-1] if '@' in database_url else database_url}")
    return db


def configure_celery(app: Flask, redis_clients: Dict[str, redis.Redis]) -> Celery:
    """
    Configure Celery with Redis broker and comprehensive task routing
    
    Features:
    - Multiple queues for different task types
    - Result backend configuration
    - Task routing and priority
    - Error handling and retry logic
    - Monitoring integration
    """
    # Configure Celery with Redis broker
    celery_config = {
        'broker_url': f"redis://{app.config.get('REDIS_HOST', 'localhost')}:{app.config.get('REDIS_PORT', 6379)}/2",
        'result_backend': f"redis://{app.config.get('REDIS_HOST', 'localhost')}:{app.config.get('REDIS_PORT', 6379)}/2",
        'task_serializer': 'json',
        'result_serializer': 'json',
        'accept_content': ['json'],
        'result_expires': 3600,
        'timezone': 'UTC',
        'enable_utc': True,
        
        # Worker configuration
        'worker_prefetch_multiplier': 1,
        'task_acks_late': True,
        'worker_disable_rate_limits': False,
        'worker_max_tasks_per_child': 1000,
        
        # Task routing
        'task_routes': {
            'tasks.email_sender.send_single_email': {'queue': 'email_sending'},
            'tasks.email_sender.send_batch': {'queue': 'batch_processing'},
            'tasks.email_sender.process_campaign': {'queue': 'campaign_management'},
            'services.analytics.*': {'queue': 'analytics'},
        },
        
        # Queue definitions
        'task_default_queue': 'default',
        'task_queues': (
            Queue('email_sending', routing_key='email_sending'),
            Queue('batch_processing', routing_key='batch_processing'),
            Queue('campaign_management', routing_key='campaign_management'),
            Queue('analytics', routing_key='analytics'),
            Queue('default', routing_key='default'),
        ),
        
        # Monitoring
        'worker_send_task_events': True,
        'task_send_sent_event': True,
        'worker_hijack_root_logger': False,
        
        # Error handling
        'task_reject_on_worker_lost': True,
        'task_ignore_result': False,
    }
    
    # Update Celery app configuration
    celery_app.conf.update(celery_config)
    
    # Configure Celery to work with Flask context
    class ContextTask(celery_app.Task):
        """Make celery tasks work with Flask app context"""
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)
    
    celery_app.Task = ContextTask
    
    app.logger.info("Celery configured with Redis broker")
    return celery_app


def configure_security(app: Flask, redis_clients: Dict[str, redis.Redis]) -> tuple:
    """
    Configure comprehensive security features
    
    Returns:
        Tuple of (SecurityManager, CSRFProtect, Limiter)
    """
    # Initialize security manager
    security_manager = init_security_manager(app, redis_clients['rate_limit'])
    
    # Configure CSRF protection
    csrf = CSRFProtect()
    csrf.init_app(app)
    
    # Configure rate limiting
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        storage_uri=f"redis://{app.config.get('REDIS_HOST', 'localhost')}:{app.config.get('REDIS_PORT', 6379)}/3",
        default_limits=["1000 per hour", "100 per minute"],
        headers_enabled=True
    )
    
    # Configure CORS for API endpoints
    CORS(app, 
         origins=app.config.get('CORS_ORIGINS', ['http://localhost:3000']),
         supports_credentials=True,
         allow_headers=['Content-Type', 'Authorization', 'X-CSRF-Token'])
    
    app.logger.info("Security features configured")
    return security_manager, csrf, limiter


def register_blueprints(app: Flask) -> None:
    """
    Register all application blueprints with proper URL prefixes
    """
    # Authentication API
    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    
    # Analytics API  
    app.register_blueprint(analytics_bp, url_prefix='/api/analytics')
    
    # Additional blueprints will be registered here as they're created
    # app.register_blueprint(campaigns_bp, url_prefix='/api/campaigns')
    # app.register_blueprint(templates_bp, url_prefix='/api/templates')
    # app.register_blueprint(lists_bp, url_prefix='/api/lists')
    
    app.logger.info("Application blueprints registered")


def configure_error_handlers(app: Flask) -> None:
    """
    Configure comprehensive error handling with custom error pages
    """
    @app.errorhandler(400)
    def bad_request(error):
        app.logger.warning(f"Bad request from {request.remote_addr}: {error}")
        return jsonify({
            'error': 'Bad Request',
            'message': 'Invalid request format or parameters',
            'status_code': 400
        }), 400
    
    @app.errorhandler(401)
    def unauthorized(error):
        app.logger.warning(f"Unauthorized access attempt from {request.remote_addr}")
        return jsonify({
            'error': 'Unauthorized', 
            'message': 'Authentication required',
            'status_code': 401
        }), 401
    
    @app.errorhandler(403)
    def forbidden(error):
        app.logger.warning(f"Forbidden access attempt from {request.remote_addr}")
        return jsonify({
            'error': 'Forbidden',
            'message': 'Insufficient permissions',
            'status_code': 403
        }), 403
    
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({
            'error': 'Not Found',
            'message': 'The requested resource was not found',
            'status_code': 404
        }), 404
    
    @app.errorhandler(429)
    def rate_limit_exceeded(error):
        app.logger.warning(f"Rate limit exceeded for {request.remote_addr}")
        return jsonify({
            'error': 'Rate Limit Exceeded',
            'message': 'Too many requests. Please try again later.',
            'status_code': 429,
            'retry_after': error.retry_after if hasattr(error, 'retry_after') else 60
        }), 429
    
    @app.errorhandler(500)
    def internal_error(error):
        app.logger.error(f"Internal server error: {error}", exc_info=True)
        return jsonify({
            'error': 'Internal Server Error',
            'message': 'An unexpected error occurred',
            'status_code': 500
        }), 500
    
    @app.errorhandler(Exception)
    def handle_exception(e):
        """Handle unexpected exceptions"""
        if isinstance(e, HTTPException):
            return e
            
        app.logger.error(f"Unhandled exception: {e}", exc_info=True)
        return jsonify({
            'error': 'Internal Server Error',
            'message': 'An unexpected error occurred',
            'status_code': 500
        }), 500


def configure_health_checks(app: Flask, db: SQLAlchemy, redis_clients: Dict[str, redis.Redis]) -> None:
    """
    Configure health check endpoints for monitoring and load balancing
    """
    @app.route('/health')
    def health_check():
        """Basic health check endpoint"""
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'version': app.config.get('VERSION', '1.0.0')
        })
    
    @app.route('/health/detailed')
    def detailed_health_check():
        """Detailed health check with component status"""
        health_status = {
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'components': {}
        }
        
        # Check database connectivity
        try:
            db.session.execute('SELECT 1')
            health_status['components']['database'] = 'healthy'
        except Exception as e:
            health_status['components']['database'] = f'unhealthy: {str(e)}'
            health_status['status'] = 'unhealthy'
        
        # Check Redis connectivity
        for name, client in redis_clients.items():
            try:
                client.ping()
                health_status['components'][f'redis_{name}'] = 'healthy'
            except Exception as e:
                health_status['components'][f'redis_{name}'] = f'unhealthy: {str(e)}'
                health_status['status'] = 'unhealthy'
        
        # Check Celery worker availability
        try:
            celery_inspect = celery_app.control.inspect()
            active_workers = celery_inspect.active()
            if active_workers:
                health_status['components']['celery_workers'] = f'healthy ({len(active_workers)} workers)'
            else:
                health_status['components']['celery_workers'] = 'no workers available'
                health_status['status'] = 'degraded'
        except Exception as e:
            health_status['components']['celery_workers'] = f'unhealthy: {str(e)}'
            health_status['status'] = 'unhealthy'
        
        status_code = 200 if health_status['status'] == 'healthy' else 503
        return jsonify(health_status), status_code
    
    @app.route('/metrics')
    def metrics():
        """Prometheus-compatible metrics endpoint"""
        # This would integrate with your monitoring service
        # For now, return basic application metrics
        return jsonify({
            'http_requests_total': request.environ.get('REQUEST_COUNT', 0),
            'active_sessions': len(session) if session else 0,
            'uptime_seconds': (datetime.utcnow() - app.config.get('START_TIME', datetime.utcnow())).total_seconds()
        })


def configure_request_middleware(app: Flask, security_manager: SecurityManager) -> None:
    """
    Configure request/response middleware for security and monitoring
    """
    @app.before_request
    def before_request():
        """Execute before each request"""
        # Store request start time for performance monitoring
        g.start_time = datetime.utcnow()
        
        # Security logging for sensitive endpoints
        if request.endpoint and any(sensitive in request.endpoint for sensitive in ['auth', 'admin', 'config']):
            app.logger.info(f"Sensitive endpoint access: {request.endpoint} from {request.remote_addr}")
        
        # Session timeout check
        if 'user_id' in session:
            last_activity = session.get('last_activity')
            if last_activity:
                last_activity = datetime.fromisoformat(last_activity)
                if datetime.utcnow() - last_activity > timedelta(hours=8):
                    session.clear()
                    app.logger.info(f"Session expired for user {session.get('user_id')}")
    
    @app.after_request
    def after_request(response):
        """Execute after each request"""
        # Add security headers
        response = security_headers(response)
        
        # Log request performance
        if hasattr(g, 'start_time'):
            duration = (datetime.utcnow() - g.start_time).total_seconds() * 1000
            if duration > app.config.get('SLOW_REQUEST_THRESHOLD', 1000):
                app.logger.warning(f"Slow request ({duration:.0f}ms): {request.method} {request.path}")
        
        # Update session activity
        if 'user_id' in session:
            session['last_activity'] = datetime.utcnow().isoformat()
        
        return response


def create_app(config_name: str = None) -> Flask:
    """
    Flask application factory with comprehensive production configuration
    
    Args:
        config_name: Configuration environment ('development', 'testing', 'production')
        
    Returns:
        Configured Flask application instance
    """
    # Create Flask application
    app = Flask(__name__, 
                instance_relative_config=True,
                static_folder='static',
                template_folder='templates')
    
    # Store application start time for metrics
    app.config['START_TIME'] = datetime.utcnow()
    
    # Load configuration based on environment
    config_name = config_name or os.environ.get('FLASK_ENV', 'production')
    
    if config_name == 'development':
        app.config.from_object('config.DevelopmentConfig')
    elif config_name == 'testing':
        app.config.from_object('config.TestingConfig')  
    else:
        app.config.from_object(FedoraSecurityConfig)
    
    # Override with environment variables
    app.config.update({
        'SECRET_KEY': os.environ.get('SECRET_KEY') or secrets.token_urlsafe(32),
        'DATABASE_URL': os.environ.get('DATABASE_URL') or 'sqlite:///email_sender.db',
        'REDIS_HOST': os.environ.get('REDIS_HOST', 'localhost'),
        'REDIS_PORT': int(os.environ.get('REDIS_PORT', 6379)),
        'CELERY_BROKER_URL': os.environ.get('CELERY_BROKER_URL') or f"redis://localhost:6379/2",
        'VERSION': os.environ.get('APP_VERSION', '1.0.0'),
    })
    
    # Configure proxy handling for production deployment behind nginx
    if config_name == 'production':
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
    
    # Setup logging system
    setup_fedora_logging(app)
    app.logger.info(f"Starting Email Sender application in {config_name} mode")
    
    # Create Redis clients
    redis_clients = create_redis_clients(app)
    app.redis_clients = redis_clients  # Store for access in views
    
    # Configure database
    db = configure_database(app)
    app.db = db
    
    # Configure database migrations
    migrate = Migrate(app, db)
    
    # Configure Celery
    celery = configure_celery(app, redis_clients)
    app.celery = celery
    
    # Configure security features
    security_manager, csrf, limiter = configure_security(app, redis_clients)
    app.security_manager = security_manager
    app.csrf = csrf
    app.limiter = limiter
    
    # Configure SocketIO for real-time features
    socketio = init_socketio(app)
    app.socketio = socketio
    
    # Register application blueprints
    register_blueprints(app)
    
    # Configure error handling
    configure_error_handlers(app)
    
    # Configure health checks
    configure_health_checks(app, db, redis_clients)
    
    # Configure request middleware
    configure_request_middleware(app, security_manager)
    
    # Initialize analytics service
    app.analytics = analytics_service
    
    # Create database tables (in production, use migrations instead)
    with app.app_context():
        if config_name == 'development':
            db.create_all()
            app.logger.info("Database tables created (development mode)")
    
    # Setup graceful shutdown handling
    def shutdown_handler(signum, frame):
        app.logger.info("Received shutdown signal, cleaning up...")
        # Close Redis connections
        for client in redis_clients.values():
            try:
                client.close()
            except:
                pass
        # Close database connections
        db.session.close()
        app.logger.info("Cleanup completed")
    
    signal.signal(signal.SIGTERM, shutdown_handler)
    signal.signal(signal.SIGINT, shutdown_handler)
    atexit.register(lambda: shutdown_handler(None, None))
    
    app.logger.info("Flask application factory completed successfully")
    return app


# Production WSGI application
application = create_app()

if __name__ == '__main__':
    # Development server
    app = create_app('development')
    
    # Run with SocketIO support
    app.socketio.run(
        app,
        host='0.0.0.0',
        port=5000,
        debug=True,
        use_reloader=True
    )

