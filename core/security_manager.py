# core/security_manager.py
"""
Comprehensive Security Manager for Email Sender Application
Implements enterprise-grade security features including:
- Data encryption and key management
- Content validation and compliance checking
- Threat detection and prevention
- Audit logging and monitoring
Optimized for Fedora 41 with SELinux integration
"""

import hashlib
import secrets
import hmac
import base64
import re
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass
from enum import Enum
import json
import ipaddress
from urllib.parse import urlparse
from functools import wraps
from flask import session, redirect, url_for, flash
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import pyotp
import qrcode
import redis
from flask import request, session, current_app
import bleach
from email_validator import validate_email, EmailNotValidError

# Configure logging
logger = logging.getLogger(__name__)


class ThreatLevel(Enum):
    """Security threat levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ComplianceStandard(Enum):
    """Supported compliance standards"""
    GDPR = "gdpr"
    CAN_SPAM = "can_spam"
    CASL = "casl"
    PECR = "pecr"


@dataclass
class SecurityViolation:
    """Security violation record"""
    timestamp: datetime
    violation_type: str
    severity: ThreatLevel
    description: str
    source_ip: str
    user_agent: Optional[str]
    details: Dict[str, Any]


@dataclass
class ComplianceIssue:
    """Compliance validation issue"""
    standard: ComplianceStandard
    issue_type: str
    severity: str
    message: str
    recommendation: str
    location: Optional[str] = None


@dataclass
class SecurityAuditLog:
    """Security audit log entry"""
    timestamp: datetime
    event_type: str
    user_id: Optional[str]
    session_id: Optional[str]
    source_ip: str
    resource: str
    action: str
    outcome: str
    details: Dict[str, Any]


class SecurityManager:
    """
    Comprehensive security manager with enterprise features
    """
    
    # Threat detection patterns
    THREAT_PATTERNS = {
        'sql_injection': [
            r"(\bunion\b.*\bselect\b)",
            r"(\bselect\b.*\bfrom\b)",
            r"(\bdrop\b.*\btable\b)",
            r"(\binsert\b.*\binto\b)",
            r"(\bupdate\b.*\bset\b)",
            r"(\bdelete\b.*\bfrom\b)"
        ],
        'xss_attempt': [
            r"<script[^>]*>.*?</script>",
            r"javascript:",
            r"on\w+\s*=",
            r"data:text/html",
            r"vbscript:"
        ],
        'path_traversal': [
            r"\.\./",
            r"\.\.\\",
            r"~/"
        ],
        'command_injection': [
            r"[;&|`$]",
            r"\b(cat|ls|pwd|whoami|id|uname)\b",
            r"\b(rm|mv|cp|chmod|chown)\b"
        ]
    }
    
    # Phishing detection keywords
    PHISHING_INDICATORS = [
        'urgent action required',
        'verify your account immediately',
        'click here now',
        'limited time offer',
        'congratulations you have won',
        'claim your prize',
        'suspended account',
        'security alert',
        'confirm your identity',
        'update payment information'
    ]
    
    # GDPR compliance requirements
    GDPR_REQUIREMENTS = [
        'unsubscribe',
        'opt-out',
        'data protection',
        'privacy policy'
    ]
    
    # CAN-SPAM compliance requirements
    CAN_SPAM_REQUIREMENTS = [
        'physical address',
        'company name',
        'unsubscribe'
    ]
    
    def __init__(self, app=None, redis_client=None):
        """
        Initialize security manager
        
        Args:
            app: Flask application instance
            redis_client: Redis client for caching and rate limiting
        """
        self.app = app
        self.redis_client = redis_client or redis.Redis(host='localhost', port=6379, db=3)
        
        # Initialize encryption
        self.master_key = None
        self.cipher = None
        self._init_encryption()
        
        # Security configuration
        self.max_login_attempts = 5
        self.lockout_duration = timedelta(minutes=15)
        self.session_timeout = timedelta(hours=8)
        self.audit_retention_days = 90
        
        # Rate limiting configuration
        self.rate_limits = {
            'login': (5, 60),      # 5 attempts per minute
            'api': (100, 60),      # 100 requests per minute
            'email_send': (50, 60) # 50 emails per minute
        }
        
        # Initialize threat detection
        self._compile_threat_patterns()
        
        logger.info("SecurityManager initialized")
    
    def _init_encryption(self):
        """Initialize encryption system with key derivation"""
        try:
            # Get or generate master key
            master_key = self._get_or_generate_master_key()
            
            # Derive Fernet key from master key
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b'email_sender_salt',  # Use secure salt in production
                iterations=100000,
                backend=default_backend()
            )
            
            key = base64.urlsafe_b64encode(kdf.derive(master_key.encode()))
            self.cipher = Fernet(key)
            
            logger.info("Encryption system initialized")
            
        except Exception as e:
            logger.error(f"Encryption initialization failed: {str(e)}")
            raise
    
    def _get_or_generate_master_key(self) -> str:
        """Get or generate master encryption key"""
        if self.app and 'ENCRYPTION_KEY' in self.app.config:
            return self.app.config['ENCRYPTION_KEY']
        
        # Generate new key (store securely in production)
        master_key = secrets.token_urlsafe(32)
        logger.warning("Generated new master key - ensure it's stored securely")
        return master_key
    
    def _compile_threat_patterns(self):
        """Compile regex patterns for threat detection"""
        self.compiled_patterns = {}
        for threat_type, patterns in self.THREAT_PATTERNS.items():
            self.compiled_patterns[threat_type] = [
                re.compile(pattern, re.IGNORECASE | re.MULTILINE)
                for pattern in patterns
            ]
    
    def encrypt_sensitive_data(self, data: str) -> str:
        """
        Encrypt sensitive data with authenticated encryption
        
        Args:
            data: Plain text data to encrypt
            
        Returns:
            Base64 encoded encrypted data
        """
        try:
            if not isinstance(data, str):
                data = str(data)
            
            encrypted = self.cipher.encrypt(data.encode('utf-8'))
            return base64.b64encode(encrypted).decode('ascii')
            
        except Exception as e:
            logger.error(f"Encryption failed: {str(e)}")
            raise
    
    def decrypt_sensitive_data(self, encrypted_data: str) -> str:
        """
        Decrypt sensitive data with integrity verification
        
        Args:
            encrypted_data: Base64 encoded encrypted data
            
        Returns:
            Decrypted plain text
        """
        try:
            encrypted_bytes = base64.b64decode(encrypted_data.encode('ascii'))
            decrypted = self.cipher.decrypt(encrypted_bytes)
            return decrypted.decode('utf-8')
            
        except Exception as e:
            logger.error(f"Decryption failed: {str(e)}")
            raise
    
    def hash_password(self, password: str, salt: Optional[str] = None) -> Tuple[str, str]:
        """
        Hash password with secure salt
        
        Args:
            password: Plain text password
            salt: Optional salt (generates new if not provided)
            
        Returns:
            Tuple of (hashed_password, salt)
        """
        if salt is None:
            salt = secrets.token_hex(16)
        
        # Use PBKDF2 with high iteration count
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt.encode(),
            iterations=200000,
            backend=default_backend()
        )
        
        hashed = base64.b64encode(kdf.derive(password.encode())).decode()
        return hashed, salt
    
    def verify_password(self, password: str, hashed_password: str, salt: str) -> bool:
        """
        Verify password against hash
        
        Args:
            password: Plain text password to verify
            hashed_password: Stored password hash
            salt: Password salt
            
        Returns:
            True if password is valid
        """
        try:
            computed_hash, _ = self.hash_password(password, salt)
            return hmac.compare_digest(hashed_password, computed_hash)
        except Exception:
            return False
    
    def generate_2fa_secret(self, user_id: str) -> Tuple[str, str]:
        """
        Generate 2FA secret and QR code URL
        
        Args:
            user_id: User identifier
            
        Returns:
            Tuple of (secret, qr_code_url)
        """
        secret = pyotp.random_base32()
        
        totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=user_id,
            issuer_name="Email Sender Pro"
        )
        
        return secret, totp_uri
    
    def verify_2fa_code(self, secret: str, code: str, window: int = 1) -> bool:
        """
        Verify 2FA TOTP code
        
        Args:
            secret: User's 2FA secret
            code: TOTP code to verify
            window: Time window for code validity
            
        Returns:
            True if code is valid
        """
        try:
            totp = pyotp.TOTP(secret)
            return totp.verify(code, valid_window=window)
        except Exception:
            return False
    
    def validate_email_content(self, content: str, 
                             standards: List[ComplianceStandard] = None) -> Dict[str, Any]:
        """
        Comprehensive email content validation for security and compliance
        
        Args:
            content: Email content to validate
            standards: Compliance standards to check against
            
        Returns:
            Validation result with issues and recommendations
        """
        if standards is None:
            standards = [ComplianceStandard.GDPR, ComplianceStandard.CAN_SPAM]
        
        issues = []
        security_score = 100
        
        # Security validation
        security_issues = self._validate_content_security(content)
        issues.extend(security_issues)
        
        # Compliance validation
        for standard in standards:
            compliance_issues = self._validate_compliance(content, standard)
            issues.extend(compliance_issues)
        
        # Calculate scores
        high_severity_count = len([i for i in issues if i.severity == 'high'])
        medium_severity_count = len([i for i in issues if i.severity == 'medium'])
        
        security_score = max(0, 100 - (high_severity_count * 20) - (medium_severity_count * 10))
        
        # Determine overall validation result
        is_valid = high_severity_count == 0
        
        return {
            'valid': is_valid,
            'security_score': security_score,
            'issues': [self._compliance_issue_to_dict(issue) for issue in issues],
            'recommendations': self._generate_content_recommendations(issues),
            'standards_checked': [s.value for s in standards]
        }
    
    def _validate_content_security(self, content: str) -> List[ComplianceIssue]:
        """Validate content for security threats"""
        issues = []
        
        # Check for phishing indicators
        content_lower = content.lower()
        for indicator in self.PHISHING_INDICATORS:
            if indicator in content_lower:
                issues.append(ComplianceIssue(
                    standard=ComplianceStandard.GDPR,  # Generic standard
                    issue_type='phishing_risk',
                    severity='medium',
                    message=f'Potential phishing indicator: "{indicator}"',
                    recommendation='Remove or rephrase suspicious language'
                ))
        
        # Check for malicious scripts
        for threat_type, patterns in self.compiled_patterns.items():
            for pattern in patterns:
                if pattern.search(content):
                    issues.append(ComplianceIssue(
                        standard=ComplianceStandard.GDPR,
                        issue_type='security_threat',
                        severity='high',
                        message=f'Potential {threat_type} detected',
                        recommendation=f'Remove {threat_type} patterns from content'
                    ))
        
        # Check for suspicious URLs
        urls = re.findall(r'https?://[^\s<>"]+', content)
        for url in urls:
            if self._is_suspicious_url(url):
                issues.append(ComplianceIssue(
                    standard=ComplianceStandard.GDPR,
                    issue_type='suspicious_url',
                    severity='medium',
                    message=f'Suspicious URL detected: {url}',
                    recommendation='Verify URL legitimacy or use URL shortener'
                ))
        
        return issues
    
    def _validate_compliance(self, content: str, 
                           standard: ComplianceStandard) -> List[ComplianceIssue]:
        """Validate content against specific compliance standard"""
        issues = []
        content_lower = content.lower()
        
        if standard == ComplianceStandard.GDPR:
            # Check GDPR requirements
            gdpr_found = any(req in content_lower for req in self.GDPR_REQUIREMENTS)
            if not gdpr_found:
                issues.append(ComplianceIssue(
                    standard=standard,
                    issue_type='missing_unsubscribe',
                    severity='high',
                    message='Missing GDPR-required unsubscribe mechanism',
                    recommendation='Add clear unsubscribe link and privacy policy reference'
                ))
        
        elif standard == ComplianceStandard.CAN_SPAM:
            # Check CAN-SPAM requirements
            missing_requirements = []
            for req in self.CAN_SPAM_REQUIREMENTS:
                if req not in content_lower:
                    missing_requirements.append(req)
            
            if missing_requirements:
                issues.append(ComplianceIssue(
                    standard=standard,
                    issue_type='can_spam_violation',
                    severity='high',
                    message=f'Missing CAN-SPAM requirements: {", ".join(missing_requirements)}',
                    recommendation='Include physical address, company name, and unsubscribe link'
                ))
        
        return issues
    def require_auth(f):
        """Decorator to require authentication"""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash('Please log in to access this page.', 'error')
                return redirect(url_for('auth_routes.login'))
            return f(*args, **kwargs)
        return decorated_function

# Export it so it can be imported
    __all__ = ['SecurityManager', 'require_auth', 'ThreatLevel']

    def _is_suspicious_url(self, url: str) -> bool:
        """Check if URL is potentially suspicious"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            # Check for suspicious TLDs
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.bit']
            if any(domain.endswith(tld) for tld in suspicious_tlds):
                return True
            
            # Check for URL shorteners (might hide destination)
            shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly']
            if any(shortener in domain for shortener in shorteners):
                return True
            
            # Check for suspicious patterns
            if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):  # IP address
                return True
            
            return False
            
        except Exception:
            return True  # If we can't parse it, consider it suspicious
    
    def _compliance_issue_to_dict(self, issue: ComplianceIssue) -> Dict[str, Any]:
        """Convert compliance issue to dictionary"""
        return {
            'standard': issue.standard.value,
            'type': issue.issue_type,
            'severity': issue.severity,
            'message': issue.message,
            'recommendation': issue.recommendation,
            'location': issue.location
        }
    
    def _generate_content_recommendations(self, issues: List[ComplianceIssue]) -> List[str]:
        """Generate actionable recommendations based on issues"""
        recommendations = []
        
        # Group issues by type
        issue_types = set(issue.issue_type for issue in issues)
        
        if 'missing_unsubscribe' in issue_types:
            recommendations.append("Add prominent unsubscribe link in email footer")
        
        if 'phishing_risk' in issue_types:
            recommendations.append("Review language to avoid phishing-like phrases")
        
        if 'security_threat' in issue_types:
            recommendations.append("Remove potentially malicious code patterns")
        
        if 'suspicious_url' in issue_types:
            recommendations.append("Verify all URLs and consider using trusted domains")
        
        if 'can_spam_violation' in issue_types:
            recommendations.append("Include required sender identification information")
        
        return recommendations
    
    def check_rate_limit(self, key: str, limit_type: str = 'api') -> Tuple[bool, Dict[str, Any]]:
        """
        Check rate limit for given key
        
        Args:
            key: Rate limit key (IP, user ID, etc.)
            limit_type: Type of rate limit to check
            
        Returns:
            Tuple of (allowed, limit_info)
        """
        try:
            max_requests, window_seconds = self.rate_limits.get(limit_type, (100, 60))
            
            # Redis key for rate limiting
            redis_key = f"rate_limit:{limit_type}:{key}"
            
            # Get current count
            current = self.redis_client.get(redis_key)
            if current is None:
                current = 0
            else:
                current = int(current)
            
            # Check if limit exceeded
            if current >= max_requests:
                ttl = self.redis_client.ttl(redis_key)
                return False, {
                    'limit': max_requests,
                    'current': current,
                    'reset_in': ttl,
                    'window': window_seconds
                }
            
            # Increment counter
            pipe = self.redis_client.pipeline()
            pipe.incr(redis_key)
            pipe.expire(redis_key, window_seconds)
            pipe.execute()
            
            return True, {
                'limit': max_requests,
                'current': current + 1,
                'remaining': max_requests - current - 1,
                'window': window_seconds
            }
            
        except Exception as e:
            logger.error(f"Rate limit check failed: {str(e)}")
            # Allow request if rate limiting fails
            return True, {}
    
    def detect_threats(self, request_data: Dict[str, Any]) -> List[SecurityViolation]:
        """
        Detect security threats in request data
        
        Args:
            request_data: Request data to analyze
            
        Returns:
            List of detected security violations
        """
        violations = []
        
        # Analyze each field in request data
        for field_name, field_value in request_data.items():
            if isinstance(field_value, str):
                field_violations = self._analyze_field_for_threats(
                    field_name, 
                    field_value, 
                    request.remote_addr,
                    request.headers.get('User-Agent')
                )
                violations.extend(field_violations)
        
        return violations
    
    def _analyze_field_for_threats(self, field_name: str, field_value: str,
                                 source_ip: str, user_agent: str) -> List[SecurityViolation]:
        """Analyze individual field for security threats"""
        violations = []
        
        for threat_type, patterns in self.compiled_patterns.items():
            for pattern in patterns:
                if pattern.search(field_value):
                    violations.append(SecurityViolation(
                        timestamp=datetime.utcnow(),
                        violation_type=threat_type,
                        severity=ThreatLevel.HIGH,
                        description=f'{threat_type} detected in field "{field_name}"',
                        source_ip=source_ip,
                        user_agent=user_agent,
                        details={
                            'field': field_name,
                            'pattern': pattern.pattern,
                            'value_excerpt': field_value[:100] + '...' if len(field_value) > 100 else field_value
                        }
                    ))
        
        return violations
    
    def log_security_event(self, event_type: str, details: Dict[str, Any] = None):
        """
        Log security event for audit trail
        
        Args:
            event_type: Type of security event
            details: Additional event details
        """
        try:
            log_entry = SecurityAuditLog(
                timestamp=datetime.utcnow(),
                event_type=event_type,
                user_id=session.get('user_id'),
                session_id=session.get('session_id'),
                source_ip=request.remote_addr if request else 'system',
                resource=request.endpoint if request else 'system',
                action=request.method if request else 'system',
                outcome='logged',
                details=details or {}
            )
            
            # Store in Redis for immediate access
            log_key = f"audit_log:{datetime.utcnow().isoformat()}"
            self.redis_client.setex(
                log_key, 
                86400 * self.audit_retention_days,  # Retain for configured days
                json.dumps(self._audit_log_to_dict(log_entry))
            )
            
            logger.info(f"Security event logged: {event_type}")
            
        except Exception as e:
            logger.error(f"Failed to log security event: {str(e)}")
    
    def _audit_log_to_dict(self, log_entry: SecurityAuditLog) -> Dict[str, Any]:
        """Convert audit log entry to dictionary"""
        return {
            'timestamp': log_entry.timestamp.isoformat(),
            'event_type': log_entry.event_type,
            'user_id': log_entry.user_id,
            'session_id': log_entry.session_id,
            'source_ip': log_entry.source_ip,
            'resource': log_entry.resource,
            'action': log_entry.action,
            'outcome': log_entry.outcome,
            'details': log_entry.details
        }
    
    def get_security_metrics(self, hours: int = 24) -> Dict[str, Any]:
        """
        Get security metrics for dashboard
        
        Args:
            hours: Number of hours to analyze
            
        Returns:
            Security metrics dictionary
        """
        try:
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(hours=hours)
            
            # Get audit logs from Redis
            log_keys = self.redis_client.keys(f"audit_log:*")
            
            # Filter logs by timeframe
            relevant_logs = []
            for key in log_keys:
                log_data = self.redis_client.get(key)
                if log_data:
                    try:
                        log_entry = json.loads(log_data)
                        log_time = datetime.fromisoformat(log_entry['timestamp'])
                        if start_time <= log_time <= end_time:
                            relevant_logs.append(log_entry)
                    except Exception:
                        continue
            
            # Analyze logs
            total_events = len(relevant_logs)
            event_types = {}
            threat_levels = {}
            source_ips = set()
            
            for log in relevant_logs:
                # Count event types
                event_type = log.get('event_type', 'unknown')
                event_types[event_type] = event_types.get(event_type, 0) + 1
                
                # Track unique IPs
                if log.get('source_ip'):
                    source_ips.add(log['source_ip'])
            
            return {
                'timeframe_hours': hours,
                'total_events': total_events,
                'unique_ips': len(source_ips),
                'event_types': event_types,
                'top_event_types': sorted(event_types.items(), key=lambda x: x[1], reverse=True)[:5],
                'events_per_hour': total_events / hours if hours > 0 else 0
            }
            
        except Exception as e:
            logger.error(f"Failed to get security metrics: {str(e)}")
            return {'error': str(e)}


# Fedora 41 SELinux Integration
class SELinuxSecurityManager:
    """
    SELinux-specific security management for Fedora 41
    """
    
    @staticmethod
    def check_selinux_context():
        """Check if running in correct SELinux context"""
        try:
            import selinux
            if selinux.is_selinux_enabled():
                context = selinux.getcon()
                logger.info(f"Running in SELinux context: {context}")
                return True
        except ImportError:
            logger.warning("SELinux module not available")
        return False
    
    @staticmethod
    def set_file_security_context(filepath: str, context: str):
        """Set SELinux security context for files"""
        try:
            import selinux
            selinux.setfilecon(filepath, context)
            logger.info(f"Set SELinux context for {filepath}: {context}")
        except Exception as e:
            logger.error(f"Failed to set SELinux context: {str(e)}")


# Global security manager instance
security_manager = None

def init_security_manager(app, redis_client=None):
    """Initialize global security manager"""
    global security_manager
    security_manager = SecurityManager(app, redis_client)
    return security_manager

