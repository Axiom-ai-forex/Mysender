# smtp_validator.py
"""
Secure SMTP Validation Module for Fedora 41
Implements comprehensive SMTP profile validation with modern security checks
Based on RFC 5321, RFC 3207 (STARTTLS), and current security best practices
"""

import asyncio
import aiosmtplib
import socket
import ssl
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import dns.resolver
from email.utils import parseaddr
from cryptography.fernet import Fernet
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import logging
from datetime import datetime, timedelta
import re

# Configure logging for systemd journal integration on Fedora 41
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class TLSVersion(Enum):
    """Supported TLS versions based on modern security standards"""
    TLS_1_0 = ssl.TLSVersion.TLSv1
    TLS_1_1 = ssl.TLSVersion.TLSv1_1
    TLS_1_2 = ssl.TLSVersion.TLSv1_2
    TLS_1_3 = ssl.TLSVersion.TLSv1_3


class SecurityLevel(Enum):
    """Security assessment levels"""
    EXCELLENT = "excellent"
    GOOD = "good"
    ACCEPTABLE = "acceptable"
    WEAK = "weak"
    INSECURE = "insecure"


@dataclass
class MXRecordInfo:
    """MX record validation results"""
    priority: int
    hostname: str
    ip_addresses: List[str]
    is_reachable: bool


@dataclass
class TLSSecurityInfo:
    """TLS/SSL security analysis results"""
    supported: bool
    version: Optional[str]
    cipher_suite: Optional[str]
    certificate_valid: bool
    certificate_expiry: Optional[datetime]
    security_level: SecurityLevel
    vulnerabilities: List[str]


@dataclass
class AuthenticationInfo:
    """SMTP authentication capabilities"""
    methods_supported: List[str]
    requires_auth: bool
    auth_successful: bool
    recommended_method: Optional[str]


@dataclass
class RateLimitInfo:
    """Rate limiting detection results"""
    detected: bool
    max_recipients_per_message: Optional[int]
    max_messages_per_connection: Optional[int]
    recommended_rate: float  # emails per second


@dataclass
class ValidationResult:
    """Complete SMTP profile validation result"""
    status: str
    mx_validation: Dict
    connection_test: Dict
    tls_security: Dict
    authentication: Dict
    rate_limits: Dict
    recommendations: List[str]
    security_score: int  # 0-100
    timestamp: datetime


class SecureSMTPValidator:
    """
    Comprehensive SMTP validation with security-first approach
    Validates SMTP profiles for email sending campaigns on Fedora 41
    """
    
    # Weak cipher suites to flag (based on IETF recommendations)[2]
    WEAK_CIPHERS = [
        'RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT', 'anon'
    ]
    
    # Minimum acceptable TLS version
    MIN_TLS_VERSION = TLSVersion.TLS_1_2
    
    # SMTP authentication methods ranked by security
    AUTH_METHODS_SECURITY = {
        'XOAUTH2': 5,      # OAuth2 - most secure
        'OAUTHBEARER': 5,
        'CRAM-MD5': 4,
        'DIGEST-MD5': 4,
        'LOGIN': 2,        # Base64 encoded, not encrypted
        'PLAIN': 1         # Least secure
    }
    
    def __init__(self, encryption_key: str):
        """
        Initialize validator with encryption for sensitive data
        
        Args:
            encryption_key: Fernet encryption key for storing credentials
        """
        self.cipher = Fernet(encryption_key.encode())
        self.dns_resolver = dns.resolver.Resolver()
        # Use Fedora 41's systemd-resolved
        self.dns_resolver.nameservers = ['127.0.0.53']
        
    async def validate_smtp_profile(self, profile: dict) -> ValidationResult:
        """
        Comprehensive SMTP validation with security analysis
        
        Args:
            profile: Dict containing SMTP configuration
                {
                    'host': 'smtp.example.com',
                    'port': 587,
                    'username': 'user@example.com',
                    'password': 'encrypted_password',
                    'use_tls': True,
                    'from_address': 'sender@example.com'
                }
        
        Returns:
            ValidationResult with complete analysis
        """
        results = {
            'status': 'unknown',
            'tests': {},
            'recommendations': [],
            'security_score': 0
        }
        
        logger.info(f"Starting validation for SMTP host: {profile['host']}")
        
        try:
            # 1. DNS/MX Record Validation
            logger.info("Step 1: Validating MX records...")
            mx_records = await self._check_mx_records(profile['host'])
            results['tests']['mx_records'] = mx_records
            
            # 2. Connection Test
            logger.info("Step 2: Testing SMTP connection...")
            conn_test = await self._test_connection(profile)
            results['tests']['connection'] = conn_test
            
            # 3. TLS/Security Test (critical for modern email)[2][9]
            logger.info("Step 3: Analyzing TLS security...")
            tls_test = await self._test_tls_security(profile)
            results['tests']['tls_security'] = tls_test
            
            # 4. Authentication Test
            logger.info("Step 4: Validating authentication...")
            auth_test = await self._test_authentication(profile)
            results['tests']['authentication'] = auth_test
            
            # 5. Rate Limit Detection
            logger.info("Step 5: Detecting rate limits...")
            rate_test = await self._test_rate_limits(profile)
            results['tests']['rate_limits'] = rate_test
            
            # 6. Security Score Calculation
            security_score = self._calculate_security_score(results['tests'])
            results['security_score'] = security_score
            
            # 7. Generate Recommendations
            recommendations = self._generate_recommendations(
                results['tests'], 
                security_score
            )
            results['recommendations'] = recommendations
            
            # Determine overall status
            all_passed = all(
                test.get('passed', False) 
                for test in results['tests'].values()
            )
            results['status'] = 'valid' if all_passed else 'invalid'
            
            logger.info(f"Validation complete. Status: {results['status']}, "
                       f"Security Score: {security_score}/100")
            
        except Exception as e:
            logger.error(f"Validation error: {str(e)}", exc_info=True)
            results['status'] = 'error'
            results['error'] = str(e)
            results['recommendations'].append({
                'severity': 'critical',
                'message': f'Validation failed: {str(e)}',
                'action': 'Check SMTP configuration and network connectivity'
            })
        
        return ValidationResult(
            status=results['status'],
            mx_validation=results['tests'].get('mx_records', {}),
            connection_test=results['tests'].get('connection', {}),
            tls_security=results['tests'].get('tls_security', {}),
            authentication=results['tests'].get('authentication', {}),
            rate_limits=results['tests'].get('rate_limits', {}),
            recommendations=results['recommendations'],
            security_score=results['security_score'],
            timestamp=datetime.utcnow()
        )
    
    async def _check_mx_records(self, host: str) -> Dict:
        """
        Verify MX records with comprehensive DNS validation
        """
        try:
            # Extract domain from potential FQDN
            domain = host.split('@')[-1] if '@' in host else host
            
            # Query MX records
            mx_records = []
            try:
                answers = self.dns_resolver.resolve(domain, 'MX')
                for rdata in answers:
                    mx_info = {
                        'priority': rdata.preference,
                        'hostname': str(rdata.exchange).rstrip('.'),
                        'ip_addresses': []
                    }
                    
                    # Resolve MX hostname to IP addresses
                    try:
                        a_records = self.dns_resolver.resolve(
                            mx_info['hostname'], 
                            'A'
                        )
                        mx_info['ip_addresses'] = [str(r) for r in a_records]
                    except Exception:
                        pass
                    
                    mx_records.append(mx_info)
                
                # Sort by priority (lower is higher priority)
                mx_records.sort(key=lambda x: x['priority'])
                
            except dns.resolver.NXDOMAIN:
                return {
                    'passed': False,
                    'error': 'Domain does not exist (NXDOMAIN)',
                    'records': []
                }
            except dns.resolver.NoAnswer:
                # No MX records, try A record as fallback
                try:
                    a_records = self.dns_resolver.resolve(domain, 'A')
                    mx_records = [{
                        'priority': 0,
                        'hostname': domain,
                        'ip_addresses': [str(r) for r in a_records]
                    }]
                except Exception:
                    return {
                        'passed': False,
                        'error': 'No MX or A records found',
                        'records': []
                    }
            
            # Verify at least one MX record has IP addresses
            has_valid_records = any(
                len(mx['ip_addresses']) > 0 for mx in mx_records
            )
            
            return {
                'passed': has_valid_records and len(mx_records) > 0,
                'records': mx_records,
                'count': len(mx_records),
                'has_backup_mx': len(mx_records) > 1
            }
            
        except Exception as e:
            logger.error(f"MX record check failed: {str(e)}")
            return {
                'passed': False,
                'error': str(e),
                'records': []
            }
    
    async def _test_connection(self, profile: dict) -> Dict:
        """
        Test basic SMTP connection with timeout handling
        """
        try:
            # Create SMTP client with proper configuration
            smtp = aiosmtplib.SMTP(
                hostname=profile['host'],
                port=profile['port'],
                timeout=30,
                use_tls=False  # We'll test STARTTLS separately
            )
            
            # Attempt connection
            await smtp.connect()
            
            # Get server capabilities via EHLO
            response = await smtp.ehlo()
            
            capabilities = []
            if response.message:
                # Parse capabilities from EHLO response
                lines = response.message.decode().split('\n')
                capabilities = [line.strip() for line in lines if line.strip()]
            
            # Close connection cleanly
            await smtp.quit()
            
            return {
                'passed': True,
                'response_code': response.code,
                'capabilities': capabilities,
                'supports_starttls': 'STARTTLS' in ' '.join(capabilities).upper(),
                'supports_auth': 'AUTH' in ' '.join(capabilities).upper(),
                'supports_pipelining': 'PIPELINING' in ' '.join(capabilities).upper(),
                'server_banner': capabilities[0] if capabilities else None
            }
            
        except asyncio.TimeoutError:
            return {
                'passed': False,
                'error': 'Connection timeout after 30 seconds',
                'error_type': 'timeout'
            }
        except ConnectionRefusedError:
            return {
                'passed': False,
                'error': f'Connection refused on port {profile["port"]}',
                'error_type': 'refused'
            }
        except Exception as e:
            return {
                'passed': False,
                'error': str(e),
                'error_type': 'connection_error'
            }
    
    async def _test_tls_security(self, profile: dict) -> Dict:
        """
        Comprehensive TLS security analysis
        Based on modern email security standards[2][9][10]
        """
        try:
            # Create SSL context with security checks
            context = ssl.create_default_context()
            
            # Test STARTTLS capability
            smtp = aiosmtplib.SMTP(
                hostname=profile['host'],
                port=profile['port'],
                timeout=30
            )
            
            await smtp.connect()
            
            # Check if STARTTLS is supported
            ehlo_response = await smtp.ehlo()
            capabilities = ehlo_response.message.decode().upper()
            
            if 'STARTTLS' not in capabilities:
                await smtp.quit()
                return {
                    'passed': False,
                    'error': 'STARTTLS not supported',
                    'security_level': SecurityLevel.INSECURE.value,
                    'vulnerabilities': ['No encryption support']
                }
            
            # Attempt STARTTLS
            try:
                await smtp.starttls(validate_certs=True)
            except Exception as e:
                await smtp.quit()
                return {
                    'passed': False,
                    'error': f'STARTTLS failed: {str(e)}',
                    'security_level': SecurityLevel.INSECURE.value,
                    'vulnerabilities': ['STARTTLS negotiation failed']
                }
            
            # Get TLS connection info
            tls_info = smtp.transport.get_extra_info('ssl_object')
            
            if tls_info:
                tls_version = tls_info.version()
                cipher = tls_info.cipher()
                
                # Get certificate information
                cert_der = tls_info.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(
                    cert_der, 
                    default_backend()
                )
                
                # Analyze certificate
                cert_valid = True
                cert_expiry = cert.not_valid_after
                cert_issues = []
                
                # Check certificate expiration
                days_until_expiry = (cert_expiry - datetime.utcnow()).days
                if days_until_expiry < 0:
                    cert_valid = False
                    cert_issues.append('Certificate expired')
                elif days_until_expiry < 30:
                    cert_issues.append(f'Certificate expires in {days_until_expiry} days')
                
                # Check TLS version
                vulnerabilities = []
                security_level = SecurityLevel.EXCELLENT
                
                if tls_version in ['TLSv1', 'TLSv1.1']:
                    vulnerabilities.append(f'Outdated TLS version: {tls_version}')
                    security_level = SecurityLevel.WEAK
                elif tls_version == 'TLSv1.2':
                    security_level = SecurityLevel.GOOD
                elif tls_version == 'TLSv1.3':
                    security_level = SecurityLevel.EXCELLENT
                
                # Check cipher suite
                if cipher:
                    cipher_name = cipher[0]
                    for weak in self.WEAK_CIPHERS:
                        if weak in cipher_name:
                            vulnerabilities.append(f'Weak cipher detected: {cipher_name}')
                            security_level = SecurityLevel.WEAK
                
                await smtp.quit()
                
                return {
                    'passed': cert_valid and len(vulnerabilities) == 0,
                    'tls_version': tls_version,
                    'cipher_suite': cipher[0] if cipher else None,
                    'certificate_valid': cert_valid,
                    'certificate_expiry': cert_expiry.isoformat(),
                    'days_until_expiry': days_until_expiry,
                    'certificate_issues': cert_issues,
                    'security_level': security_level.value,
                    'vulnerabilities': vulnerabilities,
                    'supports_tls_1_3': tls_version == 'TLSv1.3'
                }
            else:
                await smtp.quit()
                return {
                    'passed': False,
                    'error': 'Could not retrieve TLS information',
                    'security_level': SecurityLevel.WEAK.value
                }
                
        except Exception as e:
            logger.error(f"TLS security test failed: {str(e)}")
            return {
                'passed': False,
                'error': str(e),
                'security_level': SecurityLevel.INSECURE.value,
                'vulnerabilities': ['TLS test failed']
            }
    
    async def _test_authentication(self, profile: dict) -> Dict:
        """
        Test SMTP authentication with security analysis
        """
        try:
            # Decrypt password for testing
            decrypted_password = self.cipher.decrypt(
                profile['password'].encode()
            ).decode()
            
            smtp = aiosmtplib.SMTP(
                hostname=profile['host'],
                port=profile['port'],
                timeout=30
            )
            
            await smtp.connect()
            await smtp.ehlo()
            
            # Get supported auth methods
            ehlo_response = await smtp.ehlo()
            capabilities = ehlo_response.message.decode()
            
            auth_methods = []
            for line in capabilities.split('\n'):
                if 'AUTH' in line.upper():
                    # Extract auth methods
                    methods = re.findall(r'AUTH\s+(.*)', line, re.IGNORECASE)
                    if methods:
                        auth_methods = methods[0].split()
            
            # Determine recommended auth method
            recommended_method = None
            max_security = 0
            for method in auth_methods:
                security_level = self.AUTH_METHODS_SECURITY.get(
                    method.upper(), 
                    0
                )
                if security_level > max_security:
                    max_security = security_level
                    recommended_method = method
            
            # Enable TLS if supported
            if 'STARTTLS' in capabilities.upper():
                await smtp.starttls()
            
            # Test authentication
            auth_successful = False
            auth_error = None
            try:
                await smtp.login(profile['username'], decrypted_password)
                auth_successful = True
            except aiosmtplib.SMTPAuthenticationError as e:
                auth_error = str(e)
            
            await smtp.quit()
            
            return {
                'passed': auth_successful,
                'methods_supported': auth_methods,
                'recommended_method': recommended_method,
                'requires_auth': len(auth_methods) > 0,
                'auth_successful': auth_successful,
                'auth_error': auth_error,
                'security_assessment': self._assess_auth_security(
                    auth_methods, 
                    profile.get('use_tls', False)
                )
            }
            
        except Exception as e:
            logger.error(f"Authentication test failed: {str(e)}")
            return {
                'passed': False,
                'error': str(e),
                'methods_supported': [],
                'auth_successful': False
            }
    
    async def _test_rate_limits(self, profile: dict) -> Dict:
        """
        Detect rate limiting and connection constraints
        """
        try:
            smtp = aiosmtplib.SMTP(
                hostname=profile['host'],
                port=profile['port'],
                timeout=30
            )
            
            await smtp.connect()
            await smtp.ehlo()
            
            # Parse EHLO response for SIZE extension
            ehlo_response = await smtp.ehlo()
            capabilities = ehlo_response.message.decode()
            
            max_message_size = None
            for line in capabilities.split('\n'):
                if 'SIZE' in line.upper():
                    # Extract size limit
                    size_match = re.search(r'SIZE\s+(\d+)', line, re.IGNORECASE)
                    if size_match:
                        max_message_size = int(size_match.group(1))
            
            await smtp.quit()
            
            # Provide recommended rates based on common provider limits
            recommended_rate = self._calculate_recommended_rate(profile['host'])
            
            return {
                'passed': True,
                'max_message_size': max_message_size,
                'max_message_size_mb': max_message_size / (1024 * 1024) if max_message_size else None,
                'recommended_rate_per_second': recommended_rate,
                'recommended_batch_size': 100,
                'recommended_batch_delay_minutes': 5
            }
            
        except Exception as e:
            logger.error(f"Rate limit test failed: {str(e)}")
            return {
                'passed': False,
                'error': str(e),
                'recommended_rate_per_second': 0.5  # Conservative default
            }
    
    def _assess_auth_security(self, methods: List[str], uses_tls: bool) -> str:
        """
        Assess authentication security level
        """
        if not methods:
            return "No authentication required - INSECURE"
        
        has_oauth = any('OAUTH' in m.upper() for m in methods)
        has_plain = any(m.upper() in ['PLAIN', 'LOGIN'] for m in methods)
        
        if has_oauth:
            return "OAuth2 supported - EXCELLENT"
        elif has_plain and not uses_tls:
            return "Plain-text auth without TLS - INSECURE"
        elif has_plain and uses_tls:
            return "Plain-text auth with TLS - ACCEPTABLE"
        else:
            return "Challenge-response authentication - GOOD"
    
    def _calculate_recommended_rate(self, host: str) -> float:
        """
        Calculate recommended sending rate based on provider
        """
        # Common provider rate limits (conservative estimates)
        provider_limits = {
            'gmail': 0.2,      # ~12 per minute
            'outlook': 0.5,    # ~30 per minute
            'office365': 0.5,
            'yahoo': 0.3,
            'sendgrid': 10.0,
            'mailgun': 10.0,
            'ses.amazonaws': 5.0
        }
        
        host_lower = host.lower()
        for provider, rate in provider_limits.items():
            if provider in host_lower:
                return rate
        
        # Default conservative rate
        return 0.5
    
    def _calculate_security_score(self, tests: Dict) -> int:
        """
        Calculate overall security score (0-100)
        """
        score = 0
        
        # MX Records (10 points)
        if tests.get('mx_records', {}).get('passed'):
            score += 10
        
        # Connection (10 points)
        if tests.get('connection', {}).get('passed'):
            score += 10
        
        # TLS Security (40 points - most important)
        tls = tests.get('tls_security', {})
        if tls.get('passed'):
            score += 20
            security_level = tls.get('security_level', '')
            if security_level == SecurityLevel.EXCELLENT.value:
                score += 20
            elif security_level == SecurityLevel.GOOD.value:
                score += 15
            elif security_level == SecurityLevel.ACCEPTABLE.value:
                score += 10
            elif security_level == SecurityLevel.WEAK.value:
                score += 5
        
        # Authentication (30 points)
        auth = tests.get('authentication', {})
        if auth.get('auth_successful'):
            score += 20
            assessment = auth.get('security_assessment', '')
            if 'EXCELLENT' in assessment:
                score += 10
            elif 'GOOD' in assessment:
                score += 8
            elif 'ACCEPTABLE' in assessment:
                score += 5
        
        # Rate Limits (10 points)
        if tests.get('rate_limits', {}).get('passed'):
            score += 10
        
        return min(score, 100)
    
    def _generate_recommendations(self, tests: Dict, security_score: int) -> List[Dict]:
        """
        Generate actionable security recommendations
        """
        recommendations = []
        
        # Critical security issues
        if security_score < 50:
            recommendations.append({
                'severity': 'critical',
                'category': 'security',
                'message': 'Overall security score is critically low',
                'action': 'Review all security configurations before sending emails'
            })
        
        # TLS recommendations
        tls = tests.get('tls_security', {})
        if not tls.get('passed'):
            recommendations.append({
                'severity': 'critical',
                'category': 'encryption',
                'message': 'TLS/SSL encryption is not properly configured',
                'action': 'Enable STARTTLS and ensure valid certificates'
            })
        elif tls.get('tls_version') in ['TLSv1', 'TLSv1.1']:
            recommendations.append({
                'severity': 'high',
                'category': 'encryption',
                'message': f"Outdated TLS version detected: {tls.get('tls_version')}",
                'action': 'Upgrade to TLS 1.2 or 1.3'
            })
        
        # Certificate warnings
        if tls.get('days_until_expiry', 999) < 30:
            recommendations.append({
                'severity': 'high',
                'category': 'certificate',
                'message': f"SSL certificate expires in {tls.get('days_until_expiry')} days",
                'action': 'Renew SSL certificate immediately'
            })
        
        # Authentication recommendations
        auth = tests.get('authentication', {})
        if not auth.get('auth_successful'):
            recommendations.append({
                'severity': 'critical',
                'category': 'authentication',
                'message': 'SMTP authentication failed',
                'action': 'Verify username and password credentials'
            })
        
        assessment = auth.get('security_assessment', '')
        if 'INSECURE' in assessment:
            recommendations.append({
                'severity': 'critical',
                'category': 'authentication',
                'message': assessment,
                'action': 'Enable TLS and use stronger authentication methods'
            })
        
        # Rate limit recommendations
        rate = tests.get('rate_limits', {})
        if rate.get('recommended_rate_per_second', 0) < 1:
            recommendations.append({
                'severity': 'medium',
                'category': 'performance',
                'message': 'Low recommended sending rate detected',
                'action': f"Limit sending to {rate.get('recommended_rate_per_second')} emails/second"
            })
        
        # MX record warnings
        mx = tests.get('mx_records', {})
        if not mx.get('has_backup_mx'):
            recommendations.append({
                'severity': 'low',
                'category': 'reliability',
                'message': 'No backup MX records configured',
                'action': 'Consider adding backup MX servers for redundancy'
            })
        
        return recommendations


# Fedora 41 Integration Utilities
class Fedora41SMTPConfig:
    """
    Fedora 41 specific SMTP configuration and system integration
    """
    
    @staticmethod
    def get_system_smtp_config() -> Dict:
        """
        Get optimized SMTP configuration for Fedora 41
        """
        return {
            'dns_resolver': '127.0.0.53',  # systemd-resolved
            'log_facility': 'mail',
            'systemd_service': True,
            'selinux_context': 'system_u:system_r:mail_t:s0',
            'capabilities': ['CAP_NET_BIND_SERVICE'],
            'firewall_zones': ['mail', 'trusted'],
            'encryption_required': True,
            'min_tls_version': 'TLSv1.2',
            'max_connections': 100,
            'connection_timeout': 30
        }
    
    @staticmethod
    def setup_systemd_logging():
        """
        Configure logging for systemd journal
        """
        import systemd.journal
        
        handler = systemd.journal.JournalHandler()
        handler.setFormatter(logging.Formatter(
            '[%(levelname)s] %(message)s'
        ))
        logger.addHandler(handler)


# Usage Example
async def main():
    """
    Example usage of SecureSMTPValidator
    """
    # Generate encryption key (store securely in production)
    encryption_key = Fernet.generate_key().decode()
    
    # Initialize validator
    validator = SecureSMTPValidator(encryption_key)
    
    # Encrypt password
    cipher = Fernet(encryption_key.encode())
    encrypted_password = cipher.encrypt(b'your_password').decode()
    
    # Test SMTP profile
    profile = {
        'host': 'smtp.gmail.com',
        'port': 587,
        'username': 'your_email@gmail.com',
        'password': encrypted_password,
        'use_tls': True,
        'from_address': 'your_email@gmail.com'
    }
    
    # Validate
    result = await validator.validate_smtp_profile(profile)
    
    print(f"Validation Status: {result.status}")
    print(f"Security Score: {result.security_score}/100")
    print("\nRecommendations:")
    for rec in result.recommendations:
        print(f"  [{rec['severity'].upper()}] {rec['message']}")
        print(f"    Action: {rec['action']}\n")


if __name__ == '__main__':
    asyncio.run(main())

