# Enhanced SMTP response code categorization based on RFC 5321 & RFC 5248
# Built for Fedora 41 Python 3.12+ environment

import re
import logging
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple, Union
from enum import Enum

class ResponseCategory(Enum):
    """SMTP Response Categories based on RFC 5321"""
    SUCCESS = "success"
    TEMP_FAIL = "temp_fail" 
    PERM_FAIL = "perm_fail"
    UNKNOWN = "unknown"

class ActionType(Enum):
    """Actions to take based on SMTP response codes"""
    CONTINUE = "continue"
    DISCONNECT = "disconnect"
    RETRY_LATER = "retry_later"
    BOUNCE = "bounce"
    RETRY_ALT_MX = "retry_alt_mx"
    DEFER = "defer"

@dataclass
class SMTPResponseCode:
    """RFC 5321 compliant SMTP response code definition"""
    code: str
    category: ResponseCategory
    action: ActionType
    description: str
    enhanced_status: Optional[str] = None
    retry_after: Optional[int] = None  # seconds
    max_retries: int = 3
    is_final: bool = False

# Comprehensive SMTP response codes based on RFC 5321, RFC 5248, and real-world usage
SMTP_CODES: Dict[str, SMTPResponseCode] = {
    # 2xx Success codes (RFC 5321 Section 4.2.1)
    '200': SMTPResponseCode('200', ResponseCategory.SUCCESS, ActionType.CONTINUE, 
                           'System status, or system help reply', '2.0.0'),
    '211': SMTPResponseCode('211', ResponseCategory.SUCCESS, ActionType.CONTINUE,
                           'System status, or system help reply', '2.0.0'),
    '214': SMTPResponseCode('214', ResponseCategory.SUCCESS, ActionType.CONTINUE,
                           'Help message', '2.0.0'),
    '220': SMTPResponseCode('220', ResponseCategory.SUCCESS, ActionType.CONTINUE,
                           'Service ready', '2.0.0'),
    '221': SMTPResponseCode('221', ResponseCategory.SUCCESS, ActionType.DISCONNECT,
                           'Service closing transmission channel', '2.0.0', is_final=True),
    '250': SMTPResponseCode('250', ResponseCategory.SUCCESS, ActionType.CONTINUE,
                           'Requested mail action okay, completed', '2.0.0'),
    '251': SMTPResponseCode('251', ResponseCategory.SUCCESS, ActionType.CONTINUE,
                           'User not local; will forward to path', '2.1.5'),
    '252': SMTPResponseCode('252', ResponseCategory.SUCCESS, ActionType.CONTINUE,
                           'Cannot VRFY user, but will accept message', '2.5.2'),
    
    # 3xx Intermediate codes
    '354': SMTPResponseCode('354', ResponseCategory.SUCCESS, ActionType.CONTINUE,
                           'Start mail input; end with <CRLF>.<CRLF>', '2.0.0'),
    
    # 4xx Temporary failure codes (RFC 5321 Section 4.2.1)
    '421': SMTPResponseCode('421', ResponseCategory.TEMP_FAIL, ActionType.RETRY_LATER,
                           'Service not available, closing transmission channel', 
                           '4.3.2', retry_after=1800, max_retries=5),
    '422': SMTPResponseCode('422', ResponseCategory.TEMP_FAIL, ActionType.RETRY_LATER,
                           'Mailbox full or temporarily over quota', 
                           '4.2.2', retry_after=7200, max_retries=3),
    '431': SMTPResponseCode('431', ResponseCategory.TEMP_FAIL, ActionType.RETRY_LATER,
                           'Not enough disk space on the server',
                           '4.3.1', retry_after=3600, max_retries=3),
    '432': SMTPResponseCode('432', ResponseCategory.TEMP_FAIL, ActionType.RETRY_LATER,
                           'Recipient mailbox is locked or temporarily unavailable',
                           '4.2.1', retry_after=1800, max_retries=4),
    '441': SMTPResponseCode('441', ResponseCategory.TEMP_FAIL, ActionType.RETRY_LATER,
                           'User not local; please try alternate path',
                           '4.1.1', retry_after=900, max_retries=2),
    '442': SMTPResponseCode('442', ResponseCategory.TEMP_FAIL, ActionType.RETRY_LATER,
                           'Connection dropped due to timeout',
                           '4.4.2', retry_after=600, max_retries=3),
    '446': SMTPResponseCode('446', ResponseCategory.TEMP_FAIL, ActionType.RETRY_LATER,
                           'Maximum hop count exceeded',
                           '4.4.6', retry_after=3600, max_retries=1),
    '447': SMTPResponseCode('447', ResponseCategory.TEMP_FAIL, ActionType.RETRY_LATER,
                           'Message timeout',
                           '4.4.7', retry_after=1800, max_retries=2),
    '450': SMTPResponseCode('450', ResponseCategory.TEMP_FAIL, ActionType.RETRY_LATER,
                           'Mailbox unavailable (busy or temporarily blocked)',
                           '4.2.0', retry_after=1800, max_retries=4),
    '451': SMTPResponseCode('451', ResponseCategory.TEMP_FAIL, ActionType.RETRY_LATER,
                           'Local error in processing; try again later',
                           '4.3.0', retry_after=3600, max_retries=3),
    '452': SMTPResponseCode('452', ResponseCategory.TEMP_FAIL, ActionType.RETRY_LATER,
                           'Insufficient system storage',
                           '4.3.1', retry_after=7200, max_retries=2),
    '453': SMTPResponseCode('453', ResponseCategory.TEMP_FAIL, ActionType.RETRY_LATER,
                           'Too many recipients for this session',
                           '4.5.3', retry_after=300, max_retries=3),
    '454': SMTPResponseCode('454', ResponseCategory.TEMP_FAIL, ActionType.RETRY_LATER,
                           'TLS not available due to temporary reason',
                           '4.7.0', retry_after=1800, max_retries=2),
    
    # 5xx Permanent failure codes (RFC 5321 Section 4.2.1)
    '500': SMTPResponseCode('500', ResponseCategory.PERM_FAIL, ActionType.BOUNCE,
                           'Syntax error, command unrecognized', '5.5.2', is_final=True),
    '501': SMTPResponseCode('501', ResponseCategory.PERM_FAIL, ActionType.BOUNCE,
                           'Syntax error in parameters or arguments', '5.5.4', is_final=True),
    '502': SMTPResponseCode('502', ResponseCategory.PERM_FAIL, ActionType.BOUNCE,
                           'Command not implemented', '5.5.1', is_final=True),
    '503': SMTPResponseCode('503', ResponseCategory.PERM_FAIL, ActionType.BOUNCE,
                           'Bad sequence of commands', '5.5.1', is_final=True),
    '504': SMTPResponseCode('504', ResponseCategory.PERM_FAIL, ActionType.BOUNCE,
                           'Command parameter not implemented', '5.5.4', is_final=True),
    '521': SMTPResponseCode('521', ResponseCategory.PERM_FAIL, ActionType.BOUNCE,
                           'Machine does not accept mail', '5.3.2', is_final=True),
    '530': SMTPResponseCode('530', ResponseCategory.PERM_FAIL, ActionType.BOUNCE,
                           'Access denied / Authentication required', '5.7.1', is_final=True),
    '534': SMTPResponseCode('534', ResponseCategory.PERM_FAIL, ActionType.BOUNCE,
                           'Authentication mechanism is too weak', '5.7.9', is_final=True),
    '535': SMTPResponseCode('535', ResponseCategory.PERM_FAIL, ActionType.BOUNCE,
                           'Authentication credentials invalid', '5.7.8', is_final=True),
    '538': SMTPResponseCode('538', ResponseCategory.PERM_FAIL, ActionType.BOUNCE,
                           'Encryption required for requested authentication mechanism',
                           '5.7.11', is_final=True),
    '550': SMTPResponseCode('550', ResponseCategory.PERM_FAIL, ActionType.BOUNCE,
                           'Mailbox unavailable (not found, access denied)', 
                           '5.1.1', is_final=True),
    '551': SMTPResponseCode('551', ResponseCategory.PERM_FAIL, ActionType.BOUNCE,
                           'User not local; please try alternate path', 
                           '5.1.6', is_final=True),
    '552': SMTPResponseCode('552', ResponseCategory.PERM_FAIL, ActionType.BOUNCE,
                           'Exceeded storage allocation', '5.2.2', is_final=True),
    '553': SMTPResponseCode('553', ResponseCategory.PERM_FAIL, ActionType.BOUNCE,
                           'Mailbox name not allowed (invalid address syntax)',
                           '5.1.3', is_final=True),
    '554': SMTPResponseCode('554', ResponseCategory.PERM_FAIL, ActionType.BOUNCE,
                           'Transaction failed (general failure or policy violation)',
                           '5.3.0', is_final=True),
    '555': SMTPResponseCode('555', ResponseCategory.PERM_FAIL, ActionType.BOUNCE,
                           'MAIL FROM/RCPT TO parameters not recognized or not implemented',
                           '5.5.4', is_final=True),
    
    # Modern spam/policy related codes (Common in 2025)
    '571': SMTPResponseCode('571', ResponseCategory.PERM_FAIL, ActionType.BOUNCE,
                           'Blocked due to spam policy', '5.7.1', is_final=True),
    '575': SMTPResponseCode('575', ResponseCategory.PERM_FAIL, ActionType.BOUNCE,
                           'Message content rejected due to policy', '5.7.7', is_final=True),
}

class SMTPResponseAnalyzer:
    """Advanced SMTP response analysis for RFC-compliant email systems"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        # Enhanced status code pattern (RFC 3463)
        self.enhanced_status_pattern = re.compile(r'(\d)\.(\d+)\.(\d+)')
        
    def parse_response(self, smtp_response: str) -> Tuple[str, str, Optional[str]]:
        """
        Parse SMTP response line according to RFC 5321
        Returns: (response_code, message, enhanced_status_code)
        """
        if not smtp_response or len(smtp_response) < 3:
            return ('500', 'Invalid response format', None)
            
        try:
            # Extract basic response code
            response_code = smtp_response[:3]
            message = smtp_response[4:].strip() if len(smtp_response) > 4 else ''
            
            # Extract enhanced status code if present (RFC 3463)
            enhanced_match = self.enhanced_status_pattern.search(message)
            enhanced_code = enhanced_match.group(0) if enhanced_match else None
            
            return (response_code, message, enhanced_code)
            
        except Exception as e:
            self.logger.error(f"Error parsing SMTP response '{smtp_response}': {e}")
            return ('500', 'Response parsing error', None)
    
    def categorize_response(self, response_code: str) -> SMTPResponseCode:
        """
        Categorize SMTP response code according to RFC 5321 standards
        """
        code_info = SMTP_CODES.get(response_code)
        
        if code_info:
            return code_info
        
        # Fallback categorization for unknown codes
        if response_code.startswith('2'):
            return SMTPResponseCode(response_code, ResponseCategory.SUCCESS, 
                                  ActionType.CONTINUE, 'Unknown success code')
        elif response_code.startswith('3'):
            return SMTPResponseCode(response_code, ResponseCategory.SUCCESS,
                                  ActionType.CONTINUE, 'Unknown intermediate code')
        elif response_code.startswith('4'):
            return SMTPResponseCode(response_code, ResponseCategory.TEMP_FAIL,
                                  ActionType.RETRY_LATER, 'Unknown temporary failure',
                                  retry_after=1800, max_retries=3)
        elif response_code.startswith('5'):
            return SMTPResponseCode(response_code, ResponseCategory.PERM_FAIL,
                                  ActionType.BOUNCE, 'Unknown permanent failure',
                                  is_final=True)
        else:
            return SMTPResponseCode(response_code, ResponseCategory.UNKNOWN,
                                  ActionType.BOUNCE, 'Invalid response code format',
                                  is_final=True)
    
    def should_retry(self, response_code: str, attempt_count: int) -> bool:
        """
        Determine if email should be retried based on RFC 5321 guidelines
        """
        code_info = self.categorize_response(response_code)
        
        if code_info.category == ResponseCategory.PERM_FAIL:
            return False
            
        if code_info.category == ResponseCategory.TEMP_FAIL:
            return attempt_count < code_info.max_retries
            
        return False
    
    def get_retry_delay(self, response_code: str, attempt_count: int) -> int:
        """
        Calculate retry delay with exponential backoff (RFC 5321 recommendations)
        """
        code_info = self.categorize_response(response_code)
        base_delay = code_info.retry_after or 1800  # Default 30 minutes
        
        # Exponential backoff: base_delay * (2 ^ (attempt_count - 1))
        # Cap at 24 hours maximum
        delay = min(base_delay * (2 ** (attempt_count - 1)), 86400)
        return delay
    
    def analyze_bounce_reason(self, response_code: str, message: str) -> Dict[str, Union[str, bool]]:
        """
        Analyze bounce reason for detailed categorization and reporting
        """
        code_info = self.categorize_response(response_code)
        message_lower = message.lower()
        
        bounce_analysis = {
            'category': code_info.category.value,
            'subcategory': 'unknown',
            'is_suppression_list': False,
            'is_spam_related': False,
            'is_authentication_issue': False,
            'is_policy_violation': False,
            'is_mailbox_full': False,
            'is_invalid_recipient': False,
            'description': code_info.description,
            'recommended_action': code_info.action.value
        }
        
        # Enhanced categorization based on message content
        if any(keyword in message_lower for keyword in ['spam', 'blocked', 'blacklist', 'reputation']):
            bounce_analysis['is_spam_related'] = True
            bounce_analysis['subcategory'] = 'spam_policy'
            
        elif any(keyword in message_lower for keyword in ['full', 'quota', 'storage']):
            bounce_analysis['is_mailbox_full'] = True
            bounce_analysis['subcategory'] = 'mailbox_full'
            
        elif any(keyword in message_lower for keyword in ['not found', 'unknown', 'invalid', 'does not exist']):
            bounce_analysis['is_invalid_recipient'] = True
            bounce_analysis['subcategory'] = 'invalid_recipient'
            
        elif any(keyword in message_lower for keyword in ['auth', 'login', 'credential', 'password']):
            bounce_analysis['is_authentication_issue'] = True
            bounce_analysis['subcategory'] = 'authentication'
            
        elif any(keyword in message_lower for keyword in ['policy', 'violation', 'prohibited', 'denied']):
            bounce_analysis['is_policy_violation'] = True
            bounce_analysis['subcategory'] = 'policy_violation'
            
        elif any(keyword in message_lower for keyword in ['suppress', 'unsubscrib', 'opt-out', 'bounced']):
            bounce_analysis['is_suppression_list'] = True
            bounce_analysis['subcategory'] = 'suppression_list'
        
        return bounce_analysis

# Integration example for Fedora 41 environment
class Fedora41SMTPHandler:
    """SMTP handler optimized for Fedora 41 with systemd integration"""
    
    def __init__(self):
        self.analyzer = SMTPResponseAnalyzer()
        self.setup_logging()
        
    def setup_logging(self):
        """Configure logging for systemd journal integration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(),  # stdout for systemd
                logging.FileHandler('/var/log/email-sender/smtp.log')
            ]
        )
    
    def handle_smtp_response(self, response: str, email_address: str, 
                           attempt_count: int = 1) -> Dict[str, any]:
        """
        Handle SMTP response with full RFC compliance and logging
        """
        code, message, enhanced_code = self.analyzer.parse_response(response)
        code_info = self.analyzer.categorize_response(code)
        bounce_analysis = self.analyzer.analyze_bounce_reason(code, message)
        
        result = {
            'response_code': code,
            'message': message,
            'enhanced_code': enhanced_code,
            'category': code_info.category.value,
            'action': code_info.action.value,
            'should_retry': self.analyzer.should_retry(code, attempt_count),
            'retry_delay': self.analyzer.get_retry_delay(code, attempt_count),
            'bounce_analysis': bounce_analysis,
            'is_final': code_info.is_final
        }
        
        # Log to systemd journal with structured data
        self.logger.info(
            f"SMTP response for {email_address}: {code} - {message}",
            extra={
                'email_address': email_address,
                'smtp_code': code,
                'enhanced_code': enhanced_code,
                'category': code_info.category.value,
                'attempt': attempt_count
            }
        )
        
        return result

# Fedora 41 specific configuration
def get_fedora41_smtp_config():
    """Get optimized SMTP configuration for Fedora 41"""
    return {
        'dns_resolver': '127.0.0.1',  # systemd-resolved
        'log_facility': 'mail',
        'systemd_service': True,
        'security_context': 'system_u:system_r:mail_t:s0',  # SELinux
        'capabilities': ['CAP_NET_BIND_SERVICE'],  # For port 25/587
        'firewall_zones': ['mail', 'trusted'],
        'encryption_required': True,
        'min_tls_version': '1.2'
    }

