# core/template_engine.py
"""
Secure Template Engine for Email Marketing System
Implements comprehensive XSS protection, HTML sanitization, and email-specific security
Optimized for Fedora 41 with modern Python security practices
"""

import re
import logging
from typing import Dict, List, Optional, Tuple, Set, Any
from dataclasses import dataclass
from enum import Enum
import html
import urllib.parse
from datetime import datetime

from jinja2 import Environment, select_autoescape, StrictUndefined, meta
from jinja2.exceptions import TemplateError, UndefinedError, TemplateSyntaxError
from markupsafe import Markup, escape
import bleach
from bleach.css_sanitizer import CSSSanitizer
import premailer
from bs4 import BeautifulSoup

# Configure logging
logger = logging.getLogger(__name__)


class TemplateSecurityLevel(Enum):
    """Security levels for template processing"""
    STRICT = "strict"      # Maximum security, minimal HTML
    STANDARD = "standard"  # Balanced security for email marketing
    RELAXED = "relaxed"    # More permissive for trusted content


class ContentType(Enum):
    """Supported content types"""
    HTML = "html"
    TEXT = "text"
    MIXED = "mixed"


@dataclass
class SecurityWarning:
    """Security warning information"""
    level: str  # 'low', 'medium', 'high', 'critical'
    category: str
    message: str
    location: Optional[str] = None
    recommendation: Optional[str] = None


@dataclass
class TemplateRenderResult:
    """Result of template rendering operation"""
    html: Optional[str]
    text: Optional[str]
    variables_used: Set[str]
    variables_missing: Set[str]
    security_warnings: List[SecurityWarning]
    inline_css_applied: bool
    size_bytes: int
    render_time_ms: float


class SecureTemplateEngine:
    """
    Production-ready template engine with comprehensive security features
    Designed specifically for email marketing with XSS protection
    """
    
    # Email-safe HTML tags (conservative approach)
    EMAIL_SAFE_TAGS = {
        TemplateSecurityLevel.STRICT: [
            'p', 'br', 'strong', 'em', 'b', 'i', 'u',
            'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
            'ul', 'ol', 'li', 'a', 'img',
            'table', 'thead', 'tbody', 'tr', 'td', 'th',
            'div', 'span', 'hr'
        ],
        TemplateSecurityLevel.STANDARD: [
            'p', 'br', 'strong', 'em', 'b', 'i', 'u', 's', 'sub', 'sup',
            'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
            'ul', 'ol', 'li', 'dl', 'dt', 'dd',
            'a', 'img', 'figure', 'figcaption',
            'table', 'thead', 'tbody', 'tfoot', 'tr', 'td', 'th', 'caption',
            'div', 'span', 'section', 'article', 'header', 'footer',
            'hr', 'blockquote', 'pre', 'code',
            'center'  # Legacy email client support
        ],
        TemplateSecurityLevel.RELAXED: [
            'p', 'br', 'strong', 'em', 'b', 'i', 'u', 's', 'sub', 'sup',
            'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
            'ul', 'ol', 'li', 'dl', 'dt', 'dd',
            'a', 'img', 'figure', 'figcaption',
            'table', 'thead', 'tbody', 'tfoot', 'tr', 'td', 'th', 'caption',
            'div', 'span', 'section', 'article', 'header', 'footer', 'main',
            'hr', 'blockquote', 'pre', 'code', 'kbd', 'samp', 'var',
            'center', 'font', 'nobr'  # Legacy support
        ]
    }
    
    # Safe attributes for email HTML
    EMAIL_SAFE_ATTRIBUTES = {
        '*': ['class', 'id', 'style', 'title', 'dir', 'lang'],
        'a': ['href', 'title', 'rel', 'target'],
        'img': ['src', 'alt', 'width', 'height', 'border', 'align', 'title'],
        'table': ['border', 'cellpadding', 'cellspacing', 'width', 'align', 'bgcolor'],
        'td': ['colspan', 'rowspan', 'width', 'height', 'align', 'valign', 'bgcolor'],
        'th': ['colspan', 'rowspan', 'width', 'height', 'align', 'valign', 'bgcolor'],
        'tr': ['align', 'valign', 'bgcolor'],
        'div': ['align'],
        'p': ['align'],
        'h1': ['align'], 'h2': ['align'], 'h3': ['align'],
        'h4': ['align'], 'h5': ['align'], 'h6': ['align'],
        'font': ['color', 'face', 'size'],  # Legacy support
    }
    
    # Dangerous patterns to detect
    SECURITY_PATTERNS = {
        'javascript': re.compile(r'javascript:', re.IGNORECASE),
        'data_uri': re.compile(r'data:', re.IGNORECASE),
        'vbscript': re.compile(r'vbscript:', re.IGNORECASE),
        'on_events': re.compile(r'\son\w+\s*=', re.IGNORECASE),
        'expression': re.compile(r'expression\s*\(', re.IGNORECASE),
        'import': re.compile(r'@import', re.IGNORECASE),
        'behavior': re.compile(r'behavior\s*:', re.IGNORECASE),
        'binding': re.compile(r'binding\s*:', re.IGNORECASE)
    }
    
    def __init__(self, 
                 security_level: TemplateSecurityLevel = TemplateSecurityLevel.STANDARD,
                 enable_css_inlining: bool = True,
                 max_template_size: int = 1024 * 1024):  # 1MB limit
        """
        Initialize secure template engine
        
        Args:
            security_level: Security level for HTML sanitization
            enable_css_inlining: Whether to inline CSS for email compatibility
            max_template_size: Maximum template size in bytes
        """
        self.security_level = security_level
        self.enable_css_inlining = enable_css_inlining
        self.max_template_size = max_template_size
        
        # Configure Jinja2 environment with security settings
        self.env = Environment(
            autoescape=select_autoescape(['html', 'xml']),
            undefined=StrictUndefined,  # Fail on undefined variables
            trim_blocks=True,
            lstrip_blocks=True,
            cache_size=100  # Limit cache size
        )
        
        # Add custom filters for email-specific formatting
        self.env.filters['url_encode'] = urllib.parse.quote
        self.env.filters['html_escape'] = html.escape
        self.env.filters['email_safe'] = self._email_safe_filter
        
        # Configure CSS sanitizer for inline styles
        self.css_sanitizer = CSSSanitizer(
            allowed_css_properties=[
                'color', 'background-color', 'background',
                'font-family', 'font-size', 'font-weight', 'font-style',
                'text-align', 'text-decoration', 'text-transform',
                'margin', 'margin-top', 'margin-bottom', 'margin-left', 'margin-right',
                'padding', 'padding-top', 'padding-bottom', 'padding-left', 'padding-right',
                'border', 'border-top', 'border-bottom', 'border-left', 'border-right',
                'border-color', 'border-style', 'border-width',
                'width', 'height', 'max-width', 'min-width',
                'display', 'float', 'clear',
                'line-height', 'vertical-align'
            ],
            allowed_svg_properties=[],  # Disable SVG for security
            strip_disallowed=True
        )
        
        # Configure HTML sanitizer
        self._setup_html_sanitizer()
        
        logger.info(f"SecureTemplateEngine initialized with {security_level.value} security level")
    
    def _setup_html_sanitizer(self):
        """Configure bleach HTML sanitizer based on security level"""
        tags = self.EMAIL_SAFE_TAGS[self.security_level]
        attributes = self.EMAIL_SAFE_ATTRIBUTES.copy()
        
        # Create bleach cleaner instance
        self.html_cleaner = bleach.Cleaner(
            tags=tags,
            attributes=attributes,
            css_sanitizer=self.css_sanitizer,
            strip=True,  # Strip disallowed tags instead of escaping
            strip_comments=True  # Remove HTML comments
        )
    
    def render_template(self, 
                       template_content: str, 
                       variables: Dict[str, Any],
                       content_type: ContentType = ContentType.MIXED,
                       sanitize_html: bool = True,
                       apply_inline_css: bool = None) -> TemplateRenderResult:
        """
        Render email template with comprehensive security checks
        
        Args:
            template_content: Jinja2 template string
            variables: Template variables dictionary
            content_type: Type of content to generate
            sanitize_html: Whether to sanitize HTML output
            apply_inline_css: Whether to inline CSS (overrides instance setting)
        
        Returns:
            TemplateRenderResult with rendered content and security analysis
        """
        start_time = datetime.now()
        
        # Input validation
        if not template_content or not isinstance(template_content, str):
            raise ValueError("Template content must be a non-empty string")
        
        if len(template_content.encode('utf-8')) > self.max_template_size:
            raise ValueError(f"Template size exceeds limit of {self.max_template_size} bytes")
        
        # Initialize result
        result = TemplateRenderResult(
            html=None,
            text=None,
            variables_used=set(),
            variables_missing=set(),
            security_warnings=[],
            inline_css_applied=False,
            size_bytes=0,
            render_time_ms=0
        )
        
        try:
            # Parse template to identify variables
            parsed_template = self.env.parse(template_content)
            required_vars = meta.find_undeclared_variables(parsed_template)
            result.variables_used = required_vars
            
            # Check for missing variables
            provided_vars = set(variables.keys())
            result.variables_missing = required_vars - provided_vars
            
            # Security scan of template content
            template_warnings = self._scan_template_security(template_content)
            result.security_warnings.extend(template_warnings)
            
            # Compile and render template
            template = self.env.from_string(template_content)
            rendered_html = template.render(**variables)
            
            # Apply security sanitization
            if sanitize_html and content_type in [ContentType.HTML, ContentType.MIXED]:
                # Pre-sanitization security scan
                pre_warnings = self._scan_html_security(rendered_html)
                result.security_warnings.extend(pre_warnings)
                
                # Sanitize HTML
                rendered_html = self.html_cleaner.clean(rendered_html)
                
                # Post-sanitization verification
                post_warnings = self._scan_html_security(rendered_html)
                result.security_warnings.extend(post_warnings)
            
            # Apply CSS inlining for email compatibility
            inline_css = apply_inline_css if apply_inline_css is not None else self.enable_css_inlining
            if inline_css and rendered_html and content_type in [ContentType.HTML, ContentType.MIXED]:
                try:
                    rendered_html = self._inline_css(rendered_html)
                    result.inline_css_applied = True
                except Exception as e:
                    logger.warning(f"CSS inlining failed: {str(e)}")
                    result.security_warnings.append(SecurityWarning(
                        level='low',
                        category='css',
                        message='CSS inlining failed, email rendering may be inconsistent',
                        recommendation='Check CSS syntax and email client compatibility'
                    ))
            
            # Generate content based on type
            if content_type in [ContentType.HTML, ContentType.MIXED]:
                result.html = rendered_html
            
            if content_type in [ContentType.TEXT, ContentType.MIXED]:
                result.text = self._html_to_text(rendered_html or template_content)
            
            # Calculate final size
            total_size = 0
            if result.html:
                total_size += len(result.html.encode('utf-8'))
            if result.text:
                total_size += len(result.text.encode('utf-8'))
            result.size_bytes = total_size
            
            # Email size warning
            if total_size > 102400:  # 100KB warning threshold
                result.security_warnings.append(SecurityWarning(
                    level='medium',
                    category='performance',
                    message=f'Email size ({total_size:,} bytes) may cause delivery issues',
                    recommendation='Consider reducing content size or splitting into multiple emails'
                ))
            
        except UndefinedError as e:
            raise TemplateError(f"Template variable error: {str(e)}")
        except TemplateSyntaxError as e:
            raise TemplateError(f"Template syntax error: {str(e)}")
        except Exception as e:
            logger.error(f"Template rendering failed: {str(e)}")
            raise TemplateError(f"Template rendering failed: {str(e)}")
        
        # Calculate render time
        end_time = datetime.now()
        result.render_time_ms = (end_time - start_time).total_seconds() * 1000
        
        logger.info(f"Template rendered successfully in {result.render_time_ms:.2f}ms, "
                   f"size: {result.size_bytes:,} bytes, warnings: {len(result.security_warnings)}")
        
        return result
    
    def _scan_template_security(self, template_content: str) -> List[SecurityWarning]:
        """
        Scan template content for security issues before rendering
        """
        warnings = []
        
        # Check for dangerous patterns
        for pattern_name, pattern in self.SECURITY_PATTERNS.items():
            matches = pattern.findall(template_content)
            if matches:
                warnings.append(SecurityWarning(
                    level='high',
                    category='xss',
                    message=f'Potentially dangerous pattern detected: {pattern_name}',
                    recommendation=f'Remove or sanitize {pattern_name} usage'
                ))
        
        # Check for complex Jinja2 expressions that might be risky
        complex_expressions = re.findall(r'\{\{.*?__.*?\}\}', template_content)
        if complex_expressions:
            warnings.append(SecurityWarning(
                level='medium',
                category='template',
                message='Complex template expressions detected',
                recommendation='Review template expressions for security implications'
            ))
        
        # Check for external resource references
        external_refs = re.findall(r'(https?://[^\s\'"<>]+)', template_content, re.IGNORECASE)
        if len(external_refs) > 10:
            warnings.append(SecurityWarning(
                level='low',
                category='privacy',
                message=f'{len(external_refs)} external references found',
                recommendation='Consider hosting resources locally for privacy'
            ))
        
        return warnings
    
    def _scan_html_security(self, html_content: str) -> List[SecurityWarning]:
        """
        Scan rendered HTML for security issues
        """
        warnings = []
        
        if not html_content:
            return warnings
        
        # Parse HTML for analysis
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
        except Exception:
            warnings.append(SecurityWarning(
                level='medium',
                category='parsing',
                message='HTML parsing failed, security scan incomplete',
                recommendation='Verify HTML structure'
            ))
            return warnings
        
        # Check for dangerous attributes
        for tag in soup.find_all():
            # Check for event handlers
            dangerous_attrs = [attr for attr in tag.attrs.keys() if attr.lower().startswith('on')]
            if dangerous_attrs:
                warnings.append(SecurityWarning(
                    level='critical',
                    category='xss',
                    message=f'JavaScript event handler found in {tag.name} tag: {dangerous_attrs}',
                    recommendation='Remove JavaScript event handlers'
                ))
            
            # Check for dangerous href/src values
            for attr in ['href', 'src', 'action']:
                if attr in tag.attrs:
                    value = tag.attrs[attr].lower()
                    if any(dangerous in value for dangerous in ['javascript:', 'data:', 'vbscript:']):
                        warnings.append(SecurityWarning(
                            level='critical',
                            category='xss',
                            message=f'Dangerous {attr} value in {tag.name} tag: {value[:50]}...',
                            recommendation=f'Use safe URLs in {attr} attributes'
                        ))
        
        # Check for script tags (should be stripped by sanitizer)
        if soup.find_all('script'):
            warnings.append(SecurityWarning(
                level='critical',
                category='xss',
                message='Script tags found in HTML',
                recommendation='Remove all script tags from email content'
            ))
        
        # Check for form elements (not suitable for email)
        forms = soup.find_all(['form', 'input', 'textarea', 'select'])
        if forms:
            warnings.append(SecurityWarning(
                level='medium',
                category='compatibility',
                message='Form elements found - not supported in most email clients',
                recommendation='Use links to web forms instead'
            ))
        
        return warnings
    
    def _inline_css(self, html_content: str) -> str:
        """
        Inline CSS styles for better email client compatibility
        """
        try:
            # Use premailer to inline CSS
            p = premailer.Premailer(
                html_content,
                remove_classes=False,  # Keep classes for fallback
                keep_style_tags=True,  # Keep style tags for progressive enhancement
                include_star_selectors=True,
                strip_important=False,
                external_styles=None  # Don't fetch external stylesheets for security
            )
            return p.transform()
        except Exception as e:
            logger.warning(f"CSS inlining failed: {str(e)}")
            return html_content
    
    def _html_to_text(self, html_content: str) -> str:
        """
        Convert HTML to plain text with proper formatting for email
        """
        if not html_content:
            return ""
        
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Convert common elements to text equivalents
            for br in soup.find_all('br'):
                br.replace_with('\n')
            
            for p in soup.find_all('p'):
                p.insert_after('\n\n')
            
            for header in soup.find_all(['h1', 'h2', 'h3', 'h4', 'h5', 'h6']):
                header.insert_before('\n')
                header.insert_after('\n')
            
            for li in soup.find_all('li'):
                li.insert_before('• ')
                li.insert_after('\n')
            
            # Handle links
            for link in soup.find_all('a', href=True):
                link_text = link.get_text()
                href = link['href']
                if href != link_text:
                    link.replace_with(f"{link_text} ({href})")
            
            # Get clean text
            text = soup.get_text()
            
            # Clean up whitespace
            text = re.sub(r'\n\s*\n', '\n\n', text)  # Remove empty lines
            text = re.sub(r'[ \t]+', ' ', text)      # Normalize spaces
            text = text.strip()
            
            return text
            
        except Exception as e:
            logger.warning(f"HTML to text conversion failed: {str(e)}")
            # Fallback: simple tag removal
            text = re.sub(r'<[^<]+?>', '', html_content)
            text = re.sub(r'\s+', ' ', text).strip()
            return text
    
    def _email_safe_filter(self, value: str) -> str:
        """
        Custom Jinja2 filter for email-safe content
        """
        if not isinstance(value, str):
            value = str(value)
        
        # Basic HTML escaping
        value = html.escape(value)
        
        # Additional email-specific escaping
        value = value.replace('\n', '<br>')
        
        return Markup(value)
    
    def _extract_variables(self, template_content: str) -> Set[str]:
        """
        Extract variable names from template content
        """
        try:
            parsed = self.env.parse(template_content)
            return meta.find_undeclared_variables(parsed)
        except Exception:
            # Fallback: regex-based extraction
            variables = set()
            for match in re.finditer(r'\{\{\s*([^}|{\s]+)', template_content):
                var_name = match.group(1).split('.')[0].split('[')[0]
                variables.add(var_name)
            return variables
    
    def validate_template(self, template_content: str) -> Dict[str, Any]:
        """
        Validate template syntax and security without rendering
        """
        validation_result = {
            'valid': False,
            'syntax_errors': [],
            'security_warnings': [],
            'required_variables': set(),
            'estimated_size': 0
        }
        
        try:
            # Parse template
            parsed = self.env.parse(template_content)
            validation_result['required_variables'] = meta.find_undeclared_variables(parsed)
            
            # Compile template to check for syntax errors
            self.env.from_string(template_content)
            
            # Security scan
            security_warnings = self._scan_template_security(template_content)
            validation_result['security_warnings'] = security_warnings
            
            # Estimate size
            validation_result['estimated_size'] = len(template_content.encode('utf-8'))
            
            validation_result['valid'] = True
            
        except TemplateSyntaxError as e:
            validation_result['syntax_errors'].append({
                'line': e.lineno,
                'message': e.message,
                'type': 'syntax'
            })
        except Exception as e:
            validation_result['syntax_errors'].append({
                'line': None,
                'message': str(e),
                'type': 'general'
            })
        
        return validation_result
    
    def get_security_recommendations(self) -> List[str]:
        """
        Get general security recommendations for email templates
        """
        return [
            "Always sanitize user-generated content in templates",
            "Avoid JavaScript and external scripts in email templates",
            "Use HTTPS URLs for all external resources",
            "Test templates across multiple email clients",
            "Keep email size under 100KB for better deliverability",
            "Use inline CSS for better email client compatibility",
            "Validate all template variables before rendering",
            "Use alt text for all images",
            "Include plain text version for all HTML emails",
            "Avoid form elements in email templates"
        ]


# Fedora 41 Integration Utilities
def setup_fedora41_template_engine(config_path: str = '/etc/email-sender/templates.conf') -> SecureTemplateEngine:
    """
    Setup template engine with Fedora 41 specific configuration
    """
    try:
        # Load configuration (implement config loading as needed)
        security_level = TemplateSecurityLevel.STANDARD
        
        # Create engine with system-optimized settings
        engine = SecureTemplateEngine(
            security_level=security_level,
            enable_css_inlining=True,
            max_template_size=2 * 1024 * 1024  # 2MB for system use
        )
        
        logger.info("Template engine configured for Fedora 41")
        return engine
        
    except Exception as e:
        logger.error(f"Failed to setup Fedora 41 template engine: {str(e)}")
        raise


# Usage example
if __name__ == '__main__':
    # Example usage
    engine = SecureTemplateEngine(
        security_level=TemplateSecurityLevel.STANDARD,
        enable_css_inlining=True
    )
    
    template_content = """
    <html>
    <head>
        <style>
            .header { color: #333; font-size: 24px; }
            .content { margin: 20px; }
        </style>
    </head>
    <body>
        <div class="header">Hello {{ name }}!</div>
        <div class="content">
            <p>Welcome to our service. Your account: {{ account_id }}</p>
            <a href="{{ unsubscribe_url }}">Unsubscribe</a>
        </div>
    </body>
    </html>
    """
    
    variables = {
        'name': 'John Doe',
        'account_id': '12345',
        'unsubscribe_url': 'https://example.com/unsubscribe?token=abc123'
    }
    
    result = engine.render_template(template_content, variables)
    
    print(f"Render successful: {result.html is not None}")
    print(f"Security warnings: {len(result.security_warnings)}")
    print(f"Size: {result.size_bytes:,} bytes")
    print(f"Render time: {result.render_time_ms:.2f}ms")

