# tasks/email_sender.py
"""
Advanced Celery-Based Async Email Engine for Fedora 41
Implements production-ready email campaign processing with:
- RFC-compliant SMTP handling
- Advanced retry logic with exponential backoff
- Real-time monitoring and reporting
- Rate limiting and throttling
- Comprehensive error handling and logging
"""

import asyncio
import time
import uuid
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import json
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from email.utils import formataddr, formatdate

from celery import Celery, group, chain, chord
from celery.exceptions import Retry, WorkerLostError
from celery.signals import task_prerun, task_postrun, task_failure
from celery.utils.log import get_task_logger
import aiosmtplib
import redis
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Import our core modules
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.template_engine import SecureTemplateEngine, ContentType
from core.smtp_rfc_handler import SMTPResponseAnalyzer, Fedora41SMTPHandler
from core.database_models import EmailCampaign, EmailSend, SMTPProfile

# Configure task logger
logger = get_task_logger(__name__)

# Redis connection for real-time updates
redis_client = redis.Redis(host='localhost', port=6379, db=1, decode_responses=True)


class TaskStatus(Enum):
    """Task execution status"""
    PENDING = "pending"
    PROCESSING = "processing"
    SUCCESS = "success"
    FAILED = "failed"
    RETRY = "retry"
    CANCELLED = "cancelled"


class CampaignStatus(Enum):
    """Campaign processing status"""
    DRAFT = "draft"
    SCHEDULED = "scheduled"
    PROCESSING = "processing"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class EmailResult:
    """Result of individual email send operation"""
    success: bool
    smtp_code: Optional[str]
    smtp_message: Optional[str]
    delivery_status: str
    bounce_category: Optional[str]
    sent_at: datetime
    retry_count: int
    error_message: Optional[str] = None


@dataclass
class BatchResult:
    """Result of batch email processing"""
    batch_id: str
    total_emails: int
    successful: int
    failed: int
    processing_time_seconds: float
    results: List[EmailResult]


# Enhanced Celery configuration for Fedora 41
celery_app = Celery('email_sender')
celery_app.conf.update({
    # Broker and Result Backend
    'broker_url': 'redis://localhost:6379/0',
    'result_backend': 'redis://localhost:6379/0',
    
    # Serialization
    'task_serializer': 'json',
    'result_serializer': 'json',
    'accept_content': ['json'],
    
    # Timezone
    'timezone': 'UTC',
    'enable_utc': True,
    
    # Task Execution
    'task_acks_late': True,
    'task_reject_on_worker_lost': True,
    'worker_prefetch_multiplier': 1,  # Critical for rate limiting
    'worker_disable_rate_limits': False,
    
    # Result settings
    'result_expires': 3600,  # 1 hour
    'result_compression': 'gzip',
    
    # Routing
    'task_routes': {
        'tasks.email_sender.send_single_email': {'queue': 'email_sending'},
        'tasks.email_sender.process_campaign': {'queue': 'campaign_management'},
        'tasks.email_sender.send_batch': {'queue': 'batch_processing'},
    },
    
    # Monitoring
    'worker_send_task_events': True,
    'task_send_sent_event': True,
    
    # Security
    'worker_hijack_root_logger': False,
    'worker_log_color': False,  # Better for systemd journal
    
    # Performance
    'task_compression': 'gzip',
    'result_backend_transport_options': {
        'master_name': 'mymaster',
        'visibility_timeout': 3600,
    }
})


class EmailSenderError(Exception):
    """Base exception for email sending operations"""
    pass


class SMTPConfigurationError(EmailSenderError):
    """SMTP configuration related errors"""
    pass


class TemplateRenderingError(EmailSenderError):
    """Template rendering related errors"""
    pass


class RateLimitExceededError(EmailSenderError):
    """Rate limit exceeded error"""
    pass


def get_database_session():
    """Get database session for task operations"""
    # This should be configured based on your database setup
    engine = create_engine('sqlite:///email_sender.db')  # Update as needed
    Session = sessionmaker(bind=engine)
    return Session()


def publish_realtime_update(channel: str, data: Dict[str, Any]):
    """Publish real-time update via Redis"""
    try:
        redis_client.publish(channel, json.dumps({
            'timestamp': datetime.utcnow().isoformat(),
            'data': data
        }))
    except Exception as e:
        logger.warning(f"Failed to publish real-time update: {str(e)}")


@celery_app.task(bind=True, max_retries=5, default_retry_delay=60)
def send_single_email(self, 
                     campaign_id: str, 
                     recipient_data: Dict[str, Any],
                     template_data: Dict[str, Any], 
                     smtp_config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Send individual email with comprehensive error handling and monitoring
    
    Args:
        campaign_id: UUID of the email campaign
        recipient_data: Recipient information including email and personalization data
        template_data: Template content and metadata
        smtp_config: SMTP server configuration
    
    Returns:
        Dict containing send result and metadata
    """
    task_id = self.request.id
    recipient_email = recipient_data.get('email', 'unknown')
    
    logger.info(f"Starting email send task {task_id} for {recipient_email}")
    
    # Initialize components
    smtp_handler = Fedora41SMTPHandler()
    template_engine = SecureTemplateEngine()
    
    try:
        # 1. Rate limiting - respect provider limits
        rate_limit = smtp_config.get('rate_limit', 1.0)  # emails per second
        if rate_limit > 0:
            sleep_time = 1.0 / rate_limit
            logger.debug(f"Rate limiting: sleeping {sleep_time:.2f}s")
            time.sleep(sleep_time)
        
        # 2. Render personalized content
        logger.debug("Rendering email template")
        rendered_result = template_engine.render_template(
            template_data['html_content'],
            recipient_data['variables'],
            content_type=ContentType.MIXED,
            sanitize_html=True
        )
        
        if not rendered_result.html and not rendered_result.text:
            raise TemplateRenderingError("Template rendering produced no content")
        
        # Check for security warnings
        critical_warnings = [w for w in rendered_result.security_warnings if w.level == 'critical']
        if critical_warnings:
            raise TemplateRenderingError(f"Critical security issues in template: {critical_warnings}")
        
        # 3. Create email message with proper headers
        msg = MIMEMultipart('alternative')
        
        # Basic headers
        msg['Subject'] = template_data['subject']
        msg['From'] = formataddr((
            smtp_config.get('from_name', 'Email Sender'),
            smtp_config['from_address']
        ))
        msg['To'] = recipient_email
        msg['Date'] = formatdate(localtime=True)
        msg['Message-ID'] = f"<{uuid.uuid4()}@{smtp_config.get('domain', 'localhost')}>"
        
        # Optional headers
        if smtp_config.get('reply_to'):
            msg['Reply-To'] = smtp_config['reply_to']
        
        # List management headers (RFC 2369)
        if recipient_data.get('unsubscribe_token'):
            unsubscribe_url = f"{smtp_config.get('base_url', '')}/unsubscribe/{recipient_data['unsubscribe_token']}"
            msg['List-Unsubscribe'] = f"<{unsubscribe_url}>"
            msg['List-Unsubscribe-Post'] = "List-Unsubscribe=One-Click"
        
        # Tracking and identification headers
        msg['X-Campaign-ID'] = campaign_id
        msg['X-Task-ID'] = task_id
        msg['X-Mailer'] = 'Advanced Email Sender v2.0'
        
        # 4. Attach content parts
        if rendered_result.text:
            text_part = MIMEText(rendered_result.text, 'plain', 'utf-8')
            msg.attach(text_part)
        
        if rendered_result.html:
            html_part = MIMEText(rendered_result.html, 'html', 'utf-8')
            msg.attach(html_part)
        
        # 5. Send via SMTP with async support
        logger.debug("Sending email via SMTP")
        smtp_result = asyncio.run(_async_send_smtp(msg, smtp_config))
        
        # 6. Process SMTP response
        response_analysis = smtp_handler.handle_smtp_response(
            smtp_result['response'],
            recipient_email,
            self.request.retries + 1
        )
        
        # 7. Create result object
        email_result = EmailResult(
            success=response_analysis['category'] == 'success',
            smtp_code=response_analysis['response_code'],
            smtp_message=response_analysis['message'],
            delivery_status='sent' if response_analysis['category'] == 'success' else 'failed',
            bounce_category=response_analysis['bounce_analysis'].get('subcategory'),
            sent_at=datetime.utcnow(),
            retry_count=self.request.retries,
            error_message=None if response_analysis['category'] == 'success' else response_analysis['message']
        )
        
        # 8. Log to database
        _log_email_result(campaign_id, recipient_email, email_result, response_analysis)
        
        # 9. Publish real-time update
        publish_realtime_update(f'campaign:{campaign_id}', {
            'type': 'email_sent',
            'recipient': recipient_email,
            'status': email_result.delivery_status,
            'smtp_code': email_result.smtp_code
        })
        
        # 10. Handle retry logic
        if not email_result.success and response_analysis['should_retry']:
            retry_delay = response_analysis['retry_delay']
            logger.warning(f"Email to {recipient_email} failed, retrying in {retry_delay}s: {email_result.smtp_message}")
            raise self.retry(
                exc=EmailSenderError(f"SMTP error: {email_result.smtp_message}"),
                countdown=retry_delay,
                max_retries=5
            )
        
        logger.info(f"Email to {recipient_email} processed successfully: {email_result.delivery_status}")
        return asdict(email_result)
        
    except Retry:
        # Re-raise retry exceptions
        raise
    except TemplateRenderingError as e:
        logger.error(f"Template rendering failed for {recipient_email}: {str(e)}")
        error_result = EmailResult(
            success=False,
            smtp_code=None,
            smtp_message=None,
            delivery_status='failed',
            bounce_category='template_error',
            sent_at=datetime.utcnow(),
            retry_count=self.request.retries,
            error_message=str(e)
        )
        _log_email_result(campaign_id, recipient_email, error_result, None)
        return asdict(error_result)
    except Exception as exc:
        logger.error(f"Unexpected error sending email to {recipient_email}: {str(exc)}", exc_info=True)
        
        # Determine if we should retry based on error type
        if isinstance(exc, (smtplib.SMTPServerDisconnected, smtplib.SMTPConnectError)):
            # Connection issues - retry with exponential backoff
            retry_delay = min(300, 60 * (2 ** self.request.retries))  # Cap at 5 minutes
            logger.warning(f"Connection error, retrying in {retry_delay}s")
            raise self.retry(exc=exc, countdown=retry_delay)
        
        # Log permanent failure
        error_result = EmailResult(
            success=False,
            smtp_code=None,
            smtp_message=None,
            delivery_status='failed',
            bounce_category='system_error',
            sent_at=datetime.utcnow(),
            retry_count=self.request.retries,
            error_message=str(exc)
        )
        _log_email_result(campaign_id, recipient_email, error_result, None)
        return asdict(error_result)


async def _async_send_smtp(msg: MIMEMultipart, smtp_config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Async SMTP sending with comprehensive error handling
    """
    try:
        # Create SMTP client
        smtp = aiosmtplib.SMTP(
            hostname=smtp_config['host'],
            port=smtp_config['port'],
            timeout=smtp_config.get('timeout', 60),
            use_tls=smtp_config.get('port') == 465,  # Implicit TLS for port 465
            validate_certs=smtp_config.get('validate_certs', True)
        )
        
        # Connect and authenticate
        await smtp.connect()
        
        # STARTTLS if needed (port 587)
        if smtp_config.get('port') == 587:
            await smtp.starttls()
        
        # Authenticate if credentials provided
        if smtp_config.get('username') and smtp_config.get('password'):
            await smtp.login(smtp_config['username'], smtp_config['password'])
        
        # Send message
        response = await smtp.send_message(msg)
        
        # Close connection
        await smtp.quit()
        
        return {
            'success': True,
            'response': '250 Message accepted',
            'message_id': msg['Message-ID']
        }
        
    except aiosmtplib.SMTPResponseException as e:
        return {
            'success': False,
            'response': f"{e.code} {e.message}",
            'error': str(e)
        }
    except Exception as e:
        return {
            'success': False,
            'response': f"500 {str(e)}",
            'error': str(e)
        }


@celery_app.task(bind=True)
def send_batch(self, campaign_id: str, recipients_batch: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Send a batch of emails with proper coordination and monitoring
    
    Args:
        campaign_id: Campaign identifier
        recipients_batch: List of recipient data dictionaries
    
    Returns:
        BatchResult with processing statistics
    """
    batch_id = str(uuid.uuid4())
    start_time = time.time()
    
    logger.info(f"Starting batch {batch_id} with {len(recipients_batch)} emails for campaign {campaign_id}")
    
    try:
        # Load campaign configuration
        template_data = get_template_data(campaign_id)
        smtp_config = get_smtp_config(campaign_id)
        
        # Create individual email tasks
        job_group = group(
            send_single_email.s(
                campaign_id,
                recipient,
                template_data,
                smtp_config
            ) for recipient in recipients_batch
        )
        
        # Execute batch with monitoring
        result = job_group.apply_async()
        
        # Wait for completion with timeout
        batch_timeout = len(recipients_batch) * 30  # 30 seconds per email
        results = result.get(timeout=batch_timeout, propagate=False)
        
        # Analyze results
        successful = sum(1 for r in results if r and r.get('success', False))
        failed = len(results) - successful
        processing_time = time.time() - start_time
        
        batch_result = BatchResult(
            batch_id=batch_id,
            total_emails=len(recipients_batch),
            successful=successful,
            failed=failed,
            processing_time_seconds=processing_time,
            results=[EmailResult(**r) if r else None for r in results]
        )
        
        # Update campaign statistics
        _update_campaign_stats(campaign_id, successful, failed)
        
        # Publish batch completion
        publish_realtime_update(f'campaign:{campaign_id}', {
            'type': 'batch_completed',
            'batch_id': batch_id,
            'successful': successful,
            'failed': failed,
            'processing_time': processing_time
        })
        
        logger.info(f"Batch {batch_id} completed: {successful} successful, {failed} failed")
        return asdict(batch_result)
        
    except Exception as e:
        logger.error(f"Batch {batch_id} failed: {str(e)}", exc_info=True)
        raise


@celery_app.task(bind=True)
def process_campaign(self, campaign_id: str) -> Dict[str, Any]:
    """
    Process entire email campaign with intelligent batching and monitoring
    
    Args:
        campaign_id: Campaign identifier
    
    Returns:
        Campaign processing result
    """
    logger.info(f"Starting campaign processing: {campaign_id}")
    
    try:
        # Load campaign data
        campaign_data = load_campaign(campaign_id)
        recipients = load_campaign_recipients(campaign_id)
        
        if not recipients:
            raise EmailSenderError("No recipients found for campaign")
        
        # Update campaign status
        update_campaign_status(campaign_id, CampaignStatus.PROCESSING)
        
        # Calculate optimal batching
        total_recipients = len(recipients)
        batch_size = campaign_data['settings'].get('batch_size', 100)
        batch_delay_minutes = campaign_data['settings'].get('batch_delay_minutes', 5)
        
        # Create batches
        batches = [
            recipients[i:i + batch_size] 
            for i in range(0, total_recipients, batch_size)
        ]
        
        logger.info(f"Campaign {campaign_id}: {total_recipients} recipients in {len(batches)} batches")
        
        # Schedule batches with delays
        batch_jobs = []
        for i, batch in enumerate(batches):
            delay_seconds = i * batch_delay_minutes * 60
            
            job = send_batch.apply_async(
                args=[campaign_id, batch],
                countdown=delay_seconds
            )
            batch_jobs.append(job)
            
            logger.info(f"Scheduled batch {i+1}/{len(batches)} with {delay_seconds}s delay")
        
        # Create callback for campaign completion
        callback = finalize_campaign.s(campaign_id)
        
        # Use chord to wait for all batches and then finalize
        campaign_job = chord(
            group(job for job in batch_jobs)
        )(callback)
        
        # Publish campaign start event
        publish_realtime_update(f'campaign:{campaign_id}', {
            'type': 'campaign_started',
            'total_recipients': total_recipients,
            'total_batches': len(batches),
            'estimated_completion': datetime.utcnow() + timedelta(
                minutes=len(batches) * batch_delay_minutes
            )
        })
        
        return {
            'campaign_id': campaign_id,
            'status': 'processing',
            'total_recipients': total_recipients,
            'total_batches': len(batches),
            'job_id': campaign_job.id
        }
        
    except Exception as e:
        logger.error(f"Campaign {campaign_id} processing failed: {str(e)}", exc_info=True)
        update_campaign_status(campaign_id, CampaignStatus.FAILED)
        raise


@celery_app.task
def finalize_campaign(batch_results: List[Dict[str, Any]], campaign_id: str) -> Dict[str, Any]:
    """
    Finalize campaign processing and generate final statistics
    
    Args:
        batch_results: Results from all batch processing tasks
        campaign_id: Campaign identifier
    
    Returns:
        Final campaign statistics
    """
    logger.info(f"Finalizing campaign: {campaign_id}")
    
    try:
        # Aggregate statistics
        total_sent = 0
        total_failed = 0
        total_processing_time = 0
        
        for batch_result in batch_results:
            if batch_result:
                total_sent += batch_result.get('successful', 0)
                total_failed += batch_result.get('failed', 0)
                total_processing_time += batch_result.get('processing_time_seconds', 0)
        
        # Update campaign final status
        final_status = CampaignStatus.COMPLETED if total_failed == 0 else CampaignStatus.COMPLETED
        update_campaign_status(campaign_id, final_status)
        
        # Generate final report
        final_stats = {
            'campaign_id': campaign_id,
            'status': final_status.value,
            'total_sent': total_sent,
            'total_failed': total_failed,
            'success_rate': (total_sent / (total_sent + total_failed)) * 100 if (total_sent + total_failed) > 0 else 0,
            'total_processing_time_seconds': total_processing_time,
            'completed_at': datetime.utcnow().isoformat()
        }
        
        # Publish campaign completion
        publish_realtime_update(f'campaign:{campaign_id}', {
            'type': 'campaign_completed',
            **final_stats
        })
        
        logger.info(f"Campaign {campaign_id} completed: {total_sent} sent, {total_failed} failed")
        return final_stats
        
    except Exception as e:
        logger.error(f"Campaign finalization failed: {str(e)}", exc_info=True)
        update_campaign_status(campaign_id, CampaignStatus.FAILED)
        raise


# Helper functions
def load_campaign(campaign_id: str) -> Dict[str, Any]:
    """Load campaign data from database"""
    session = get_database_session()
    try:
        campaign = session.query(EmailCampaign).filter_by(id=campaign_id).first()
        if not campaign:
            raise EmailSenderError(f"Campaign {campaign_id} not found")
        
        return {
            'id': str(campaign.id),
            'name': campaign.name,
            'settings': campaign.settings or {},
            'template_id': str(campaign.template_id),
            'smtp_profile_id': str(campaign.smtp_profile_id)
        }
    finally:
        session.close()


def load_campaign_recipients(campaign_id: str) -> List[Dict[str, Any]]:
    """Load campaign recipients from database"""
    # Implementation depends on your data model
    # This is a placeholder - implement based on your recipient storage
    return []


def get_template_data(campaign_id: str) -> Dict[str, Any]:
    """Get template data for campaign"""
    # Implementation depends on your data model
    return {}


def get_smtp_config(campaign_id: str) -> Dict[str, Any]:
    """Get SMTP configuration for campaign"""
    # Implementation depends on your data model
    return {}


def update_campaign_status(campaign_id: str, status: CampaignStatus):
    """Update campaign status in database"""
    session = get_database_session()
    try:
        campaign = session.query(EmailCampaign).filter_by(id=campaign_id).first()
        if campaign:
            campaign.status = status.value
            session.commit()
    finally:
        session.close()


def _log_email_result(campaign_id: str, recipient_email: str, 
                     result: EmailResult, response_analysis: Optional[Dict[str, Any]]):
    """Log email send result to database"""
    session = get_database_session()
    try:
        email_send = EmailSend(
            campaign_id=campaign_id,
            recipient_email=recipient_email,
            smtp_response_code=result.smtp_code,
            smtp_response_message=result.smtp_message,
            delivery_status=result.delivery_status,
            bounce_category=result.bounce_category,
            sent_at=result.sent_at,
            retry_count=result.retry_count
        )
        session.add(email_send)
        session.commit()
    except Exception as e:
        logger.error(f"Failed to log email result: {str(e)}")
    finally:
        session.close()


def _update_campaign_stats(campaign_id: str, successful: int, failed: int):
    """Update campaign statistics"""
    session = get_database_session()
    try:
        campaign = session.query(EmailCampaign).filter_by(id=campaign_id).first()
        if campaign:
            campaign.sent_count += successful
            campaign.failed_count += failed
            session.commit()
    finally:
        session.close()


# Celery signal handlers for monitoring
@task_prerun.connect
def task_prerun_handler(sender=None, task_id=None, task=None, args=None, kwargs=None, **cwds):
    """Handle task pre-run events"""
    logger.info(f"Task {task.name} [{task_id}] starting")


@task_postrun.connect
def task_postrun_handler(sender=None, task_id=None, task=None, args=None, kwargs=None, 
                        retval=None, state=None, **cwds):
    """Handle task post-run events"""
    logger.info(f"Task {task.name} [{task_id}] completed with state: {state}")


@task_failure.connect
def task_failure_handler(sender=None, task_id=None, exception=None, einfo=None, **cwds):
    """Handle task failure events"""
    logger.error(f"Task {sender.name} [{task_id}] failed: {exception}")


# Fedora 41 System Integration
def setup_systemd_service():
    """Setup systemd service configuration"""
    service_config = """
[Unit]
Description=Email Sender Celery Worker
After=network.target redis.service

[Service]
Type=notify
User=email-sender
Group=email-sender
WorkingDirectory=/opt/email-sender
Environment=CELERY_BROKER_URL=redis://localhost:6379/0
ExecStart=/opt/email-sender/venv/bin/celery -A tasks.email_sender worker --loglevel=info
ExecReload=/bin/kill -s HUP $MAINPID
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
"""
    
    with open('/etc/systemd/system/email-sender-worker.service', 'w') as f:
        f.write(service_config)
    
    logger.info("Systemd service configuration created")


if __name__ == '__main__':
    # Development/testing entry point
    celery_app.start()

