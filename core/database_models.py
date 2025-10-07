# core/database_models.py
from datetime import datetime
import uuid
from sqlalchemy import Column, Integer, String, DateTime, JSON, Text, Boolean, ForeignKey, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()

def generate_uuid():
    """Generate UUID as string for SQLite compatibility"""
    return str(uuid.uuid4())

class SMTPProfile(Base):
    __tablename__ = 'smtp_profiles'
    
    id = Column(String(36), primary_key=True, default=generate_uuid)  # Changed from UUID
    name = Column(String(100), nullable=False)
    host = Column(String(255), nullable=False)
    port = Column(Integer, nullable=False)
    use_tls = Column(Boolean, default=True)
    username = Column(String(255), nullable=False)
    password_hash = Column(String(255), nullable=False)
    status = Column(String(20), default='active')
    last_tested = Column(DateTime)
    test_results = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class EmailTemplate(Base):
    __tablename__ = 'email_templates'
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    name = Column(String(100), nullable=False)
    subject_template = Column(String(255), nullable=False)
    html_content = Column(Text)
    text_content = Column(Text)
    variables = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class RecipientList(Base):
    __tablename__ = 'recipient_lists'
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    name = Column(String(100), nullable=False)
    description = Column(Text)
    emails_csv = Column(Text)
    valid_email_count = Column(Integer, default=0)
    invalid_email_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class EmailCampaign(Base):
    __tablename__ = 'email_campaigns'
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    name = Column(String(100), nullable=False)
    template_id = Column(String(36), ForeignKey('email_templates.id'), nullable=False)
    smtp_profile_id = Column(String(36), ForeignKey('smtp_profiles.id'), nullable=False)
    recipient_list_id = Column(String(36), ForeignKey('recipient_lists.id'), nullable=False)
    settings = Column(JSON)
    status = Column(String(20), default='draft')
    scheduled_at = Column(DateTime)
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    total_recipients = Column(Integer, default=0)
    sent_count = Column(Integer, default=0)
    failed_count = Column(Integer, default=0)
    bounced_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    template = relationship("EmailTemplate")
    smtp_profile = relationship("SMTPProfile")
    recipient_list = relationship("RecipientList")

class EmailSend(Base):
    __tablename__ = 'email_sends'
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    campaign_id = Column(String(36), ForeignKey('email_campaigns.id'), nullable=False)
    recipient_email = Column(String(255), nullable=False, index=True)
    smtp_response_code = Column(String(10))
    smtp_response_message = Column(Text)
    delivery_status = Column(String(20))
    bounce_category = Column(String(50))
    sent_at = Column(DateTime)
    retry_count = Column(Integer, default=0)
    last_retry_at = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    campaign = relationship("EmailCampaign")

# Add User model for authentication
class User(Base):
    __tablename__ = 'users'
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    username = Column(String(100), unique=True, nullable=False)
    email = Column(String(255), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    two_factor_secret = Column(String(32))
    locked_until = Column(DateTime)
    last_login = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

