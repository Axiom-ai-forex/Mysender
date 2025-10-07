from datetime import datetime
import uuid
from sqlalchemy import (
    Column, Integer, String, DateTime, JSON, Text, Boolean, ForeignKey, func
)

from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import UUID

Base = declarative_base()

class SMTPProfile(Base):
    __tablename__ = 'smtp_profiles'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(100), nullable=False)
    host = Column(String(255), nullable=False)
    port = Column(Integer, nullable=False)
    use_tls = Column(Boolean, default=True)
    username = Column(String(255), nullable=False)
    password_hash = Column(String(255), nullable=False)  # Store encrypted!
    status = Column(String(20), default='active')
    last_tested = Column(DateTime)
    test_results = Column(JSON)  # Store detailed JSON test outcomes
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    campaigns = relationship("EmailCampaign", back_populates="smtp_profile")

class EmailTemplate(Base):
    __tablename__ = 'email_templates'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(100), nullable=False)
    subject_template = Column(String(255), nullable=False)
    html_content = Column(Text)
    text_content = Column(Text)
    variables = Column(JSON)  # Expected template variables to validate inputs
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    campaigns = relationship("EmailCampaign", back_populates="template")

class RecipientList(Base):
    __tablename__ = 'recipient_lists'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(100), nullable=False)
    description = Column(Text)
    emails_csv = Column(Text)  # Raw email list as CSV or text blob
    valid_email_count = Column(Integer, default=0)
    invalid_email_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    campaigns = relationship("EmailCampaign", back_populates="recipient_list")

class EmailCampaign(Base):
    __tablename__ = 'email_campaigns'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(100), nullable=False)
    template_id = Column(UUID(as_uuid=True), ForeignKey('email_templates.id'), nullable=False)
    smtp_profile_id = Column(UUID(as_uuid=True), ForeignKey('smtp_profiles.id'), nullable=False)
    recipient_list_id = Column(UUID(as_uuid=True), ForeignKey('recipient_lists.id'), nullable=False)
    settings = Column(JSON)  # Throttle, scheduling, reply-to settings, etc.
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
    template = relationship("EmailTemplate", back_populates="campaigns")
    smtp_profile = relationship("SMTPProfile", back_populates="campaigns")
    recipient_list = relationship("RecipientList", back_populates="campaigns")
    sends = relationship("EmailSend", back_populates="campaign", cascade="all, delete-orphan")

class EmailSend(Base):
    __tablename__ = 'email_sends'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    campaign_id = Column(UUID(as_uuid=True), ForeignKey('email_campaigns.id'), nullable=False)
    recipient_email = Column(String(255), nullable=False, index=True)
    smtp_response_code = Column(String(10))
    smtp_response_message = Column(Text)
    delivery_status = Column(String(20))  # e.g., 'sent', 'bounced', 'failed', 'retry'
    bounce_category = Column(String(50))  # Categorized from SMTP codes and messages
    sent_at = Column(DateTime)  # Timestamp of first send attempt
    retry_count = Column(Integer, default=0)
    last_retry_at = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    campaign = relationship("EmailCampaign", back_populates="sends")

