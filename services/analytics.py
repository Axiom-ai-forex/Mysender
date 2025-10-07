# services/analytics.py
"""
Advanced Email Analytics Service for Real-time Dashboard
Implements comprehensive campaign analytics with ML-powered insights
Optimized for Fedora 41 with Redis caching and WebSocket support
"""

import logging
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from enum import Enum
import threading
from concurrent.futures import ThreadPoolExecutor
import asyncio

import pandas as pd
import numpy as np
import plotly.graph_objs as go
import plotly.utils
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
import redis
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler

# Import core modules
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.database_models import EmailCampaign, EmailSend, SMTPProfile
from core.smtp_rfc_handler import SMTP_CODES

# Configure logging
logger = logging.getLogger(__name__)

# Redis client for caching and real-time updates
redis_client = redis.Redis(host='localhost', port=6379, db=2, decode_responses=True)


class MetricType(Enum):
    """Types of email metrics"""
    DELIVERY = "delivery"
    ENGAGEMENT = "engagement" 
    BOUNCE = "bounce"
    REPUTATION = "reputation"
    PERFORMANCE = "performance"


class ChartType(Enum):
    """Types of analytics charts"""
    PIE = "pie"
    BAR = "bar"
    LINE = "line"
    SCATTER = "scatter"
    HEATMAP = "heatmap"
    GAUGE = "gauge"


@dataclass
class Metric:
    """Individual metric definition"""
    name: str
    value: float
    unit: str
    trend: Optional[str] = None  # "up", "down", "stable"
    change_percent: Optional[float] = None
    benchmark: Optional[float] = None
    status: str = "normal"  # "good", "warning", "critical"


@dataclass
class Recommendation:
    """Analytics recommendation"""
    category: str
    priority: str  # "low", "medium", "high", "critical"
    title: str
    description: str
    action: str
    impact: str
    effort: str  # "low", "medium", "high"


@dataclass
class AnalyticsSnapshot:
    """Complete analytics snapshot"""
    timestamp: datetime
    campaign_id: str
    metrics: Dict[str, Metric]
    charts: Dict[str, Dict[str, Any]]
    recommendations: List[Recommendation]
    summary: Dict[str, Any]
    cache_ttl: int = 300  # 5 minutes


class EmailAnalytics:
    """
    Advanced email analytics engine with real-time capabilities
    """
    
    # Industry benchmark values for comparison
    INDUSTRY_BENCHMARKS = {
        'delivery_rate': 95.0,
        'bounce_rate': 2.0,
        'open_rate': 22.0,
        'click_rate': 3.0,
        'unsubscribe_rate': 0.5
    }
    
    # Metric thresholds for status determination
    STATUS_THRESHOLDS = {
        'delivery_rate': {'good': 98.0, 'warning': 95.0},
        'bounce_rate': {'good': 2.0, 'warning': 5.0},
        'failure_rate': {'good': 1.0, 'warning': 3.0}
    }
    
    def __init__(self, database_url: str = None):
        """
        Initialize analytics engine
        
        Args:
            database_url: Database connection string
        """
        self.database_url = database_url or 'sqlite:///email_sender.db'
        self.engine = create_engine(self.database_url, pool_size=10, max_overflow=20)
        Session = sessionmaker(bind=self.engine)
        self.session_factory = Session
        
        # Cache configuration
        self.metrics_cache = {}
        self.cache_ttl = 300  # 5 minutes
        self.update_interval = 30  # 30 seconds for real-time updates
        
        # ML models for advanced analytics
        self.anomaly_detector = None
        self.performance_predictor = None
        
        logger.info("EmailAnalytics engine initialized")
    
    def get_campaign_metrics(self, campaign_id: str, 
                           include_predictions: bool = False,
                           force_refresh: bool = False) -> AnalyticsSnapshot:
        """
        Generate comprehensive campaign analytics with caching
        
        Args:
            campaign_id: Campaign identifier
            include_predictions: Whether to include ML predictions
            force_refresh: Force cache refresh
        
        Returns:
            Complete analytics snapshot
        """
        cache_key = f"analytics:{campaign_id}"
        
        # Check cache first
        if not force_refresh:
            cached_data = redis_client.get(cache_key)
            if cached_data:
                try:
                    data = json.loads(cached_data)
                    logger.debug(f"Returning cached analytics for {campaign_id}")
                    return AnalyticsSnapshot(**data)
                except Exception as e:
                    logger.warning(f"Cache deserialization failed: {str(e)}")
        
        logger.info(f"Generating analytics for campaign: {campaign_id}")
        start_time = time.time()
        
        try:
            # Load campaign data
            campaign_data = self._load_campaign_data(campaign_id)
            sends_df = self._load_email_sends_data(campaign_id)
            
            if sends_df.empty:
                return AnalyticsSnapshot(
                    timestamp=datetime.utcnow(),
                    campaign_id=campaign_id,
                    metrics={},
                    charts={},
                    recommendations=[],
                    summary={'error': 'No data available for analysis'}
                )
            
            # Calculate core metrics
            metrics = self._calculate_core_metrics(sends_df, campaign_data)
            
            # Generate visualizations
            charts = self._generate_charts(sends_df)
            
            # Generate recommendations
            recommendations = self._generate_intelligent_recommendations(
                metrics, sends_df, campaign_data
            )
            
            # Add ML predictions if requested
            if include_predictions:
                predictions = self._generate_predictions(sends_df, campaign_data)
                metrics.update(predictions)
            
            # Create summary
            summary = self._create_summary(metrics, sends_df)
            
            # Create snapshot
            snapshot = AnalyticsSnapshot(
                timestamp=datetime.utcnow(),
                campaign_id=campaign_id,
                metrics=metrics,
                charts=charts,
                recommendations=recommendations,
                summary=summary
            )
            
            # Cache results
            try:
                cache_data = asdict(snapshot)
                # Convert datetime objects to ISO strings for JSON serialization
                cache_data['timestamp'] = cache_data['timestamp'].isoformat()
                redis_client.setex(
                    cache_key, 
                    self.cache_ttl, 
                    json.dumps(cache_data, default=str)
                )
            except Exception as e:
                logger.warning(f"Failed to cache analytics: {str(e)}")
            
            processing_time = time.time() - start_time
            logger.info(f"Analytics generated for {campaign_id} in {processing_time:.2f}s")
            
            return snapshot
            
        except Exception as e:
            logger.error(f"Analytics generation failed for {campaign_id}: {str(e)}", exc_info=True)
            raise
    
    def _load_campaign_data(self, campaign_id: str) -> Dict[str, Any]:
        """Load campaign metadata"""
        session = self.session_factory()
        try:
            campaign = session.query(EmailCampaign).filter_by(id=campaign_id).first()
            if not campaign:
                raise ValueError(f"Campaign {campaign_id} not found")
            
            return {
                'id': str(campaign.id),
                'name': campaign.name,
                'created_at': campaign.created_at,
                'started_at': campaign.started_at,
                'completed_at': campaign.completed_at,
                'total_recipients': campaign.total_recipients,
                'sent_count': campaign.sent_count,
                'failed_count': campaign.failed_count,
                'bounced_count': campaign.bounced_count,
                'status': campaign.status
            }
        finally:
            session.close()
    
    def _load_email_sends_data(self, campaign_id: str) -> pd.DataFrame:
        """Load email sends data with optimized query"""
        query = """
        SELECT 
            es.delivery_status,
            es.smtp_response_code,
            es.bounce_category,
            es.sent_at,
            es.retry_count,
            DATE(es.sent_at) as send_date,
            HOUR(es.sent_at) as send_hour,
            MINUTE(es.sent_at) as send_minute,
            es.recipient_email
        FROM email_sends es
        WHERE es.campaign_id = :campaign_id
        ORDER BY es.sent_at
        """
        
        try:
            df = pd.read_sql(
                text(query), 
                self.engine, 
                params={'campaign_id': campaign_id}
            )
            
            # Data type conversions
            if not df.empty:
                df['sent_at'] = pd.to_datetime(df['sent_at'])
                df['send_hour'] = df['send_hour'].astype('Int64')
                df['send_minute'] = df['send_minute'].astype('Int64')
            
            return df
            
        except Exception as e:
            logger.error(f"Failed to load email sends data: {str(e)}")
            return pd.DataFrame()
    
    def _calculate_core_metrics(self, sends_df: pd.DataFrame, 
                               campaign_data: Dict[str, Any]) -> Dict[str, Metric]:
        """Calculate core email metrics with trend analysis"""
        metrics = {}
        total_sends = len(sends_df)
        
        if total_sends == 0:
            return metrics
        
        # Delivery metrics
        delivered = len(sends_df[sends_df['delivery_status'] == 'sent'])
        bounced = len(sends_df[sends_df['delivery_status'] == 'bounced'])
        failed = len(sends_df[sends_df['delivery_status'] == 'failed'])
        
        delivery_rate = (delivered / total_sends) * 100
        bounce_rate = (bounced / total_sends) * 100
        failure_rate = (failed / total_sends) * 100
        
        # Add delivery rate metric
        metrics['delivery_rate'] = Metric(
            name='Delivery Rate',
            value=delivery_rate,
            unit='%',
            benchmark=self.INDUSTRY_BENCHMARKS['delivery_rate'],
            status=self._get_metric_status('delivery_rate', delivery_rate)
        )
        
        # Add bounce rate metric
        metrics['bounce_rate'] = Metric(
            name='Bounce Rate',
            value=bounce_rate,
            unit='%',
            benchmark=self.INDUSTRY_BENCHMARKS['bounce_rate'],
            status=self._get_metric_status('bounce_rate', bounce_rate)
        )
        
        # Add failure rate metric
        metrics['failure_rate'] = Metric(
            name='Failure Rate',
            value=failure_rate,
            unit='%',
            status=self._get_metric_status('failure_rate', failure_rate)
        )
        
        # Performance metrics
        if campaign_data.get('started_at') and campaign_data.get('completed_at'):
            duration = campaign_data['completed_at'] - campaign_data['started_at']
            sends_per_hour = total_sends / max(duration.total_seconds() / 3600, 1)
            
            metrics['sending_velocity'] = Metric(
                name='Sending Velocity',
                value=sends_per_hour,
                unit='emails/hour',
                status='good' if sends_per_hour > 100 else 'warning'
            )
        
        # SMTP response analysis
        smtp_codes = sends_df['smtp_response_code'].value_counts()
        success_codes = sum(smtp_codes.get(code, 0) for code in ['250', '251', '252'])
        
        metrics['smtp_success_rate'] = Metric(
            name='SMTP Success Rate',
            value=(success_codes / total_sends) * 100,
            unit='%',
            status='good' if success_codes / total_sends > 0.95 else 'warning'
        )
        
        # Retry analysis
        avg_retries = sends_df['retry_count'].mean()
        metrics['average_retries'] = Metric(
            name='Average Retries',
            value=avg_retries,
            unit='retries',
            status='good' if avg_retries < 1 else 'warning'
        )
        
        return metrics
    
    def _get_metric_status(self, metric_name: str, value: float) -> str:
        """Determine metric status based on thresholds"""
        thresholds = self.STATUS_THRESHOLDS.get(metric_name)
        if not thresholds:
            return 'normal'
        
        if metric_name in ['bounce_rate', 'failure_rate']:
            # Lower is better
            if value <= thresholds['good']:
                return 'good'
            elif value <= thresholds['warning']:
                return 'warning'
            else:
                return 'critical'
        else:
            # Higher is better
            if value >= thresholds['good']:
                return 'good'
            elif value >= thresholds['warning']:
                return 'warning'
            else:
                return 'critical'
    
    def _generate_charts(self, sends_df: pd.DataFrame) -> Dict[str, Dict[str, Any]]:
        """Generate interactive charts for dashboard"""
        charts = {}
        
        try:
            # 1. Delivery Status Pie Chart
            status_counts = sends_df['delivery_status'].value_counts()
            
            fig_pie = go.Figure(data=[go.Pie(
                labels=status_counts.index,
                values=status_counts.values,
                hole=0.3,
                marker=dict(
                    colors=['#28a745', '#dc3545', '#ffc107', '#17a2b8']
                )
            )])
            fig_pie.update_layout(
                title='Email Delivery Status Distribution',
                font=dict(size=12),
                showlegend=True
            )
            
            charts['delivery_status_pie'] = {
                'type': 'pie',
                'data': json.loads(plotly.utils.PlotlyJSONEncoder().encode(fig_pie)),
                'description': 'Distribution of email delivery statuses'
            }
            
            # 2. Bounce Categories Bar Chart
            bounce_data = sends_df[sends_df['delivery_status'] == 'bounced']
            if not bounce_data.empty:
                bounce_categories = bounce_data['bounce_category'].value_counts()
                
                fig_bar = go.Figure(data=[go.Bar(
                    x=bounce_categories.index,
                    y=bounce_categories.values,
                    marker_color='#dc3545'
                )])
                fig_bar.update_layout(
                    title='Bounce Categories',
                    xaxis_title='Category',
                    yaxis_title='Count',
                    font=dict(size=12)
                )
                
                charts['bounce_categories_bar'] = {
                    'type': 'bar',
                    'data': json.loads(plotly.utils.PlotlyJSONEncoder().encode(fig_bar)),
                    'description': 'Breakdown of bounce reasons'
                }
            
            # 3. Hourly Sending Pattern
            hourly_sends = sends_df.groupby('send_hour').size().reset_index()
            hourly_sends.columns = ['hour', 'count']
            
            fig_line = go.Figure(data=[go.Scatter(
                x=hourly_sends['hour'],
                y=hourly_sends['count'],
                mode='lines+markers',
                line=dict(color='#007bff', width=3),
                marker=dict(size=8)
            )])
            fig_line.update_layout(
                title='Sending Pattern by Hour',
                xaxis_title='Hour of Day',
                yaxis_title='Emails Sent',
                font=dict(size=12)
            )
            
            charts['hourly_pattern_line'] = {
                'type': 'line',
                'data': json.loads(plotly.utils.PlotlyJSONEncoder().encode(fig_line)),
                'description': 'Email sending volume throughout the day'
            }
            
            # 4. SMTP Response Codes Heatmap
            smtp_codes = sends_df['smtp_response_code'].value_counts().head(10)
            
            fig_heatmap = go.Figure(data=go.Heatmap(
                z=[smtp_codes.values],
                x=smtp_codes.index,
                y=['Response Codes'],
                colorscale='RdYlBu_r',
                showscale=True
            ))
            fig_heatmap.update_layout(
                title='SMTP Response Code Distribution',
                font=dict(size=12)
            )
            
            charts['smtp_codes_heatmap'] = {
                'type': 'heatmap',
                'data': json.loads(plotly.utils.PlotlyJSONEncoder().encode(fig_heatmap)),
                'description': 'Distribution of SMTP response codes'
            }
            
            # 5. Performance Gauge
            delivery_rate = (len(sends_df[sends_df['delivery_status'] == 'sent']) / len(sends_df)) * 100
            
            fig_gauge = go.Figure(go.Indicator(
                mode="gauge+number+delta",
                value=delivery_rate,
                domain={'x': [0, 1], 'y': [0, 1]},
                title={'text': "Delivery Rate"},
                delta={'reference': 95},
                gauge={
                    'axis': {'range': [None, 100]},
                    'bar': {'color': "darkblue"},
                    'steps': [
                        {'range': [0, 90], 'color': "lightgray"},
                        {'range': [90, 95], 'color': "yellow"},
                        {'range': [95, 100], 'color': "green"}
                    ],
                    'threshold': {
                        'line': {'color': "red", 'width': 4},
                        'thickness': 0.75,
                        'value': 95
                    }
                }
            ))
            
            charts['delivery_rate_gauge'] = {
                'type': 'gauge',
                'data': json.loads(plotly.utils.PlotlyJSONEncoder().encode(fig_gauge)),
                'description': 'Current delivery rate performance'
            }
            
        except Exception as e:
            logger.error(f"Chart generation failed: {str(e)}")
        
        return charts
    
    def _generate_intelligent_recommendations(self, metrics: Dict[str, Metric],
                                            sends_df: pd.DataFrame,
                                            campaign_data: Dict[str, Any]) -> List[Recommendation]:
        """Generate AI-powered recommendations"""
        recommendations = []
        
        try:
            # Analyze delivery rate
            delivery_rate = metrics.get('delivery_rate')
            if delivery_rate and delivery_rate.value < 95:
                priority = 'critical' if delivery_rate.value < 90 else 'high'
                recommendations.append(Recommendation(
                    category='deliverability',
                    priority=priority,
                    title='Low Delivery Rate Detected',
                    description=f'Current delivery rate is {delivery_rate.value:.1f}%, below the recommended 95%',
                    action='Review SMTP configuration, sender reputation, and email content for spam triggers',
                    impact='High - Affects campaign reach and ROI',
                    effort='medium'
                ))
            
            # Analyze bounce rate
            bounce_rate = metrics.get('bounce_rate')
            if bounce_rate and bounce_rate.value > 5:
                recommendations.append(Recommendation(
                    category='list_quality',
                    priority='high',
                    title='High Bounce Rate Alert',
                    description=f'Bounce rate of {bounce_rate.value:.1f}% exceeds acceptable threshold',
                    action='Implement email validation service and clean mailing list',
                    impact='High - Damages sender reputation',
                    effort='medium'
                ))
            
            # Analyze bounce patterns
            bounce_data = sends_df[sends_df['delivery_status'] == 'bounced']
            if not bounce_data.empty:
                bounce_categories = bounce_data['bounce_category'].value_counts()
                
                if bounce_categories.get('invalid_recipient', 0) > 10:
                    recommendations.append(Recommendation(
                        category='data_quality',
                        priority='medium',
                        title='Invalid Email Addresses Detected',
                        description=f'{bounce_categories["invalid_recipient"]} emails bounced due to invalid addresses',
                        action='Implement real-time email validation at signup',
                        impact='Medium - Reduces waste and improves metrics',
                        effort='low'
                    ))
            
            # Analyze sending patterns
            hourly_pattern = sends_df.groupby('send_hour').size()
            if len(hourly_pattern) > 0:
                peak_hour = hourly_pattern.idxmax()
                if peak_hour < 9 or peak_hour > 17:
                    recommendations.append(Recommendation(
                        category='timing',
                        priority='low',
                        title='Optimize Sending Time',
                        description=f'Peak sending at {peak_hour}:00 may not be optimal for engagement',
                        action='Test sending during business hours (9 AM - 5 PM) for better engagement',
                        impact='Medium - May improve open and click rates',
                        effort='low'
                    ))
            
            # Analyze retry patterns
            avg_retries = metrics.get('average_retries')
            if avg_retries and avg_retries.value > 2:
                recommendations.append(Recommendation(
                    category='performance',
                    priority='medium',
                    title='High Retry Rate',
                    description=f'Average {avg_retries.value:.1f} retries per email indicates connection issues',
                    action='Review SMTP server reliability and implement connection pooling',
                    impact='Medium - Improves sending efficiency',
                    effort='high'
                ))
            
            # Performance recommendations based on sending velocity
            velocity = metrics.get('sending_velocity')
            if velocity and velocity.value < 50:
                recommendations.append(Recommendation(
                    category='performance',
                    priority='low',
                    title='Low Sending Velocity',
                    description=f'Sending rate of {velocity.value:.1f} emails/hour is below optimal',
                    action='Consider increasing batch size and reducing delays between sends',
                    impact='Low - Improves campaign completion time',
                    effort='low'
                ))
            
        except Exception as e:
            logger.error(f"Recommendation generation failed: {str(e)}")
        
        return recommendations
    
    def _generate_predictions(self, sends_df: pd.DataFrame,
                            campaign_data: Dict[str, Any]) -> Dict[str, Metric]:
        """Generate ML-based predictions (placeholder for advanced ML features)"""
        predictions = {}
        
        try:
            # Placeholder for future ML implementations
            # - Predict optimal send times
            # - Forecast bounce rates
            # - Recommend segment targeting
            
            # Simple trend prediction based on historical data
            if len(sends_df) > 100:
                # Calculate delivery trend
                sends_df['hour_block'] = sends_df['send_hour'] // 4
                hourly_delivery = sends_df.groupby('hour_block')['delivery_status'].apply(
                    lambda x: (x == 'sent').mean() * 100
                )
                
                if len(hourly_delivery) > 1:
                    trend = 'up' if hourly_delivery.iloc[-1] > hourly_delivery.iloc[0] else 'down'
                    predictions['delivery_trend'] = Metric(
                        name='Predicted Delivery Trend',
                        value=hourly_delivery.iloc[-1],
                        unit='%',
                        trend=trend,
                        status='good' if trend == 'up' else 'warning'
                    )
            
        except Exception as e:
            logger.error(f"Prediction generation failed: {str(e)}")
        
        return predictions
    
    def _create_summary(self, metrics: Dict[str, Metric],
                       sends_df: pd.DataFrame) -> Dict[str, Any]:
        """Create executive summary of campaign performance"""
        summary = {
            'total_emails': len(sends_df),
            'timeframe': {
                'start': sends_df['sent_at'].min().isoformat() if not sends_df.empty else None,
                'end': sends_df['sent_at'].max().isoformat() if not sends_df.empty else None
            },
            'key_insights': [],
            'health_score': 0
        }
        
        try:
            # Calculate overall health score
            health_components = []
            
            delivery_rate = metrics.get('delivery_rate')
            if delivery_rate:
                health_components.append(min(delivery_rate.value, 100))
                
                if delivery_rate.value >= 98:
                    summary['key_insights'].append("Excellent delivery performance")
                elif delivery_rate.value >= 95:
                    summary['key_insights'].append("Good delivery performance")
                else:
                    summary['key_insights'].append("Delivery performance needs improvement")
            
            bounce_rate = metrics.get('bounce_rate')
            if bounce_rate:
                # Invert bounce rate for health score (lower is better)
                health_components.append(max(0, 100 - bounce_rate.value * 10))
                
                if bounce_rate.value <= 2:
                    summary['key_insights'].append("List quality is excellent")
                elif bounce_rate.value <= 5:
                    summary['key_insights'].append("List quality is acceptable")
                else:
                    summary['key_insights'].append("List quality needs attention")
            
            if health_components:
                summary['health_score'] = sum(health_components) / len(health_components)
            
            # Add performance insights
            if summary['total_emails'] > 1000:
                summary['key_insights'].append("Large-scale campaign successfully processed")
            
        except Exception as e:
            logger.error(f"Summary creation failed: {str(e)}")
        
        return summary
    
    def get_realtime_updates(self, campaign_id: str) -> Dict[str, Any]:
        """Get real-time updates for active campaigns"""
        try:
            # Get latest metrics with minimal processing for speed
            cache_key = f"realtime:{campaign_id}"
            cached_data = redis_client.get(cache_key)
            
            if cached_data:
                return json.loads(cached_data)
            
            # Generate lightweight real-time metrics
            sends_df = self._load_email_sends_data(campaign_id)
            
            if sends_df.empty:
                return {'error': 'No data available'}
            
            # Calculate basic real-time metrics
            total = len(sends_df)
            sent = len(sends_df[sends_df['delivery_status'] == 'sent'])
            failed = len(sends_df[sends_df['delivery_status'] == 'failed'])
            bounced = len(sends_df[sends_df['delivery_status'] == 'bounced'])
            
            realtime_data = {
                'timestamp': datetime.utcnow().isoformat(),
                'total_processed': total,
                'successful': sent,
                'failed': failed,
                'bounced': bounced,
                'delivery_rate': (sent / total) * 100 if total > 0 else 0,
                'bounce_rate': (bounced / total) * 100 if total > 0 else 0,
                'last_activity': sends_df['sent_at'].max().isoformat() if not sends_df.empty else None
            }
            
            # Cache for 10 seconds
            redis_client.setex(cache_key, 10, json.dumps(realtime_data))
            
            return realtime_data
            
        except Exception as e:
            logger.error(f"Real-time updates failed for {campaign_id}: {str(e)}")
            return {'error': str(e)}


# Singleton instance for application use
analytics_service = EmailAnalytics()

