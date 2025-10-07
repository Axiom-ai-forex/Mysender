# api/analytics.py
"""
Analytics API endpoints for real-time dashboard
"""

from flask import Blueprint, request, jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room
import logging
from datetime import datetime

from services.analytics import analytics_service

# Create blueprint
analytics_bp = Blueprint('analytics', __name__)
logger = logging.getLogger(__name__)

# SocketIO instance (to be initialized with app)
socketio = None


def init_socketio(app):
    """Initialize SocketIO with Flask app"""
    global socketio
    socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')
    
    # Register SocketIO event handlers
    socketio.on_event('connect', handle_connect)
    socketio.on_event('disconnect', handle_disconnect)
    socketio.on_event('subscribe_campaign_updates', handle_campaign_subscription)
    socketio.on_event('unsubscribe_campaign_updates', handle_campaign_unsubscription)


@analytics_bp.route('/api/analytics/campaigns/<campaign_id>/metrics', methods=['GET'])
def get_campaign_metrics(campaign_id):
    """Get comprehensive campaign metrics"""
    try:
        include_predictions = request.args.get('predictions', 'false').lower() == 'true'
        force_refresh = request.args.get('refresh', 'false').lower() == 'true'
        
        snapshot = analytics_service.get_campaign_metrics(
            campaign_id,
            include_predictions=include_predictions,
            force_refresh=force_refresh
        )
        
        # Convert to JSON-serializable format
        response_data = {
            'timestamp': snapshot.timestamp.isoformat(),
            'campaign_id': snapshot.campaign_id,
            'metrics': {k: {
                'name': v.name,
                'value': v.value,
                'unit': v.unit,
                'trend': v.trend,
                'status': v.status,
                'benchmark': v.benchmark
            } for k, v in snapshot.metrics.items()},
            'charts': snapshot.charts,
            'recommendations': [{
                'category': r.category,
                'priority': r.priority,
                'title': r.title,
                'description': r.description,
                'action': r.action,
                'impact': r.impact,
                'effort': r.effort
            } for r in snapshot.recommendations],
            'summary': snapshot.summary
        }
        
        return jsonify(response_data)
        
    except Exception as e:
        logger.error(f"Failed to get campaign metrics: {str(e)}")
        return jsonify({'error': str(e)}), 500


@analytics_bp.route('/api/analytics/campaigns/<campaign_id>/realtime', methods=['GET'])
def get_realtime_metrics(campaign_id):
    """Get real-time metrics for active campaigns"""
    try:
        realtime_data = analytics_service.get_realtime_updates(campaign_id)
        return jsonify(realtime_data)
        
    except Exception as e:
        logger.error(f"Failed to get real-time metrics: {str(e)}")
        return jsonify({'error': str(e)}), 500


# SocketIO Event Handlers
def handle_connect():
    """Handle client connection"""
    logger.info(f"Client connected: {request.sid}")
    emit('connected', {'message': 'Successfully connected to analytics stream'})


def handle_disconnect():
    """Handle client disconnection"""
    logger.info(f"Client disconnected: {request.sid}")


def handle_campaign_subscription(data):
    """Handle campaign analytics subscription"""
    try:
        campaign_id = data.get('campaign_id')
        if not campaign_id:
            emit('error', {'message': 'Campaign ID is required'})
            return
        
        # Join campaign room
        join_room(f"campaign_{campaign_id}")
        logger.info(f"Client {request.sid} subscribed to campaign {campaign_id}")
        
        # Send initial metrics
        try:
            initial_metrics = analytics_service.get_realtime_updates(campaign_id)
            emit('campaign_metrics_update', {
                'campaign_id': campaign_id,
                'data': initial_metrics
            })
        except Exception as e:
            emit('error', {'message': f'Failed to load initial metrics: {str(e)}'})
        
    except Exception as e:
        logger.error(f"Campaign subscription failed: {str(e)}")
        emit('error', {'message': 'Subscription failed'})


def handle_campaign_unsubscription(data):
    """Handle campaign analytics unsubscription"""
    try:
        campaign_id = data.get('campaign_id')
        if campaign_id:
            leave_room(f"campaign_{campaign_id}")
            logger.info(f"Client {request.sid} unsubscribed from campaign {campaign_id}")
            emit('unsubscribed', {'campaign_id': campaign_id})
        
    except Exception as e:
        logger.error(f"Campaign unsubscription failed: {str(e)}")


def broadcast_campaign_update(campaign_id, update_data):
    """Broadcast update to all subscribers of a campaign"""
    if socketio:
        socketio.emit('campaign_metrics_update', {
            'campaign_id': campaign_id,
            'timestamp': datetime.utcnow().isoformat(),
            'data': update_data
        }, room=f"campaign_{campaign_id}")

