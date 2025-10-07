// static/js/dashboard.js
/**
 * Real-time Analytics Dashboard Client
 * Handles WebSocket connections and chart updates
 */

class AnalyticsDashboard {
    constructor(campaignId) {
        this.campaignId = campaignId;
        this.socket = null;
        this.charts = {};
        this.updateInterval = null;
        this.isConnected = false;
        
        this.init();
    }
    
    init() {
        this.connectWebSocket();
        this.setupEventListeners();
        this.startPeriodicUpdates();
    }
    
    connectWebSocket() {
        console.log('Connecting to analytics WebSocket...');
        
        this.socket = io('/');
        
        this.socket.on('connect', () => {
            console.log('Connected to analytics server');
            this.isConnected = true;
            this.updateConnectionStatus(true);
            
            // Subscribe to campaign updates
            this.socket.emit('subscribe_campaign_updates', {
                campaign_id: this.campaignId
            });
        });
        
        this.socket.on('disconnect', () => {
            console.log('Disconnected from analytics server');
            this.isConnected = false;
            this.updateConnectionStatus(false);
        });
        
        this.socket.on('campaign_metrics_update', (data) => {
            console.log('Received metrics update:', data);
            this.updateDashboard(data.data);
        });
        
        this.socket.on('error', (error) => {
            console.error('WebSocket error:', error);
            this.showError(error.message);
        });
    }
    
    updateConnectionStatus(connected) {
        const statusElement = document.getElementById('connection-status');
        if (statusElement) {
            statusElement.className = connected ? 'status-connected' : 'status-disconnected';
            statusElement.textContent = connected ? 'Connected' : 'Disconnected';
        }
    }
    
    updateDashboard(metricsData) {
        if (!metricsData) return;
        
        // Update metrics cards
        this.updateMetricsCards(metricsData);
        
        // Update progress indicators
        this.updateProgressIndicators(metricsData);
        
        // Update timestamp
        this.updateLastUpdated();
    }
    
    updateMetricsCards(data) {
        // Update delivery rate
        const deliveryRate = data.delivery_rate || 0;
        this.updateMetricCard('delivery-rate', deliveryRate.toFixed(1), '%');
        
        // Update bounce rate
        const bounceRate = data.bounce_rate || 0;
        this.updateMetricCard('bounce-rate', bounceRate.toFixed(1), '%');
        
        // Update total processed
        const totalProcessed = data.total_processed || 0;
        this.updateMetricCard('total-processed', totalProcessed.toLocaleString(), '');
        
        // Update successful sends
        const successful = data.successful || 0;
        this.updateMetricCard('successful-sends', successful.toLocaleString(), '');
    }
    
    updateMetricCard(cardId, value, unit) {
        const valueElement = document.getElementById(`${cardId}-value`);
        const unitElement = document.getElementById(`${cardId}-unit`);
        
        if (valueElement) {
            valueElement.textContent = value;
            // Add animation class
            valueElement.classList.add('metric-updated');
            setTimeout(() => valueElement.classList.remove('metric-updated'), 1000);
        }
        
        if (unitElement) {
            unitElement.textContent = unit;
        }
    }
    
    updateProgressIndicators(data) {
        const deliveryRate = data.delivery_rate || 0;
        const bounceRate = data.bounce_rate || 0;
        
        // Update delivery rate progress bar
        this.updateProgressBar('delivery-progress', deliveryRate, 100);
        
        // Update bounce rate progress bar (inverted - lower is better)
        this.updateProgressBar('bounce-progress', bounceRate, 10, true);
    }
    
    updateProgressBar(progressId, value, maxValue, inverted = false) {
        const progressElement = document.getElementById(progressId);
        if (progressElement) {
            const percentage = Math.min((value / maxValue) * 100, 100);
            progressElement.style.width = `${percentage}%`;
            
            // Update color based on performance
            let colorClass = 'progress-good';
            if (inverted) {
                if (value > maxValue * 0.7) colorClass = 'progress-critical';
                else if (value > maxValue * 0.4) colorClass = 'progress-warning';
            } else {
                if (value < maxValue * 0.7) colorClass = 'progress-critical';
                else if (value < maxValue * 0.9) colorClass = 'progress-warning';
            }
            
            progressElement.className = `progress-bar ${colorClass}`;
        }
    }
    
    updateLastUpdated() {
        const timestampElement = document.getElementById('last-updated');
        if (timestampElement) {
            timestampElement.textContent = `Last updated: ${new Date().toLocaleTimeString()}`;
        }
    }
    
    loadFullAnalytics() {
        console.log('Loading full analytics...');
        
        fetch(`/api/analytics/campaigns/${this.campaignId}/metrics?predictions=true`)
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    this.showError(data.error);
                    return;
                }
                
                this.renderCharts(data.charts);
                this.renderRecommendations(data.recommendations);
                this.updateSummary(data.summary);
            })
            .catch(error => {
                console.error('Failed to load analytics:', error);
                this.showError('Failed to load analytics data');
            });
    }
    
    renderCharts(chartsData) {
        Object.entries(chartsData).forEach(([chartId, chartConfig]) => {
            const container = document.getElementById(`chart-${chartId}`);
            if (container && chartConfig.data) {
                Plotly.newPlot(container, chartConfig.data.data, chartConfig.data.layout, {
                    responsive: true,
                    displayModeBar: false
                });
            }
        });
    }
    
    renderRecommendations(recommendations) {
        const container = document.getElementById('recommendations-container');
        if (!container) return;
        
        container.innerHTML = '';
        
        recommendations.forEach(rec => {
            const recElement = document.createElement('div');
            recElement.className = `recommendation recommendation-${rec.priority}`;
            recElement.innerHTML = `
                <div class="recommendation-header">
                    <span class="recommendation-title">${rec.title}</span>
                    <span class="recommendation-priority">${rec.priority.toUpperCase()}</span>
                </div>
                <div class="recommendation-description">${rec.description}</div>
                <div class="recommendation-action">
                    <strong>Action:</strong> ${rec.action}
                </div>
                <div class="recommendation-meta">
                    <span>Impact: ${rec.impact}</span> • 
                    <span>Effort: ${rec.effort}</span>
                </div>
            `;
            container.appendChild(recElement);
        });
    }
    
    updateSummary(summary) {
        const healthScore = summary.health_score || 0;
        const healthElement = document.getElementById('health-score');
        
        if (healthElement) {
            healthElement.textContent = `${healthScore.toFixed(0)}%`;
            
            // Update health score color
            let healthClass = 'health-good';
            if (healthScore < 70) healthClass = 'health-critical';
            else if (healthScore < 85) healthClass = 'health-warning';
            
            healthElement.className = `health-score ${healthClass}`;
        }
        
        // Update key insights
        const insightsContainer = document.getElementById('key-insights');
        if (insightsContainer && summary.key_insights) {
            insightsContainer.innerHTML = summary.key_insights
                .map(insight => `<li>${insight}</li>`)
                .join('');
        }
    }
    
    showError(message) {
        const errorContainer = document.getElementById('error-messages');
        if (errorContainer) {
            const errorDiv = document.createElement('div');
            errorDiv.className = 'alert alert-error';
            errorDiv.textContent = message;
            errorContainer.appendChild(errorDiv);
            
            // Auto-remove after 5 seconds
            setTimeout(() => errorDiv.remove(), 5000);
        }
    }
    
    startPeriodicUpdates() {
        // Load full analytics initially
        this.loadFullAnalytics();
        
        // Refresh charts every 5 minutes
        this.updateInterval = setInterval(() => {
            this.loadFullAnalytics();
        }, 5 * 60 * 1000);
    }
    
    setupEventListeners() {
        // Refresh button
        const refreshButton = document.getElementById('refresh-analytics');
        if (refreshButton) {
            refreshButton.addEventListener('click', () => {
                this.loadFullAnalytics();
            });
        }
        
        // Export button
        const exportButton = document.getElementById('export-analytics');
        if (exportButton) {
            exportButton.addEventListener('click', () => {
                this.exportAnalytics();
            });
        }
    }
    
    exportAnalytics() {
        window.open(`/api/analytics/campaigns/${this.campaignId}/export`, '_blank');
    }
    
    destroy() {
        if (this.socket) {
            this.socket.emit('unsubscribe_campaign_updates', {
                campaign_id: this.campaignId
            });
            this.socket.disconnect();
        }
        
        if (this.updateInterval) {
            clearInterval(this.updateInterval);
        }
    }
}

// Initialize dashboard when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    const campaignId = document.getElementById('campaign-id')?.dataset.campaignId;
    if (campaignId) {
        window.analyticsDashboard = new AnalyticsDashboard(campaignId);
    }
});

