// System monitoring and API communication functions

class SystemMonitor {
    constructor() {
        this.isActive = false;
        this.updateInterval = 5000; // 5 seconds
        this.intervalId = null;
        this.callbacks = {};
    }

    start() {
        if (this.isActive) return;
        
        this.isActive = true;
        this.update(); // Initial update
        this.intervalId = setInterval(() => this.update(), this.updateInterval);
        
        console.log('System monitoring started');
    }

    stop() {
        if (!this.isActive) return;
        
        this.isActive = false;
        if (this.intervalId) {
            clearInterval(this.intervalId);
            this.intervalId = null;
        }
        
        console.log('System monitoring stopped');
    }

    on(event, callback) {
        if (!this.callbacks[event]) {
            this.callbacks[event] = [];
        }
        this.callbacks[event].push(callback);
    }

    emit(event, data) {
        if (this.callbacks[event]) {
            this.callbacks[event].forEach(callback => callback(data));
        }
    }

    async update() {
        try {
            // Fetch all monitoring data in parallel
            const [status, systemStats, alerts, suspiciousProcesses, keyboardPatterns] = await Promise.all([
                this.fetchStatus(),
                this.fetchSystemStats(),
                this.fetchAlerts(),
                this.fetchSuspiciousProcesses(),
                this.fetchKeyboardPatterns()
            ]);

            // Emit events with updated data
            this.emit('status', status);
            this.emit('systemStats', systemStats);
            this.emit('alerts', alerts);
            this.emit('suspiciousProcesses', suspiciousProcesses);
            this.emit('keyboardPatterns', keyboardPatterns);

        } catch (error) {
            console.error('Error updating monitoring data:', error);
            this.emit('error', error);
        }
    }

    async fetchStatus() {
        const response = await fetch('/api/status');
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return await response.json();
    }

    async fetchSystemStats() {
        const response = await fetch('/api/system-stats');
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return await response.json();
    }

    async fetchAlerts() {
        const response = await fetch('/api/alerts');
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return await response.json();
    }

    async fetchSuspiciousProcesses() {
        const response = await fetch('/api/suspicious-processes');
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return await response.json();
    }

    async fetchKeyboardPatterns() {
        const response = await fetch('/api/keyboard-patterns');
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return await response.json();
    }

    async triggerScan() {
        const response = await fetch('/api/scan-now', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        });
        
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return await response.json();
    }

    async getProcessDetails(pid) {
        const response = await fetch(`/api/process-details/${pid}`);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return await response.json();
    }

    async sendKeyboardEvent(eventData) {
        const response = await fetch('/api/keyboard-event', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(eventData)
        });
        
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return await response.json();
    }
}

// Utility functions for data formatting and display
class MonitorUtils {
    static formatBytes(bytes) {
        if (bytes === 0) return '0 Bytes';
        
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    static formatUptime(seconds) {
        const days = Math.floor(seconds / 86400);
        const hours = Math.floor((seconds % 86400) / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        
        if (days > 0) {
            return `${days}d ${hours}h ${minutes}m`;
        } else if (hours > 0) {
            return `${hours}h ${minutes}m`;
        } else {
            return `${minutes}m`;
        }
    }

    static formatTimestamp(timestamp) {
        const date = new Date(timestamp);
        return date.toLocaleString();
    }

    static getSeverityColor(severity) {
        switch (severity?.toLowerCase()) {
            case 'high': return 'danger';
            case 'medium': return 'warning';
            case 'low': return 'info';
            default: return 'secondary';
        }
    }

    static getRiskColor(risk) {
        switch (risk?.toLowerCase()) {
            case 'high': return 'danger';
            case 'medium': return 'warning';
            case 'low': return 'info';
            default: return 'secondary';
        }
    }

    static getAlertIcon(type) {
        switch (type) {
            case 'process': return 'fas fa-exclamation-triangle';
            case 'keyboard': return 'fas fa-keyboard';
            case 'network': return 'fas fa-wifi';
            case 'manual_scan': return 'fas fa-search';
            default: return 'fas fa-bell';
        }
    }

    static truncateText(text, maxLength = 50) {
        if (!text) return '';
        if (text.length <= maxLength) return text;
        return text.substring(0, maxLength) + '...';
    }

    static debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }

    static throttle(func, limit) {
        let inThrottle;
        return function(...args) {
            if (!inThrottle) {
                func.apply(this, args);
                inThrottle = true;
                setTimeout(() => inThrottle = false, limit);
            }
        };
    }
}

// Notification system for alerts
class NotificationManager {
    constructor() {
        this.notifications = [];
        this.maxNotifications = 5;
        this.requestPermission();
    }

    async requestPermission() {
        if ('Notification' in window) {
            if (Notification.permission === 'default') {
                await Notification.requestPermission();
            }
        }
    }

    show(title, options = {}) {
        const notification = {
            id: Date.now(),
            title,
            options,
            timestamp: new Date()
        };

        // Add to internal list
        this.notifications.unshift(notification);
        if (this.notifications.length > this.maxNotifications) {
            this.notifications.pop();
        }

        // Show browser notification if permission granted
        if ('Notification' in window && Notification.permission === 'granted') {
            const browserNotification = new Notification(title, {
                icon: '/static/favicon.ico',
                badge: '/static/favicon.ico',
                ...options
            });

            // Auto-close after 5 seconds
            setTimeout(() => {
                browserNotification.close();
            }, 5000);

            browserNotification.onclick = () => {
                window.focus();
                browserNotification.close();
            };
        }

        return notification;
    }

    showAlert(alert) {
        const severity = alert.severity || 'info';
        const title = `Security Alert: ${alert.type.replace('_', ' ').toUpperCase()}`;
        
        this.show(title, {
            body: alert.message,
            tag: alert.type,
            requireInteraction: severity === 'high'
        });
    }

    clear() {
        this.notifications = [];
    }

    getRecent(count = 5) {
        return this.notifications.slice(0, count);
    }
}

// Initialize global instances
window.systemMonitor = new SystemMonitor();
window.monitorUtils = new MonitorUtils();
window.notificationManager = new NotificationManager();

// Export for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        SystemMonitor,
        MonitorUtils,
        NotificationManager
    };
}
