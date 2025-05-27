// Keyboard detection and behavioral analysis

class KeyboardDetector {
    constructor() {
        this.isActive = false;
        this.events = [];
        this.maxEvents = 1000;
        this.analysisInterval = 2000; // 2 seconds
        this.lastAnalysis = 0;
        this.patterns = {
            typingSpeed: [],
            intervals: [],
            sequences: [],
            applications: new Set()
        };
        this.suspiciousThresholds = {
            maxWPM: 200,
            minInterval: 0.01,
            maxInterval: 2.0,
            repetitionLimit: 5
        };
    }

    start() {
        if (this.isActive) return;
        
        this.isActive = true;
        this.attachListeners();
        console.log('Keyboard detection started');
    }

    stop() {
        if (!this.isActive) return;
        
        this.isActive = false;
        this.detachListeners();
        console.log('Keyboard detection stopped');
    }

    attachListeners() {
        // Keyboard event listeners
        document.addEventListener('keydown', this.handleKeyEvent.bind(this), true);
        document.addEventListener('keyup', this.handleKeyEvent.bind(this), true);
        
        // Focus tracking for application context
        window.addEventListener('focus', this.handleFocusEvent.bind(this));
        window.addEventListener('blur', this.handleFocusEvent.bind(this));
        
        // Mouse events to detect potential overlay attacks
        document.addEventListener('mousedown', this.handleMouseEvent.bind(this), true);
        document.addEventListener('mouseup', this.handleMouseEvent.bind(this), true);
    }

    detachListeners() {
        document.removeEventListener('keydown', this.handleKeyEvent.bind(this), true);
        document.removeEventListener('keyup', this.handleKeyEvent.bind(this), true);
        window.removeEventListener('focus', this.handleFocusEvent.bind(this));
        window.removeEventListener('blur', this.handleFocusEvent.bind(this));
        document.removeEventListener('mousedown', this.handleMouseEvent.bind(this), true);
        document.removeEventListener('mouseup', this.handleMouseEvent.bind(this), true);
    }

    handleKeyEvent(event) {
        if (!this.isActive) return;

        const eventData = {
            type: event.type,
            key: this.sanitizeKey(event.key),
            code: event.code,
            timestamp: performance.now(),
            target: this.getTargetInfo(event.target),
            metaKeys: {
                ctrl: event.ctrlKey,
                alt: event.altKey,
                shift: event.shiftKey,
                meta: event.metaKey
            }
        };

        this.recordEvent(eventData);
        
        // Perform real-time analysis
        if (Date.now() - this.lastAnalysis > this.analysisInterval) {
            this.performAnalysis();
            this.lastAnalysis = Date.now();
        }
    }

    handleFocusEvent(event) {
        const eventData = {
            type: 'focus_change',
            focus: event.type === 'focus',
            timestamp: performance.now(),
            target: 'window'
        };

        this.recordEvent(eventData);
    }

    handleMouseEvent(event) {
        // Track mouse events to detect overlay attacks
        const eventData = {
            type: 'mouse_' + event.type,
            button: event.button,
            timestamp: performance.now(),
            coordinates: {
                x: event.clientX,
                y: event.clientY
            },
            target: this.getTargetInfo(event.target)
        };

        this.recordEvent(eventData);
    }

    sanitizeKey(key) {
        // Remove potentially sensitive data while keeping structure
        if (key.length === 1 && key.match(/[a-zA-Z0-9]/)) {
            return 'alphanumeric';
        }
        
        // Keep special keys for pattern analysis
        const allowedKeys = [
            'Enter', 'Tab', 'Space', 'Backspace', 'Delete', 
            'Escape', 'ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight',
            'Home', 'End', 'PageUp', 'PageDown', 'Insert'
        ];
        
        return allowedKeys.includes(key) ? key : 'other';
    }

    getTargetInfo(target) {
        if (!target) return 'unknown';
        
        return {
            tagName: target.tagName?.toLowerCase() || 'unknown',
            type: target.type || null,
            className: target.className || null,
            id: target.id || null
        };
    }

    recordEvent(eventData) {
        this.events.push(eventData);
        
        // Maintain maximum event history
        if (this.events.length > this.maxEvents) {
            this.events.shift();
        }

        // Track applications
        if (eventData.target && eventData.target !== 'window') {
            this.patterns.applications.add(this.getApplicationSignature(eventData.target));
        }
    }

    getApplicationSignature(target) {
        if (typeof target === 'object') {
            return `${target.tagName}-${target.type || 'none'}`;
        }
        return target;
    }

    performAnalysis() {
        if (this.events.length < 10) return;

        const recentEvents = this.events.slice(-50); // Analyze last 50 events
        const analysis = {
            timestamp: Date.now(),
            suspicious: false,
            confidence: 0,
            reasons: [],
            patterns: this.analyzePatterns(recentEvents)
        };

        // Analyze typing speed
        const speedAnalysis = this.analyzeTypingSpeed(recentEvents);
        if (speedAnalysis.suspicious) {
            analysis.suspicious = true;
            analysis.confidence += 0.3;
            analysis.reasons.push(...speedAnalysis.reasons);
        }

        // Analyze rhythm patterns
        const rhythmAnalysis = this.analyzeRhythm(recentEvents);
        if (rhythmAnalysis.suspicious) {
            analysis.suspicious = true;
            analysis.confidence += 0.25;
            analysis.reasons.push(...rhythmAnalysis.reasons);
        }

        // Analyze key sequences
        const sequenceAnalysis = this.analyzeSequences(recentEvents);
        if (sequenceAnalysis.suspicious) {
            analysis.suspicious = true;
            analysis.confidence += 0.2;
            analysis.reasons.push(...sequenceAnalysis.reasons);
        }

        // Analyze overlay indicators
        const overlayAnalysis = this.analyzeOverlayIndicators(recentEvents);
        if (overlayAnalysis.suspicious) {
            analysis.suspicious = true;
            analysis.confidence += 0.4;
            analysis.reasons.push(...overlayAnalysis.reasons);
        }

        // Send to backend for processing
        if (analysis.suspicious) {
            this.reportSuspiciousActivity(analysis);
        }

        return analysis;
    }

    analyzeTypingSpeed(events) {
        const keyEvents = events.filter(e => e.type === 'keydown' && e.key === 'alphanumeric');
        const result = { suspicious: false, reasons: [] };

        if (keyEvents.length < 5) return result;

        const timeSpan = (keyEvents[keyEvents.length - 1].timestamp - keyEvents[0].timestamp) / 1000;
        const wpm = (keyEvents.length / timeSpan) * 60 / 5; // Assuming 5 chars per word

        if (wpm > this.suspiciousThresholds.maxWPM) {
            result.suspicious = true;
            result.reasons.push(`Impossibly fast typing: ${wpm.toFixed(1)} WPM`);
        }

        return result;
    }

    analyzeRhythm(events) {
        const keyEvents = events.filter(e => e.type === 'keydown');
        const result = { suspicious: false, reasons: [] };

        if (keyEvents.length < 10) return result;

        const intervals = [];
        for (let i = 1; i < keyEvents.length; i++) {
            const interval = (keyEvents[i].timestamp - keyEvents[i-1].timestamp) / 1000;
            intervals.push(interval);
        }

        // Check for mechanical patterns
        const avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
        const variance = intervals.reduce((acc, val) => acc + Math.pow(val - avgInterval, 2), 0) / intervals.length;
        const stdDev = Math.sqrt(variance);

        // Too consistent (robotic)
        if (stdDev < this.suspiciousThresholds.minInterval && avgInterval < 0.5) {
            result.suspicious = true;
            result.reasons.push('Mechanical typing rhythm detected');
        }

        // Too inconsistent (possibly overlayed)
        if (stdDev > this.suspiciousThresholds.maxInterval) {
            result.suspicious = true;
            result.reasons.push('Highly irregular typing pattern');
        }

        return result;
    }

    analyzeSequences(events) {
        const keyEvents = events.filter(e => e.type === 'keydown');
        const result = { suspicious: false, reasons: [] };

        if (keyEvents.length < 5) return result;

        // Check for repetitive patterns
        const recentKeys = keyEvents.slice(-10).map(e => e.key);
        const uniqueKeys = new Set(recentKeys);

        if (uniqueKeys.size <= 2 && recentKeys.length >= this.suspiciousThresholds.repetitionLimit) {
            result.suspicious = true;
            result.reasons.push('Repetitive key pattern detected');
        }

        // Check for suspicious key combinations
        const metaKeyUsage = keyEvents.filter(e => 
            e.metaKeys.ctrl || e.metaKeys.alt || e.metaKeys.meta
        ).length;

        if (metaKeyUsage > keyEvents.length * 0.3) {
            result.suspicious = true;
            result.reasons.push('Excessive meta key usage');
        }

        return result;
    }

    analyzeOverlayIndicators(events) {
        const result = { suspicious: false, reasons: [] };

        // Check for simultaneous mouse and keyboard activity
        const mouseEvents = events.filter(e => e.type.startsWith('mouse_'));
        const keyEvents = events.filter(e => e.type === 'keydown');

        if (mouseEvents.length > 0 && keyEvents.length > 0) {
            // Check for overlapping timestamps
            const overlaps = keyEvents.filter(keyEvent => {
                return mouseEvents.some(mouseEvent => 
                    Math.abs(keyEvent.timestamp - mouseEvent.timestamp) < 100
                );
            });

            if (overlaps.length > 2) {
                result.suspicious = true;
                result.reasons.push('Simultaneous mouse and keyboard activity');
            }
        }

        // Check for focus changes during typing
        const focusEvents = events.filter(e => e.type === 'focus_change');
        if (focusEvents.length > 3 && keyEvents.length > 0) {
            result.suspicious = true;
            result.reasons.push('Frequent focus changes during input');
        }

        return result;
    }

    analyzePatterns(events) {
        return {
            totalEvents: events.length,
            keyboardEvents: events.filter(e => e.type.includes('key')).length,
            mouseEvents: events.filter(e => e.type.includes('mouse')).length,
            focusEvents: events.filter(e => e.type === 'focus_change').length,
            uniqueTargets: new Set(events.map(e => this.getApplicationSignature(e.target))).size,
            timeSpan: events.length > 0 ? 
                (events[events.length - 1].timestamp - events[0].timestamp) / 1000 : 0
        };
    }

    async reportSuspiciousActivity(analysis) {
        try {
            const eventData = {
                timestamp: analysis.timestamp,
                type: 'behavioral_analysis',
                suspicious: analysis.suspicious,
                confidence: analysis.confidence,
                reasons: analysis.reasons,
                patterns: analysis.patterns,
                user_agent: navigator.userAgent,
                target_app: 'web_browser'
            };

            const response = await fetch('/api/keyboard-event', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(eventData)
            });

            if (!response.ok) {
                console.error('Failed to report suspicious activity');
            }

        } catch (error) {
            console.error('Error reporting suspicious activity:', error);
        }
    }

    getStatistics() {
        return {
            totalEvents: this.events.length,
            isActive: this.isActive,
            patterns: {
                ...this.patterns,
                applications: Array.from(this.patterns.applications)
            },
            recentActivity: this.events.slice(-10)
        };
    }

    reset() {
        this.events = [];
        this.patterns = {
            typingSpeed: [],
            intervals: [],
            sequences: [],
            applications: new Set()
        };
        console.log('Keyboard detector reset');
    }
}

// Initialize keyboard detection when DOM is ready
function initKeyboardDetection() {
    if (!window.keyboardDetector) {
        window.keyboardDetector = new KeyboardDetector();
        window.keyboardDetector.start();
        
        // Auto-start detection
        console.log('Keyboard detection initialized and started');
    }
}

// Export for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { KeyboardDetector };
}

// Auto-initialize when included
if (typeof window !== 'undefined') {
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initKeyboardDetection);
    } else {
        initKeyboardDetection();
    }
}
