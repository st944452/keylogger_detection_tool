import time
import statistics
from collections import defaultdict, deque
from datetime import datetime, timedelta

class KeyloggerDetector:
    """Advanced keylogger detection through behavioral analysis"""
    
    def __init__(self):
        # Timing analysis
        self.keystroke_times = deque(maxlen=1000)
        self.typing_patterns = defaultdict(list)
        
        # Pattern detection
        self.suspicious_sequences = []
        self.last_events = deque(maxlen=50)
        
        # Statistical baselines
        self.baseline_wpm = None
        self.baseline_rhythm = None
        self.user_patterns = {}
        
        # Suspicious indicators
        self.suspicious_apps = [
            'keylogger', 'spyware', 'monitor', 'capture', 'hook',
            'remote', 'spy', 'stealth', 'hidden', 'background'
        ]
        
        # Alert thresholds
        self.rapid_typing_threshold = 200  # WPM
        self.unusual_rhythm_threshold = 2.0  # Standard deviations
        self.suspicious_sequence_length = 5
    
    def analyze_event(self, event_data):
        """Analyze a keyboard event for suspicious patterns"""
        try:
            timestamp = event_data.get('timestamp', time.time())
            key = event_data.get('key', '')
            event_type = event_data.get('type', 'keydown')
            target_app = event_data.get('target_app', 'unknown')
            
            # Store event for pattern analysis
            self.last_events.append({
                'timestamp': timestamp,
                'key': key,
                'type': event_type,
                'target_app': target_app
            })
            
            analysis_result = {
                'suspicious': False,
                'confidence': 0.0,
                'reasons': [],
                'severity': 'low'
            }
            
            # Analyze typing speed
            speed_analysis = self._analyze_typing_speed(timestamp)
            if speed_analysis['suspicious']:
                analysis_result['suspicious'] = True
                analysis_result['reasons'].extend(speed_analysis['reasons'])
                analysis_result['confidence'] += 0.3
            
            # Analyze rhythm patterns
            rhythm_analysis = self._analyze_rhythm_patterns()
            if rhythm_analysis['suspicious']:
                analysis_result['suspicious'] = True
                analysis_result['reasons'].extend(rhythm_analysis['reasons'])
                analysis_result['confidence'] += 0.25
            
            # Check for suspicious key sequences
            sequence_analysis = self._analyze_key_sequences()
            if sequence_analysis['suspicious']:
                analysis_result['suspicious'] = True
                analysis_result['reasons'].extend(sequence_analysis['reasons'])
                analysis_result['confidence'] += 0.2
            
            # Check target application
            app_analysis = self._analyze_target_app(target_app)
            if app_analysis['suspicious']:
                analysis_result['suspicious'] = True
                analysis_result['reasons'].extend(app_analysis['reasons'])
                analysis_result['confidence'] += 0.4
            
            # Determine severity based on confidence
            if analysis_result['confidence'] >= 0.7:
                analysis_result['severity'] = 'high'
            elif analysis_result['confidence'] >= 0.4:
                analysis_result['severity'] = 'medium'
            
            # Generate alert message
            if analysis_result['suspicious']:
                analysis_result['message'] = self._generate_alert_message(analysis_result)
            
            return analysis_result
            
        except Exception as e:
            print(f"Error analyzing keyboard event: {e}")
            return {'suspicious': False, 'error': str(e)}
    
    def _analyze_typing_speed(self, current_time):
        """Analyze typing speed for anomalies"""
        self.keystroke_times.append(current_time)
        
        result = {'suspicious': False, 'reasons': []}
        
        if len(self.keystroke_times) >= 10:
            # Calculate current WPM
            time_span = self.keystroke_times[-1] - self.keystroke_times[-10]
            if time_span > 0:
                current_wpm = (10 / time_span) * 60 / 5  # Assuming 5 chars per word
                
                # Check for impossibly fast typing
                if current_wpm > self.rapid_typing_threshold:
                    result['suspicious'] = True
                    result['reasons'].append(f"Impossibly fast typing detected: {current_wpm:.1f} WPM")
                
                # Check against baseline if established
                if self.baseline_wpm and abs(current_wpm - self.baseline_wpm) > 50:
                    result['suspicious'] = True
                    result['reasons'].append(f"Typing speed deviation from baseline: {current_wpm:.1f} vs {self.baseline_wpm:.1f} WPM")
        
        return result
    
    def _analyze_rhythm_patterns(self):
        """Analyze keystroke rhythm for mechanical patterns"""
        result = {'suspicious': False, 'reasons': []}
        
        if len(self.last_events) >= 10:
            # Calculate inter-keystroke intervals
            intervals = []
            for i in range(1, len(self.last_events)):
                interval = self.last_events[i]['timestamp'] - self.last_events[i-1]['timestamp']
                intervals.append(interval)
            
            if len(intervals) >= 5:
                # Check for unnaturally consistent timing (possible automated input)
                std_dev = statistics.stdev(intervals)
                mean_interval = statistics.mean(intervals)
                
                # Very low variance might indicate automated input
                if std_dev < 0.01 and mean_interval < 0.5:
                    result['suspicious'] = True
                    result['reasons'].append(f"Mechanical rhythm detected (std dev: {std_dev:.4f})")
                
                # Very high variance might indicate overlayed input
                if std_dev > 1.0:
                    result['suspicious'] = True
                    result['reasons'].append(f"Highly irregular timing pattern (std dev: {std_dev:.4f})")
        
        return result
    
    def _analyze_key_sequences(self):
        """Analyze for suspicious key sequences"""
        result = {'suspicious': False, 'reasons': []}
        
        if len(self.last_events) >= 5:
            # Extract recent key sequence
            recent_keys = [event['key'] for event in list(self.last_events)[-10:]]
            sequence = ''.join(recent_keys).lower()
            
            # Check for suspicious patterns
            suspicious_patterns = [
                'password', 'login', 'admin', 'root', 'key', 'secret',
                'bank', 'card', 'ssn', 'social', 'account'
            ]
            
            for pattern in suspicious_patterns:
                if pattern in sequence:
                    result['suspicious'] = True
                    result['reasons'].append(f"Potentially sensitive data pattern detected: {pattern}")
            
            # Check for repetitive patterns that might indicate automated input
            if len(set(recent_keys)) <= 2 and len(recent_keys) >= 5:
                result['suspicious'] = True
                result['reasons'].append("Repetitive key pattern detected")
        
        return result
    
    def _analyze_target_app(self, target_app):
        """Analyze the target application for suspicious characteristics"""
        result = {'suspicious': False, 'reasons': []}
        
        if target_app and target_app != 'unknown':
            app_lower = target_app.lower()
            
            # Check if app name contains suspicious keywords
            for suspicious_term in self.suspicious_apps:
                if suspicious_term in app_lower:
                    result['suspicious'] = True
                    result['reasons'].append(f"Input directed to suspicious application: {target_app}")
                    break
            
            # Check for hidden or unusual applications
            if 'hidden' in app_lower or 'background' in app_lower:
                result['suspicious'] = True
                result['reasons'].append(f"Input captured by hidden/background application: {target_app}")
        
        return result
    
    def _generate_alert_message(self, analysis_result):
        """Generate a human-readable alert message"""
        severity = analysis_result['severity']
        confidence = analysis_result['confidence']
        
        base_message = f"Potential keylogger activity detected (Confidence: {confidence:.1%})"
        
        if analysis_result['reasons']:
            details = "; ".join(analysis_result['reasons'][:3])  # Limit to top 3 reasons
            return f"{base_message}. Details: {details}"
        
        return base_message
    
    def analyze_patterns(self):
        """Analyze overall patterns and return summary"""
        if len(self.last_events) < 5:
            return []
        
        patterns = []
        
        # Analyze recent activity window
        recent_events = list(self.last_events)[-20:]
        
        # Calculate metrics
        if len(recent_events) >= 2:
            time_span = recent_events[-1]['timestamp'] - recent_events[0]['timestamp']
            if time_span > 0:
                events_per_second = len(recent_events) / time_span
                
                patterns.append({
                    'type': 'activity_rate',
                    'value': events_per_second,
                    'description': f"Current input rate: {events_per_second:.2f} events/second",
                    'timestamp': datetime.now().isoformat()
                })
        
        # Application diversity
        apps = set(event.get('target_app', 'unknown') for event in recent_events)
        patterns.append({
            'type': 'app_diversity',
            'value': len(apps),
            'description': f"Active applications: {len(apps)}",
            'timestamp': datetime.now().isoformat()
        })
        
        return patterns
    
    def calibrate_baseline(self, events):
        """Calibrate baseline typing patterns from user data"""
        if len(events) < 50:
            return False
        
        # Calculate baseline WPM
        timestamps = [event['timestamp'] for event in events]
        time_span = timestamps[-1] - timestamps[0]
        if time_span > 0:
            self.baseline_wpm = (len(events) / time_span) * 60 / 5
        
        # Calculate baseline rhythm
        intervals = []
        for i in range(1, len(events)):
            interval = events[i]['timestamp'] - events[i-1]['timestamp']
            intervals.append(interval)
        
        if intervals:
            self.baseline_rhythm = {
                'mean': statistics.mean(intervals),
                'std_dev': statistics.stdev(intervals) if len(intervals) > 1 else 0
            }
        
        return True
