from flask import request, jsonify, current_app
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps
import redis
import json
from datetime import datetime, timedelta
import logging

# Constants for security settings
MAX_LOGIN_ATTEMPTS = 5
LOGIN_ATTEMPT_WINDOW = 900  # 15 minutes in seconds
BLOCK_DURATION = 3600  # 1 hour in seconds
SUSPICIOUS_ACTIVITY_THRESHOLD = 10  # Number of requests before considering suspicious

# Initialize Redis with error handling
try:
    redis_client = redis.Redis(
        host='localhost',
        port=6379,
        db=0,
        decode_responses=True,
        socket_timeout=2,
        socket_connect_timeout=2
    )
    # Test the connection
    redis_client.ping()
except (redis.ConnectionError, redis.TimeoutError) as e:
    logging.warning(f"Redis connection failed: {str(e)}. Using in-memory storage for rate limiting.")
    redis_client = None

# In-memory storage fallback
class MemoryStorage:
    def __init__(self):
        self._storage = {}
        self._timestamps = {}
    
    def get(self, key):
        # Clean expired keys
        self._clean_expired()
        return self._storage.get(key)
    
    def setex(self, key, seconds, value):
        expiry = datetime.utcnow() + timedelta(seconds=seconds)
        self._storage[key] = value
        self._timestamps[key] = expiry
    
    def delete(self, key):
        self._storage.pop(key, None)
        self._timestamps.pop(key, None)
    
    def lpush(self, key, value):
        if key not in self._storage:
            self._storage[key] = []
        self._storage[key].insert(0, value)
    
    def lrange(self, key, start, end):
        return self._storage.get(key, [])[start:end+1]
    
    def ltrim(self, key, start, end):
        if key in self._storage:
            self._storage[key] = self._storage[key][start:end+1]
    
    def expire(self, key, seconds):
        if key in self._storage:
            self._timestamps[key] = datetime.utcnow() + timedelta(seconds=seconds)
    
    def _clean_expired(self):
        now = datetime.utcnow()
        expired = [k for k, v in self._timestamps.items() if v < now]
        for k in expired:
            self.delete(k)

# Use in-memory storage if Redis is not available
storage = redis_client if redis_client is not None else MemoryStorage()

def get_limiter(app):
    return Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=["200 per day", "50 per hour"],
        storage_uri="redis://localhost:6379"
    )

class IPBlocker:
    @staticmethod
    def is_ip_blocked(ip):
        """Check if an IP is blocked"""
        return storage.get(f"blocked:{ip}") is not None

    @staticmethod
    def block_ip(ip, duration=BLOCK_DURATION, reason=""):
        """Block an IP address"""
        storage.setex(f"blocked:{ip}", duration, reason)
        # Log the blocking event
        log_entry = {
            "ip": ip,
            "timestamp": datetime.utcnow().isoformat(),
            "duration": duration,
            "reason": reason
        }
        storage.lpush("ip_block_log", json.dumps(log_entry))

    @staticmethod
    def unblock_ip(ip):
        """Unblock an IP address"""
        storage.delete(f"blocked:{ip}")

    @staticmethod
    def record_failed_login(ip):
        """Record a failed login attempt"""
        key = f"failed_login:{ip}"
        current_attempts = storage.get(key)
        if current_attempts is None:
            current_attempts = 0
        current_attempts = int(current_attempts) + 1
        storage.setex(key, LOGIN_ATTEMPT_WINDOW, str(current_attempts))
        
        if current_attempts >= MAX_LOGIN_ATTEMPTS:
            IPBlocker.block_ip(ip, reason="Too many failed login attempts")
            return True
        return False

    @staticmethod
    def record_request(ip):
        """Record a request from an IP"""
        key = f"requests:{ip}"
        current_requests = storage.get(key)
        if current_requests is None:
            current_requests = 0
        current_requests = int(current_requests) + 1
        storage.setex(key, 3600, str(current_requests))
        
        if current_requests > SUSPICIOUS_ACTIVITY_THRESHOLD:
            if IPBlocker.is_suspicious_pattern(ip):
                IPBlocker.block_ip(ip, reason="Suspicious activity pattern")
                return True
        return False

    @staticmethod
    def is_suspicious_pattern(ip):
        """Check if the IP shows suspicious request patterns"""
        key = f"request_times:{ip}"
        now = datetime.utcnow().timestamp()
        
        storage.lpush(key, str(now))
        storage.ltrim(key, 0, 9)  # Keep last 10 requests
        storage.expire(key, 3600)  # Expire after 1 hour
        
        timestamps = [float(t) for t in storage.lrange(key, 0, -1)]
        
        if len(timestamps) < 5:
            return False
            
        intervals = [timestamps[i] - timestamps[i+1] for i in range(len(timestamps)-1)]
        rapid_requests = sum(1 for interval in intervals if interval < 1)
        
        return rapid_requests >= 3

def ip_block_check():
    """Decorator to check if IP is blocked before processing request"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            ip = get_remote_address()
            
            if IPBlocker.is_ip_blocked(ip):
                return jsonify({
                    "error": "Access denied",
                    "message": "Your IP has been blocked due to suspicious activity"
                }), 403
            
            if IPBlocker.record_request(ip):
                return jsonify({
                    "error": "Access denied",
                    "message": "Suspicious activity detected"
                }), 403
                
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def configure_security(app):
    """Configure security settings for the application"""
    try:
        limiter = get_limiter(app)
        
        # Apply rate limits to specific routes if they exist
        route_limits = {
            'login': "5 per minute",
            'reset_password': "3 per minute",
            'repository': "20 per minute",
            'analytics': "30 per minute"
        }
        
        for route, limit in route_limits.items():
            if route in app.view_functions:
                limiter.limit(limit)(app.view_functions[route])
        
        # Apply general rate limit to all routes
        @app.before_request
        def before_request():
            if IPBlocker.is_ip_blocked(get_remote_address()):
                return jsonify({
                    "error": "Access denied",
                    "message": "Your IP has been blocked due to suspicious activity"
                }), 403

        @app.after_request
        def after_request(response):
            # Add security headers
            response.headers['X-Content-Type-Options'] = 'nosniff'
            response.headers['X-Frame-Options'] = 'SAMEORIGIN'
            response.headers['X-XSS-Protection'] = '1; mode=block'
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
            response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' cdn.jsdelivr.net; style-src 'self' 'unsafe-inline'; img-src 'self' data:;"
            return response

        return limiter
    except Exception as e:
        logging.error(f"Error configuring security: {str(e)}")
        # Return a basic limiter without specific route limits
        return get_limiter(app) 