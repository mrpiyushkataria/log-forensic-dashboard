import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-here'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///logs.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100MB max file size
    UPLOAD_FOLDER = './uploads'
    PROCESSED_FOLDER = './processed'
    
    # Log paths for real-time monitoring
    LOG_PATHS = {
        'nginx_access': '/var/log/nginx/access.log',
        'nginx_error': '/var/log/nginx/error.log',
        'mysql': '/var/log/mysql/error.log',
        'auth': '/var/log/auth.log',
        'syslog': '/var/log/syslog',
        'secure': '/var/log/secure'
    }
    
    # Security patterns
    SECURITY_PATTERNS = {
        'sql_injection': [
            r"'.*?(union|select|insert|update|delete|drop|exec).*?'",
            r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
            r"\b(OR|AND)\b.*?\d+.*?=\s*\d+",
            r"\/\*.*?\*\/"
        ],
        'xss': [
            r"<script.*?>.*?</script>",
            r"javascript:",
            r"onerror\s*=",
            r"onload\s*=",
            r"onclick\s*=",
            r"alert\(.*?\)"
        ],
        'path_traversal': [
            r"\.\.\/",
            r"\.\.\\",
            r"\/etc\/passwd",
            r"\/proc\/self"
        ],
        'brute_force': [
            r"Failed password",
            r"authentication failure",
            r"Invalid user"
        ]
    }
