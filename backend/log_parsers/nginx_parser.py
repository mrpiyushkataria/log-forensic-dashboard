import re
from datetime import datetime
from collections import Counter
import ipaddress
import json

class NginxParser:
    def __init__(self):
        self.pattern = re.compile(
            r'(?P<ip>\S+) - - \[(?P<timestamp>.*?)\] "(?P<method>\S+) (?P<url>\S+) (?P<protocol>\S+)" '
            r'(?P<status>\d+) (?P<size>\d+) "(?P<referrer>.*?)" "(?P<user_agent>.*?)"'
        )
        
        self.error_pattern = re.compile(
            r'^(?P<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[(?P<level>\w+)\] '
            r'(?P<pid>\d+)\#(?P<tid>\d+): \*(?P<cid>\d+) (?P<message>.*)'
        )
    
    def parse_line(self, line):
        """Parse single nginx log line"""
        match = self.pattern.match(line)
        if match:
            data = match.groupdict()
            
            # Parse timestamp
            try:
                data['timestamp'] = datetime.strptime(data['timestamp'], '%d/%b/%Y:%H:%M:%S %z')
            except:
                pass
            
            # Additional analysis
            data['endpoint'] = data['url'].split('?')[0] if '?' in data['url'] else data['url']
            data['query_params'] = self.extract_query_params(data['url'])
            data['is_bot'] = self.is_bot(data['user_agent'])
            data['is_mobile'] = self.is_mobile(data['user_agent'])
            
            return data
        return {'raw': line.strip()}
    
    def parse(self, filepath):
        """Parse entire nginx log file"""
        results = {
            'entries': [],
            'statistics': {},
            'security_issues': [],
            'performance_metrics': {}
        }
        
        with open(filepath, 'r') as f:
            entries = []
            for line in f:
                if line.strip():
                    parsed = self.parse_line(line)
                    entries.append(parsed)
            
            results['entries'] = entries
            
            # Generate statistics
            if entries and 'status' in entries[0]:
                results['statistics'] = self.generate_statistics(entries)
                results['security_issues'] = self.find_security_issues(entries)
                results['performance_metrics'] = self.calculate_performance(entries)
        
        return results
    
    def generate_statistics(self, entries):
        """Generate comprehensive statistics"""
        stats = {
            'total_requests': len(entries),
            'status_codes': Counter(),
            'methods': Counter(),
            'top_endpoints': Counter(),
            'top_ips': Counter(),
            'user_agents': Counter(),
            'referrers': Counter(),
            'hourly_distribution': Counter(),
            'bot_traffic': 0,
            'mobile_traffic': 0,
            'unique_ips': set(),
            'data_transferred': 0,
            'error_rate': 0
        }
        
        for entry in entries:
            if 'status' in entry:
                # Status codes
                stats['status_codes'][entry['status']] += 1
                
                # Methods
                if 'method' in entry:
                    stats['methods'][entry['method']] += 1
                
                # Endpoints
                if 'endpoint' in entry:
                    stats['top_endpoints'][entry['endpoint']] += 1
                
                # IPs
                if 'ip' in entry:
                    stats['top_ips'][entry['ip']] += 1
                    stats['unique_ips'].add(entry['ip'])
                
                # User agents
                if 'user_agent' in entry:
                    stats['user_agents'][entry['user_agent']] += 1
                
                # Referrers
                if 'referrer' in entry:
                    if entry['referrer'] != '-':
                        stats['referrers'][entry['referrer']] += 1
                
                # Hourly distribution
                if 'timestamp' in entry and isinstance(entry['timestamp'], datetime):
                    hour = entry['timestamp'].hour
                    stats['hourly_distribution'][hour] += 1
                
                # Bot traffic
                if entry.get('is_bot', False):
                    stats['bot_traffic'] += 1
                
                # Mobile traffic
                if entry.get('is_mobile', False):
                    stats['mobile_traffic'] += 1
                
                # Data transferred
                if 'size' in entry and entry['size'].isdigit():
                    stats['data_transferred'] += int(entry['size'])
        
        # Calculate error rate
        total_errors = sum(count for code, count in stats['status_codes'].items() 
                          if code.startswith('4') or code.startswith('5'))
        stats['error_rate'] = (total_errors / stats['total_requests'] * 100) if stats['total_requests'] > 0 else 0
        
        # Convert Counter to dict and get top items
        stats['status_codes'] = dict(stats['status_codes'])
        stats['methods'] = dict(stats['methods'])
        stats['top_endpoints'] = dict(stats['top_endpoints'].most_common(20))
        stats['top_ips'] = dict(stats['top_ips'].most_common(20))
        stats['user_agents'] = dict(stats['user_agents'].most_common(20))
        stats['referrers'] = dict(stats['referrers'].most_common(20))
        stats['hourly_distribution'] = dict(sorted(stats['hourly_distribution'].items()))
        stats['unique_ips_count'] = len(stats['unique_ips'])
        
        return stats
    
    def find_security_issues(self, entries):
        """Find potential security issues"""
        issues = []
        security_patterns = {
            'sql_injection': [
                r"'.*?(union|select|insert|update|delete|drop|exec).*?'",
                r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
                r"\/\*.*?\*\/"
            ],
            'xss': [
                r"<script.*?>.*?</script>",
                r"javascript:",
                r"onerror\s*=",
                r"alert\(.*?\)"
            ],
            'path_traversal': [
                r"\.\.\/",
                r"\.\.\\",
                r"\/etc\/passwd",
                r"\/proc\/self"
            ],
            'lfi': [
                r"include\s*=",
                r"require\s*=",
                r"\.\.\/\.\.\/"
            ],
            'sensitive_endpoints': [
                r"/phpmyadmin",
                r"/admin",
                r"/wp-login",
                r"/config",
                r"/\.env",
                r"/\.git"
            ]
        }
        
        for entry in entries:
            if 'url' in entry:
                url = entry['url']
                for issue_type, patterns in security_patterns.items():
                    for pattern in patterns:
                        if re.search(pattern, url, re.IGNORECASE):
                            issues.append({
                                'type': issue_type,
                                'url': url,
                                'ip': entry.get('ip', 'Unknown'),
                                'timestamp': entry.get('timestamp'),
                                'user_agent': entry.get('user_agent', 'Unknown')
                            })
                            break
        
        return issues
    
    def calculate_performance(self, entries):
        """Calculate performance metrics"""
        metrics = {
            'requests_per_minute': Counter(),
            'response_sizes': [],
            'slow_requests': [],
            'peak_hours': []
        }
        
        # Group by minute
        for entry in entries:
            if 'timestamp' in entry and isinstance(entry['timestamp'], datetime):
                minute_key = entry['timestamp'].strftime('%Y-%m-%d %H:%M')
                metrics['requests_per_minute'][minute_key] += 1
        
        # Find slow requests (based on large response size or specific patterns)
        for entry in entries:
            if 'size' in entry and entry['size'].isdigit():
                size = int(entry['size'])
                metrics['response_sizes'].append(size)
                
                # Consider requests > 10MB as potentially slow
                if size > 10 * 1024 * 1024:
                    metrics['slow_requests'].append({
                        'url': entry.get('url', 'Unknown'),
                        'size': size,
                        'timestamp': entry.get('timestamp'),
                        'ip': entry.get('ip', 'Unknown')
                    })
        
        # Find peak hours
        hourly = Counter()
        for entry in entries:
            if 'timestamp' in entry and isinstance(entry['timestamp'], datetime):
                hour = entry['timestamp'].hour
                hourly[hour] += 1
        
        if hourly:
            peak_hour = hourly.most_common(1)[0]
            metrics['peak_hours'] = [{
                'hour': peak_hour[0],
                'requests': peak_hour[1]
            }]
        
        # Calculate averages
        if metrics['response_sizes']:
            metrics['avg_response_size'] = sum(metrics['response_sizes']) / len(metrics['response_sizes'])
            metrics['max_response_size'] = max(metrics['response_sizes'])
            metrics['min_response_size'] = min(metrics['response_sizes'])
        
        metrics['requests_per_minute'] = dict(metrics['requests_per_minute'])
        
        return metrics
    
    def extract_query_params(self, url):
        """Extract query parameters from URL"""
        params = {}
        if '?' in url:
            query_string = url.split('?')[1]
            pairs = query_string.split('&')
            for pair in pairs:
                if '=' in pair:
                    key, value = pair.split('=', 1)
                    params[key] = value
        return params
    
    def is_bot(self, user_agent):
        """Check if user agent is a bot"""
        bot_indicators = [
            'bot', 'crawler', 'spider', 'scraper', 'curl', 'wget',
            'python', 'java', 'go-http', 'ruby', 'php'
        ]
        if not user_agent or user_agent == '-':
            return False
        return any(indicator in user_agent.lower() for indicator in bot_indicators)
    
    def is_mobile(self, user_agent):
        """Check if user agent is mobile"""
        mobile_indicators = [
            'mobile', 'android', 'iphone', 'ipad', 'ipod',
            'blackberry', 'webos', 'windows phone'
        ]
        if not user_agent or user_agent == '-':
            return False
        return any(indicator in user_agent.lower() for indicator in mobile_indicators)
    
    def parse_error_log(self, filepath):
        """Parse nginx error log"""
        errors = []
        with open(filepath, 'r') as f:
            for line in f:
                match = self.error_pattern.match(line)
                if match:
                    errors.append(match.groupdict())
                else:
                    errors.append({'raw': line.strip()})
        return errors
