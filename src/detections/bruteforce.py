
import re


def parse_auth_log(line):
    # Extract values from the log

    timestamp_pattern  = r'[A-Z][a-z]{2} \d{2} \d{2}:\d{2}:\d{2}'
    timestamp_match = re.search(timestamp_pattern, line)

    username_pattern = r'for (\S+) from'
    username_match = re.search(username_pattern, line)

    ip_pattern = r'from (\d+\.\d+\.\d+\.\d+)'
    ip_pattern_match = re.search(ip_pattern, line)

    port_pattern = r'port (\d+)'
    port_pattern_match = re.search(port_pattern, line)

    action_pattern = r'(\w+ password)'
    action_pattern_match = re.search(action_pattern, line)

    # if all valid
    if timestamp_match and username_match and ip_pattern_match and port_pattern_match and action_pattern_match:
        return {
            'timestamp': timestamp_match.group(0),
            'action': action_pattern_match.group(0),
            'username': username_match.group(1),
            'source_ip': ip_pattern_match.group(1),
            'port': port_pattern_match.group(1)
        }
    else:
        return None

    

def detect_bruteforce(log_lines, threshold=5):
    # Initialize dictionaries
    ipAttempts = {}
    ipUsernames = {}

    # for each line in log lines
    for line in log_lines:
        # parse log using the parse_auth_log function
        parsed = parse_auth_log(line)
        if parsed and parsed['action'] == "Failed password":
            ip = parsed['source_ip']
            username = parsed['username']
            ipAttempts[ip] = ipAttempts.get(ip, 0) + 1
            
            # Track usernames for this IP
            if ip not in ipUsernames:
                ipUsernames[ip] = []
            if username not in ipUsernames[ip]:
                ipUsernames[ip].append(username)
             
    alerts = []
  
    for ip, count in ipAttempts.items():
        if count >= threshold:
            alerts.append({
                'ip': ip,
                'count': count,
                'usernames': ipUsernames[ip]
            })
    
    return alerts

   