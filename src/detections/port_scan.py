
import re


def parse_firewall_log(line):



    # extracting and parsing information from the logs

    
    timestamp_pattern  = r'[A-Z][a-z]{2} \d{2} \d{2}:\d{2}:\d{2}'
    timestamp_match = re.search(timestamp_pattern, line)

    action_pattern = r'firewall (\S+)'
    action_pattern_match = re.search(action_pattern, line)

    source_ip_pattern = r'firewall \S+ (\d+\.\d+\.\d+\.\d+)'
    source_ip_match = re.search(source_ip_pattern, line)


    dest_pattern = r'-> (\d+\.\d+\.\d+\.\d+):(\d+)'
    dest_pattern_match = re.search(dest_pattern, line)




      # if all valid
    if timestamp_match and action_pattern_match and source_ip_match and dest_pattern_match:
        return {
            'timestamp': timestamp_match.group(0),
            'action': action_pattern_match.group(1),
            'source_ip': source_ip_match.group(1),
            'dest_ip': dest_pattern_match.group(1),
            'dest_port': dest_pattern_match.group(2), 

        }
    else:
        return None



def detect_port_scan(log_lines, threshold=5):

    
    port_attempts = {}  # {source_ip: set of ports}
    targets = {}        # {source_ip: set of target IPs}

    for line in log_lines:
        parsed = parse_firewall_log(line) 
        if parsed and parsed['action'] == 'DENY':
            source_ip = parsed['source_ip']
            dest_ip = parsed['dest_ip']
            port = parsed['dest_port']

        # Track unique ports
        if source_ip not in port_attempts:
            port_attempts[source_ip] = set() # create the set for that ip
        port_attempts[source_ip].add(port) # save that port for that ip

        # Track unique target IPs
        if source_ip not in targets:
            targets[source_ip] = set()  # create the set for that ip
        targets[source_ip].add(dest_ip) # save that destination ip contacted by the source ip
        

    alerts = []
    for ip, ports in port_attempts.items():
        if len(ports) >= threshold:
            alerts.append({
                'src_ip': ip,
                'unique_ports': list(ports),
                'count': len(ports),
                'targets': list(targets[ip])
            })

    return alerts
    

    

