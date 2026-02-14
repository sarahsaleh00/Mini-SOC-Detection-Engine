#!/usr/bin/env python3
"""
Mini SOC Detection Engine
Main entry point for the detection engine
"""

import argparse
import json
import os
from datetime import datetime
from src.detections import bruteforce, port_scan, web_attack


def parse_arguments():
    """
    Parse command line arguments
    
    Practice: CLI argument handling with argparse
    """
    parser = argparse.ArgumentParser(
        description="Mini SOC Detection Engine - Analyze logs for security threats"
    )
    parser.add_argument(
        "--logdir",
        type=str,
        default="logs",
        help="Directory containing log files (default: logs)"
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="Threshold for brute force detection (default: 5)"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="reports/alert_report.json",
        help="Output file for detection results (default: reports/alert_report.json)"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    
    return parser.parse_args()


def load_logs(log_dir, log_type):
    """
    Load log file and return lines
    
    Practice: File handling, error handling
    
    Args:
        log_dir: Directory containing logs
        log_type: Type of log (auth, firewall, web_access)
    
    Returns:
        List of log lines
    """
    log_file = os.path.join(log_dir, f"{log_type}.log")
    
    # TODO: Implement file reading
    # HINT: Use 'with open()' to safely read the file
    # HINT: Use .strip() to remove whitespace
    # HINT: Skip empty lines
    
    lines = []
    try:
        with open(log_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line:  # Skip empty lines
                    lines.append(line)
    except FileNotFoundError:
        print(f"[!] Warning: {log_file} not found")
        return []
    
    return lines


def save_report(alerts, output_file):
    """
    Save detection results to JSON file
    
    Practice: JSON serialization, file writing
    
    Args:
        alerts: Dictionary containing detection results
        output_file: Path to output file
    """
    # Create reports directory if it doesn't exist
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    # Add metadata
    report = {
        "timestamp": datetime.now().isoformat(),
        "summary": {
            "total_alerts": sum(len(v) for v in alerts.values()),
            "categories": len([k for k, v in alerts.items() if v])
        },
        "alerts": alerts
    }
    
    # TODO: Write report to JSON file
    # HINT: Use json.dump() with indent for readability
    
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"[+] Report saved to: {output_file}")


def print_summary(alerts):
    """
    Print summary of detections to console
    
    Practice: Data formatting, console output
    """
    print("\n" + "="*60)
    print("DETECTION SUMMARY")
    print("="*60)
    
    total_alerts = 0
    
    for category, items in alerts.items():
        if items:
            print(f"\n[!] {category.upper().replace('_', ' ')}: {len(items)} alerts")
            total_alerts += len(items)
            
            for item in items[:3]:  # Show first 3
                if 'ip' in item:
                    print(f"    - {item['ip']} (Count: {item.get('count', 'N/A')})")
                elif 'src_ip' in item:
                    print(f"    - {item['src_ip']} -> {item.get('target', 'N/A')}")
            
            if len(items) > 3:
                print(f"    ... and {len(items) - 3} more")
    
    print(f"\n{'='*60}")
    print(f"Total Alerts: {total_alerts}")
    print(f"{'='*60}\n")


def main():
    """
    Main function - orchestrates the detection engine
    
    Practice: Program flow, function composition
    """
    # Parse arguments
    args = parse_arguments()
    
    print("[*] Mini SOC Detection Engine Starting...")
    print(f"[*] Log Directory: {args.logdir}")
    print(f"[*] Threshold: {args.threshold}")
    
    # Initialize alerts dictionary
    alerts = {
        "brute_force_attempts": [],
        "port_scans": [],
        "web_attacks": []
    }
    
    # Load logs
    if args.verbose:
        print("[*] Loading authentication logs...")
    auth_logs = load_logs(args.logdir, "auth")
    
    if args.verbose:
        print("[*] Loading firewall logs...")
    firewall_logs = load_logs(args.logdir, "firewall")
    
    if args.verbose:
        print("[*] Loading web access logs...")
    web_logs = load_logs(args.logdir, "web_access")
    
    # Run detections
    print("[*] Running detection modules...")
    
    # 1. Brute Force Detection
    if auth_logs:
        alerts["brute_force_attempts"] = bruteforce.detect_bruteforce(
            auth_logs, 
            threshold=args.threshold
        )
    
    # 2. Port Scan Detection
    if firewall_logs:
        alerts["port_scans"] = port_scan.detect_port_scan(
            firewall_logs,
            threshold=args.threshold
        )
    
    # 3. Web Attack Detection
    if web_logs:
        alerts["web_attacks"] = web_attack.detect_web_attacks(web_logs)
    
    # Print summary
    print_summary(alerts)
    
    # Save report
    save_report(alerts, args.output)
    
    print("[+] Detection engine completed successfully!")


if __name__ == "__main__":
    main()
