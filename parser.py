import re
from datetime import datetime

def parse_log_line(line):
    pattern = r'(\S+)\s+(\S+)\s+(\S+?):\s+(.*)'
    match = re.match(pattern, line.strip())
    
    if not match:
        return None
    
    timestamp_raw, host, service, message = match.groups()
    
    try:
        timestamp_raw_clean = timestamp_raw.split('.')[0]
        timestamp = datetime.fromisoformat(timestamp_raw_clean)
    except:
        timestamp = None
    
    return {
        "timestamp_raw": timestamp_raw,
        "timestamp": timestamp,
        "host": host,
        "service": service,
        "message": message.strip()
    }

if __name__ == "__main__":
    test_lines = [
        "2026-03-16T14:42:57.823452+05:00 abbaskhan-VMware sudo: abbaskhan : COMMAND=/usr/bin/tail",
        "2026-03-16T06:01:33.448089+05:00 abbaskhan-VMware pkexec: pam_unix(polkit-1:session): session opened for user root",
        "2026-03-16T14:22:42.674380+05:00 abbaskhan-VMware sudo: abbaskhan : TTY=pts/0 ; PWD=/home/abbaskhan ; COMMAND=/usr/bin/snap",
        "this is a bad line that wont match anything"
    ]
    
    print("=" * 60)
    print("PARSER TEST — feeding 4 log lines")
    print("=" * 60)
    
    for i, line in enumerate(test_lines, 1):
        print(f"\n--- Line {i} ---")
        print(f"RAW    : {line}")
        result = parse_log_line(line)
        if result:
            print(f"TIME   : {result['timestamp']}")
            print(f"HOST   : {result['host']}")
            print(f"SERVICE: {result['service']}")
            print(f"MESSAGE: {result['message']}")
        else:
            print("RESULT : Could not parse this line — returned None")
    
    print("\n" + "=" * 60)
    print("Parser working correctly if lines 1-3 parsed and line 4 shows None")
    print("=" * 60)
    