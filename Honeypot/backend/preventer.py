import time
import random

# Global sets/dicts for defense state
BLACKLIST = set() # IPs permanently blocked
TEMP_BAN = {} # IPs temporarily banned with expiry timestamp

def apply_prevention(ip, attack):
    """
    Applies defensive countermeasures based on the detected attack type.
    Includes permanent banning, temporary rate limiting, and tarpitting.
    """
    now = time.time()

    # 1. Block permanently if blacklisted
    if ip in BLACKLIST:
        return True

    # 2. Check if temp ban is active (expiry > current time)
    if ip in TEMP_BAN and TEMP_BAN[ip] > now:
        return True
    # Clean up expired bans
    elif ip in TEMP_BAN and TEMP_BAN[ip] <= now:
        del TEMP_BAN[ip]

    if attack != "Normal":
        # 3. Apply Temporary Ban (Rate limit for 1 hour)
        TEMP_BAN[ip] = now + 3600 # Ban for 1 hour

        # 4. Permanent blacklist for severe scans
        if attack in ["Scanner", "Path Scan"]:
            BLACKLIST.add(ip)

        # 5. Tarpit: Waste the attacker's time by forcing a delay
        # The delay makes automated scanners slow down drastically.
        print(f"[{ip}] Tarpitting detected attack: {attack}")
        time.sleep(random.uniform(3, 10))

        # Do not return True, allow the request to proceed after the delay 
        # so the attack detection can still log the full request.
        return False

    return False