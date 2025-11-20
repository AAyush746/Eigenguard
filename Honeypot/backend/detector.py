def detect_attack(path, ua, query, request):
    """
    Analyzes request parameters to categorize potential malicious activity.
    """
    path_l = path.lower()
    ua_l = ua.lower()
    q = str(query).lower()

    # Look for requests targeting known sensitive paths
    if any(x in path_l for x in [".env", "wp-admin", "phpmyadmin", "/etc/passwd"]):
        return "Path Scan"

    # Look for User-Agents belonging to known security tools
    if any(x in ua_l for x in ["sqlmap", "nikto", "nmap", "masscan"]):
        return "Scanner"

    # Look for common SQL Injection or Cross-Site Scripting payloads in query parameters
    if any(x in q for x in ["'", '"', "<script", "union select", "1=1"]):
        return "SQLi/XSS"

    # Suspiciously large POST request payload size (could indicate fuzzing or mass data attempt)
    if request.method == "POST" and request.data and len(request.data) > 1000:
        return "Suspicious POST"

    return "Normal"