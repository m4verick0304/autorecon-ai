def print_finding(service_full_name, exploit):
    """
    Renders the finding gracefully according to the project specifications.
    """
    print(f"\n[+] Detected Service: {service_full_name}")
    print(f"[+] Suggested Exploit: {exploit}")

def print_banner():
    """
    Displays the tool's banner.
    """
    banner = """
  🚀 AutoReconAI
   Intelligent Vulnerability Scanner & Exploit Recommender
    """
    print(banner)
