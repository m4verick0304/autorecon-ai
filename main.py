import sys
import os

from parser.nmap_parser import parse_nmap_xml
from recommender.recommender import ExploitRecommender
from utils.helpers import print_banner, print_finding

def main():
    print_banner()

    if len(sys.argv) < 2:
        print("Usage: python3 main.py <scan.xml>")
        sys.exit(1)

    xml_file = sys.argv[1]

    if not os.path.exists(xml_file):
        print(f"[-] Error: File '{xml_file}' not found.")
        sys.exit(1)

    # 1. Parse XML
    services = parse_nmap_xml(xml_file)
    
    # 2. Initialize Recommender
    recommender = ExploitRecommender()
    
    # 3. Analyze and Recommend
    found_exploits = False
    for service_info in services:
        exploits = recommender.recommend(service_info)
        for exploit in exploits:
            print_finding(service_info['full_name'], exploit)
            found_exploits = True

    if not found_exploits and services:
        print("\n[!] No known exploits found for detected services.")
    elif not services:
        print("\n[!] No open services found in the provided Nmap scan.")

if __name__ == "__main__":
    main()
