import xml.etree.ElementTree as ET

def parse_nmap_xml(file_path):
    """
    Parses an Nmap XML output file and returns a list of detected services.
    Each service is a dictionary with keys: port, protcol, name, product, version, extrainfo
    """
    services = []
    
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        
        for host in root.findall('host'):
            ports = host.find('ports')
            if ports is None:
                continue
                
            for port in ports.findall('port'):
                state = port.find('state')
                # Only consider open ports
                if state is None or state.get('state') != 'open':
                    continue
                
                service = port.find('service')
                if service is not None:
                    # Nmap attributes we care about
                    svc_name = service.get('name', '')
                    product = service.get('product', '')
                    version = service.get('version', '')
                    
                    # Store as a combined 'service_name' for easier matching if product is available
                    full_name = f"{product} {version}".strip() if product else svc_name
                    
                    services.append({
                        'port_id': port.get('portid', ''),
                        'protocol': port.get('protocol', ''),
                        'service_name': product if product else svc_name,
                        'version': version,
                        'full_name': full_name
                    })
                    
        return services
    except Exception as e:
        print(f"[-] Error parsing Nmap XML: {e}")
        return []
