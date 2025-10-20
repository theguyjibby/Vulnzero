import nmap 

def scan_target(ip, port_range):
    nm = nmap.PortScanner()
    # Add '-sV' for service version detection
    nm.scan(ip, port_range, arguments='-sV')
    open_ports = []
    for proto in nm[ip].all_protocols():
        lport = nm[ip][proto].keys()
        for port in lport:
            port_info = nm[ip][proto][port]
            open_ports.append({
                'port': port,
                'service': port_info.get('name', ''),
                'version': port_info.get('version', '')
            })
    return open_ports

if "__name__" == "__main__":
    ip = "192.168.206.129"
    port_range = "1-1024"
    open_ports = scan_target(ip, port_range)
    print(open_ports)
