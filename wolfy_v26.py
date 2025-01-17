import os
import re
import subprocess
import urllib3  
import dns.resolver
import socket
import requests
import http.client
import socket
from urllib.parse import urlparse
import pandas as pd
from tkinter import Tk, filedialog, messagebox
import csv
import xml.etree.ElementTree as ET
from collections import defaultdict
import threading
import getpass


http = urllib3.PoolManager()
def welcome_message():
    print('''Welcome to
 _       __   ____     __       ______   __  __
| |     / /  / __ \   / /      / ____/   \ \/ /
| | /| / /  / / / /  / /      / /_        \  / 
| |/ |/ /  / /_/ /  / /___   / __/        / /  
|__/|__/   \____/  /_____/  /_/          /_/  --BY Abhishek Mauriya
''')

def get_input(prompt):
    user_input = input(prompt).strip()
    while not user_input:
        user_input = input("Input cannot be empty. Please try again.\n\n" + prompt).strip()
    return user_input

def get_project_name():
    return get_input("Enter the project name: ")

def get_number_of_ips():
    while True:
        try:
            number_of_ips = int(get_input("Enter the number of IP Addresses: "))
            if number_of_ips > 0:
                return number_of_ips
            else:
                print("Number of IP addresses must be greater than zero.")
        except ValueError:
            print("Invalid input. Please enter a valid number.")

def get_number_of_batches():
    while True:
        try:
            num_batches = int(get_input("Enter the number of batches: "))
            if num_batches > 0:
                return num_batches
            else:
                print("Number of batches must be greater than zero.")
        except ValueError:
            print("Invalid input. Please enter a valid number.")

def select_file():
    root = Tk()
    root.withdraw()
    file_path = filedialog.askopenfilename(title="Select the text file containing IP addresses")
    while not file_path:
        messagebox.showerror("Error", "You must select a file.")
        file_path = filedialog.askopenfilename(title="Select the text file containing IP addresses")
    return file_path

def validate_ip(ip):
    pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    return bool(pattern.match(ip))

def create_project_directory(project_name, choice):
    root = Tk()
    root.withdraw()
    project_root = filedialog.askdirectory(title="Select the directory where you want to save the project")
    if not project_root:
        messagebox.showerror("Error", "You must select a directory.")
        project_root = filedialog.askdirectory(title="Select the directory where you want to save the project")

    project_path = os.path.join(project_root, project_name)
    nmap_scans_path = os.path.join(project_path, 'nmap_scans')
    os.makedirs(project_path, exist_ok=True)
    os.makedirs(nmap_scans_path, exist_ok=True)

    top_port_tcp_scan_path = None
    top_port_udp_scan_path = None
    ssl_cert_scan_path = None
    cipher_enum_scan_path = None
    full_port_tcp_scan_path = None

    if choice in ('1', '3'):
        top_port_tcp_scan_path = os.path.join(nmap_scans_path, 'top_port_tcp_scan')
        top_port_udp_scan_path = os.path.join(nmap_scans_path, 'top_port_udp_scan')
        ssl_cert_scan_path = os.path.join(nmap_scans_path, 'ssl_cert_scan')
        cipher_enum_scan_path = os.path.join(nmap_scans_path, 'cipher_enum_scan')
        os.makedirs(top_port_tcp_scan_path, exist_ok=True)
        os.makedirs(top_port_udp_scan_path, exist_ok=True)
        os.makedirs(ssl_cert_scan_path, exist_ok=True)
        os.makedirs(cipher_enum_scan_path, exist_ok=True)

    if choice in ('2', '3'):
        full_port_tcp_scan_path = os.path.join(nmap_scans_path, 'full_port_tcp_scan')
        os.makedirs(full_port_tcp_scan_path, exist_ok=True)

    return project_path, nmap_scans_path, top_port_tcp_scan_path, top_port_udp_scan_path, ssl_cert_scan_path, cipher_enum_scan_path, full_port_tcp_scan_path


def parse_xml(xml_file, batch_number):
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except ET.ParseError:
        print(f"Error parsing XML file: {xml_file}")
        return [], defaultdict(set)

    data = []
    open_ports = defaultdict(set)
    for host in root.findall('.//host'):
        address = host.find('.//address')
        if address is None:
            continue
        ip_address = address.get('addr')

        for port in host.findall('.//port'):
            port_id = port.get('portid', '')
            protocol = port.get('protocol', '')
            state_elem = port.find('.//state')
            state = state_elem.get('state') if state_elem is not None else ''

            service_elem = port.find('.//service')
            service = service_elem.get('name') if service_elem is not None else ''
            product = service_elem.get('product', '') if service_elem is not None else ''
            version = service_elem.get('version', '') if service_elem is not None else ''

            version_combined = f"{product} {version}".strip()
            data.append([batch_number, ip_address, port_id, protocol, state, service, version_combined])

            if state == 'open':
                open_ports[port_id].add(ip_address)

    return data, open_ports

def write_to_csv(all_data, csv_file):
    with open(csv_file, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['Batch Number', 'IP Address', 'Port ID', 'Protocol', 'State', 'Service', 'Version'])  # Column headers
        for batch_data in all_data:
            writer.writerows(batch_data)

def divide_ips_into_batches(ip_addresses, num_batches):
    batch_size = len(ip_addresses) // num_batches
    batches = [ip_addresses[i:i + batch_size] for i in range(0, len(ip_addresses), batch_size)]
    
    if len(batches) > num_batches:
        batches[-2].extend(batches[-1])
        batches = batches[:-1]

    return batches

def save_batches(batches, project_path):
    batch_files = []
    for i, batch in enumerate(batches, start=1):
        batch_file = os.path.join(project_path, f'batch_{i}.txt')
        with open(batch_file, 'w') as file:
            for ip in batch:
                file.write(f"{ip}\n")
        batch_files.append(batch_file)
    return batch_files

def check_for_duplicates(ip_addresses):
    ip_counts = defaultdict(list)
    for index, ip in enumerate(ip_addresses):
        ip_counts[ip].append(index + 1)

    duplicates = {ip: positions for ip, positions in ip_counts.items() if len(positions) > 1}
    return duplicates

def run_nmap_scan(batch_file, output_path, scan_type, sudo_password=None):
    command = ['nmap']
    
    if scan_type == 'tcp':
        command.extend(['-sV', '--top-ports', '1000', '-Pn', '-iL', batch_file, '-oA', output_path])
    elif scan_type == 'udp':
        command = ['sudo', '-S', 'nmap', '-sU', '--top-ports', '1000', '-Pn', '-iL', batch_file, '-oA', output_path]
        if sudo_password:
            subprocess.run(command, input=sudo_password + '\n', text=True)
            return
    elif scan_type == 'ssl':
        command.extend(['-p', '443', '--script', 'ssl-cert', '-iL', batch_file, '-oN', output_path])
    elif scan_type == 'cipher':
        command.extend(['-p', '443', '--script', 'ssl-enum-ciphers', '-iL', batch_file, '-oN', output_path])
    elif scan_type == 'safe':
        command.extend(['-sC', '-Pn', '-iL', batch_file, '-oA', output_path])
    
    subprocess.run(command)

def run_full_port_scan(batch_file, output_path, scan_type, scan_range=None, additional_flags=None):
    command = ['nmap']

    if scan_type == 'full_tcp':
        command.extend(['-p-', '-Pn', '-iL', batch_file, '-oA', output_path])
    elif scan_type == 'range' and scan_range:
        command.extend(['-p', scan_range, '-Pn', '-iL', batch_file, '-oA', output_path])

    if additional_flags:
        command.extend(additional_flags.split())

    print(f"Running command: {' '.join(command)}")  # Print the full command with additional flags
    subprocess.run(command)

def handle_tcp_udp_ssl_cipher_scans(batch_files, project_path, top_port_tcp_scan_path, top_port_udp_scan_path, ssl_cert_scan_path, cipher_enum_scan_path, all_data, host_ips_file):
    all_open_ports = defaultdict(set)
    udp_scan_threads = []

    sudo_password = getpass.getpass("Enter your sudo password for UDP scan: ")

    for i, batch_file in enumerate(batch_files, start=1):
        batch_dir = os.path.join(top_port_tcp_scan_path, f'batch{i}')
        batch_udp_dir = os.path.join(top_port_udp_scan_path, f'batch{i}')
        os.makedirs(batch_dir, exist_ok=True)
        os.makedirs(batch_udp_dir, exist_ok=True)

        nmap_tcp_scan_output = os.path.join(batch_dir, 'nmap_tcp_top_port_scan')
        nmap_udp_scan_output = os.path.join(batch_udp_dir, 'nmap_udp_top_port_scan')

        udp_thread = threading.Thread(target=run_nmap_scan, args=(batch_file, nmap_udp_scan_output, 'udp', sudo_password))
        udp_scan_threads.append(udp_thread)
        udp_thread.start()

        run_nmap_scan(batch_file, nmap_tcp_scan_output, 'tcp')
        print(f"Nmap TCP top port scan output saved to {nmap_tcp_scan_output}")

        xml_file_tcp = nmap_tcp_scan_output + '.xml'
        batch_data_tcp, open_ports_tcp = parse_xml(xml_file_tcp, i)
        all_data.append(batch_data_tcp)

        for port, ips in open_ports_tcp.items():
            all_open_ports[port].update(ips)

    for udp_thread in udp_scan_threads:
        udp_thread.join()

    for i, batch_file in enumerate(batch_files, start=1):
        batch_udp_dir = os.path.join(top_port_udp_scan_path, f'batch{i}')
        nmap_udp_scan_output = os.path.join(batch_udp_dir, 'nmap_udp_top_port_scan')

        print(f"Nmap UDP top port scan output saved to {nmap_udp_scan_output}")

        xml_file_udp = nmap_udp_scan_output + '.xml'
        batch_data_udp, open_ports_udp = parse_xml(xml_file_udp, i)

        all_data[i - 1].extend(batch_data_udp)

        for port, ips in open_ports_udp.items():
            all_open_ports[port].update(ips)

    csv_file = os.path.join(project_path, 'nmap_tcp_udp_top_port_scan_csv_converted.csv')
    write_to_csv(all_data, csv_file)
    print(f"CSV file has been created: {csv_file}")

    for port, ips in all_open_ports.items():
        port_file = os.path.join(project_path, f'hosts_with_port_{port}_open.txt')
        with open(port_file, 'w') as file:
            for ip in ips:
                file.write(f"{ip}\n")

    handle_ssl_cert_scan(project_path, ssl_cert_scan_path)
    handle_cipher_enum_scan(project_path, cipher_enum_scan_path)

    # Run an Nmap safe script scan (-sC)
    safe_script_scan_output = os.path.join(project_path, 'nmap_safe_script_scan')
    run_nmap_scan(host_ips_file, safe_script_scan_output, 'safe')
    print(f"Nmap safe script scan output saved to {safe_script_scan_output}")


def handle_ssl_cert_scan(project_path, ssl_cert_scan_path):
    ssl_hosts_file = os.path.join(project_path, 'hosts_with_port_443_open.txt')
    if os.path.exists(ssl_hosts_file):
        run_nmap_scan(ssl_hosts_file, os.path.join(ssl_cert_scan_path, 'nmap_ssl_cert_scan'), 'ssl')
        print(f"Nmap SSL certificate scan output saved to {os.path.join(ssl_cert_scan_path, 'nmap_ssl_cert_scan')}")
    else:
        print("No hosts with port 443 open found. Skipping SSL certificate scan.")

def handle_cipher_enum_scan(project_path, cipher_enum_scan_path):
    cipher_hosts_file = os.path.join(project_path, 'hosts_with_port_443_open.txt')
    if os.path.exists(cipher_hosts_file):
        run_nmap_scan(cipher_hosts_file, os.path.join(cipher_enum_scan_path, 'nmap_cipher_enum_scan'), 'cipher')
        print(f"Nmap cipher enumeration scan output saved to {os.path.join(cipher_enum_scan_path, 'nmap_cipher_enum_scan')}")
    else:
        print("No hosts with port 443 open found. Skipping cipher enumeration scan.")


def handle_full_port_tcp_scan(batch_files, project_path, full_port_tcp_scan_path, all_data):
    while True:
        scan_choice = input("\nDo you want to scan all ports at once (type 'all') or in ranges (type 'ranges')? (or press 'e' to exit): ").lower()
        if scan_choice == 'e':
            print("Exiting full port scan.")
            return None  # Return None if the user chooses to exit
        elif scan_choice not in ('all', 'ranges'):
            print("Invalid choice. Please enter 'all', 'ranges', or 'e' to exit.")
        else:
            break

    additional_flags = input("\nEnter any additional flags for the nmap scan (or press Enter to skip): ").strip()

    all_open_ports = defaultdict(set)

    if scan_choice == 'all':
        # Process all batches concurrently with a limit of 3 threads at a time
        max_threads = 3
        threads = []
        for i, batch_file in enumerate(batch_files, start=1):
            batch_dir = os.path.join(full_port_tcp_scan_path, f'batch{i}')
            os.makedirs(batch_dir, exist_ok=True)

            nmap_full_scan_output = os.path.join(batch_dir, 'nmap_full_port_tcp_scan')
            # Pass additional_flags correctly to the thread
            thread = threading.Thread(target=run_full_port_scan, args=(batch_file, nmap_full_scan_output, 'full_tcp', None, additional_flags))
            threads.append(thread)
            thread.start()

            if len(threads) == max_threads:
                for thread in threads:
                    thread.join()
                threads = []

        # Wait for any remaining threads to finish
        for thread in threads:
            thread.join()

        # Process the results after all threads have completed
        for i, batch_file in enumerate(batch_files, start=1):
            batch_dir = os.path.join(full_port_tcp_scan_path, f'batch{i}')
            xml_file_full_tcp = os.path.join(batch_dir, 'nmap_full_port_tcp_scan.xml')
            batch_data_full_tcp, open_ports_full_tcp = parse_xml(xml_file_full_tcp, i)
            all_data[i - 1].extend(batch_data_full_tcp)

            for port, ips in open_ports_full_tcp.items():
                all_open_ports[port].update(ips)

    else:
        # Process each batch in port ranges
        ranges = [(0, 10000), (10001, 20000), (20001, 30000)]
        for i, batch_file in enumerate(batch_files, start=1):
            batch_dir = os.path.join(full_port_tcp_scan_path, f'batch{i}')
            os.makedirs(batch_dir, exist_ok=True)

            threads = []
            for start, end in ranges:
                scan_range = f"{start}-{end}"
                nmap_full_scan_output = os.path.join(batch_dir, f'nmap_full_port_tcp_scan_{start}_{end}')
                thread = threading.Thread(target=run_full_port_scan, args=(batch_file, nmap_full_scan_output, 'range', scan_range, additional_flags))
                threads.append(thread)
                thread.start()

            for thread in threads:
                thread.join()

            remaining_ranges = [(30001, 40000), (40001, 50000), (50001, 60000), (60001, 65535)]
            remaining_threads = []
            for start, end in remaining_ranges:
                scan_range = f"{start}-{end}"
                nmap_full_scan_output = os.path.join(batch_dir, f'nmap_full_port_tcp_scan_{start}_{end}')
                thread = threading.Thread(target=run_full_port_scan, args=(batch_file, nmap_full_scan_output, 'range', scan_range, additional_flags))
                remaining_threads.append(thread)
                thread.start()

            for thread in remaining_threads:
                thread.join()

            for start, end in ranges + remaining_ranges:
                xml_file_full_tcp = os.path.join(batch_dir, f'nmap_full_port_tcp_scan_{start}_{end}.xml')
                batch_data_full_tcp, open_ports_full_tcp = parse_xml(xml_file_full_tcp, i)
                all_data[i - 1].extend(batch_data_full_tcp)

                for port, ips in open_ports_full_tcp.items():
                    all_open_ports[port].update(ips)

    csv_file = os.path.join(project_path, 'nmap_full_tcp_scan_csv_converted.csv')
    write_to_csv(all_data, csv_file)
    print(f"CSV file has been updated with full port scan data: {csv_file}")

    sv_output_directory = os.path.join(project_path, 'sv_full_port_results')
    os.makedirs(sv_output_directory, exist_ok=True)

    perform_sv_scan_from_csv(csv_file, sv_output_directory, csv_file)

    return csv_file


def perform_sv_scan_from_csv(csv_file, output_directory, csv_update_file):
    if csv_file is None:
        print("Error: CSV file path is None. Skipping SV scan.")
        return

    if not os.path.exists(csv_file):
        print(f"Error: CSV file '{csv_file}' does not exist. Skipping SV scan.")
        return

    # Step 1: Read the CSV file and filter the relevant rows
    full_tcp_open_ports = defaultdict(set)
    try:
        with open(csv_file, 'r') as file:
            reader = csv.DictReader(file)
            for row in reader:
                ip_address = row['IP Address']
                port_id = row['Port ID']
                if row['State'] == 'open':
                    full_tcp_open_ports[ip_address].add(port_id)
    except Exception as e:
        print(f"Error while reading CSV file: {e}")
        return

    # Step 2: Perform the `-sV` Nmap scan on the unique IP addresses and ports
    for ip_address, ports in full_tcp_open_ports.items():
        if ports:  # Only proceed if there are unique ports
            ports_str = ','.join(ports)
            output_path = os.path.join(output_directory, f"{ip_address}_sv_scan")
            command = ['nmap', '-sV', '-p', ports_str, '-Pn', ip_address, '-oA', output_path]

            try:
                subprocess.run(command, check=True)
                print(f"Nmap -sV scan output for {ip_address} saved to {output_path}")

                # Step 3: Parse the XML file and update the CSV file
                xml_file = output_path + '.xml'
                update_csv_with_sv_results(csv_update_file, xml_file, ip_address, full_tcp_open_ports)
            except subprocess.CalledProcessError as e:
                print(f"Error during Nmap scan for {ip_address}: {e}")
            except Exception as e:
                print(f"Unexpected error while scanning {ip_address}: {e}")


def update_csv_with_sv_results(csv_update_file, sv_xml_file, ip_address, full_tcp_open_ports):
    try:
        tree = ET.parse(sv_xml_file)
        root = tree.getroot()
    except ET.ParseError:
        print(f"Error parsing XML file: {sv_xml_file}")
        return

    updated_data = []
    try:
        with open(csv_update_file, 'r') as file:
            reader = csv.reader(file)
            headers = next(reader)
            updated_headers = [header for header in headers if header != 'Scan Type']
            updated_data.append(updated_headers)

            for row in reader:
                if row[1] == ip_address and row[2] in full_tcp_open_ports[ip_address]:
                    for host in root.findall('.//host'):
                        for port in host.findall('.//port'):
                            port_id = port.get('portid', '')
                            if port_id == row[2]:
                                service_elem = port.find('.//service')
                                service = service_elem.get('name', '') if service_elem is not None else ''
                                product = service_elem.get('product', '') if service_elem is not None else ''
                                version = service_elem.get('version', '') if service_elem is not None else ''
                                version_combined = f"{product} {version}".strip()
                                row[4] = service
                                row[5] = version_combined
                updated_row = [row[i] for i in range(len(headers)) if headers[i] != 'Scan Type']
                updated_data.append(updated_row)

        with open(csv_update_file, 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerows(updated_data)

    except FileNotFoundError:
        print(f"Error: CSV file '{csv_update_file}' not found.")
    except Exception as e:
        print(f"Unexpected error while updating CSV file: {e}")


def enumerate_subdomains(domain, output_txt):
    try:
        command = f'curl -s "https://crt.sh/?q=%25.{domain}&output=json" | jq -r \'.[].name_value\' | sort -u'
        result = subprocess.check_output(command, shell=True, text=True)
        print(f"Subdomain enumeration output:\n{result}")  # Debugging output
        subdomains = result.strip().split('\n')
        subdomains = [sub for sub in subdomains if sub and '*' not in sub]

        if not subdomains:
            print("No subdomains found or error in subdomain enumeration.")
        
        with open(output_txt, 'w') as file:
            for subdomain in subdomains:
                file.write(subdomain + "\n")
        print(f"Subdomains saved to {output_txt}")
    except subprocess.CalledProcessError as e:
        print(f"Error in subdomain enumeration: {e}")
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON response: {e}")

def get_ips_from_hostnames(input_txt, output_txt):
    try:
        with open(input_txt, 'r') as file:
            subdomains = [line.strip() for line in file.readlines()]

        with open(output_txt, 'w') as file:
            for subdomain in subdomains:
                try:
                    ip = socket.gethostbyname(subdomain)
                    file.write(f"{subdomain},{ip}\n")
                except (socket.gaierror, dns.resolver.NXDOMAIN):
                    file.write(f"{subdomain},0.0.0.0\n")

        print(f"IP addresses saved to {output_txt}")
    except Exception as e:
        print(f"Error in getting IPs from hostnames: {e}")

def check_reachability_for_domain(url):
    try:
        # Make a GET request to check if the domain is reachable and allow redirects
        response = requests.get(url, timeout=10, allow_redirects=True)
        final_url = response.url
        status_code = response.status_code
        
        # Check if the status code indicates a successful response (a reachable webpage)
        if status_code in range(200, 300):
            return True, final_url if final_url != url else None  # Return redirection URL if applicable
        else:
            return False, None  # Unsuccessful status code means the webpage isn't reachable
    except requests.RequestException:
        return False, None  # Handle any connection errors (domain not reachable)

def process_entry(entry):
    subdomain, ip = entry
    if ip != "0.0.0.0":  # Check only for valid IPs
        reachable, redirection = check_reachability_for_domain(f"http://{subdomain}")
        return [ip, subdomain, "Yes" if reachable else "No", redirection]  # Reachable = Yes or No
    else:
        return [ip, subdomain, "No", None]  # Mark as "No" if invalid IP

def check_reachability(input_txt, output_csv):
    try:
        with open(input_txt, 'r') as file:
            subdomains = [line.strip().split(',') for line in file.readlines()]

        results = []
        for entry in subdomains:
            result = process_entry(entry)
            results.append(result)

        save_to_csv(results, output_csv)
        print(f"Reachability results saved to {output_csv}")

    except Exception as e:
        print(f"Error in checking reachability: {e}")

def save_to_csv(results, filename):
    try:
        with open(filename, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["Reverse DNS IP", "Subdomain", "Reachable", "Redirection"])
            for result in results:
                writer.writerow(result)
    except Exception as e:
        print(f"Error in saving CSV: {e}")

def generate_excel_from_csv(top_port_csv, full_tcp_csv, subdomain_csv, output_excel):
    df_top_port = pd.read_csv(top_port_csv)
    df_full_tcp = pd.read_csv(full_tcp_csv)
    df_subdomain = pd.read_csv(subdomain_csv)

    with pd.ExcelWriter(output_excel, engine='openpyxl') as writer:
        df_top_port.to_excel(writer, sheet_name='Top Port Scan', index=False)
        df_full_tcp.to_excel(writer, sheet_name='Full TCP Scan', index=False)
        
        combined_df = pd.concat([df_top_port, df_full_tcp]).drop_duplicates(subset=['IP Address', 'Port ID'], keep='first')
        combined_df.to_excel(writer, sheet_name='Combined Unique', index=False)

        df_subdomain.to_excel(writer, sheet_name='Subdomain Info', index=False)

    print(f"Excel file {output_excel} created successfully with four sheets.")

def main():
    welcome_message()

    # Prompt the user for the choice of operation
    print("\nChoose an option:")
    print("1. Run TCP and UDP Top Port Scan")
    print("2. Run Full TCP Port Scan")
    print("3. Run EPT Scan")
    print("4. Run Subdomain Enumeration")
    choice = input("Enter your choice (1, 2, 3, or 4): ")

    if choice == '4':
        # Directly handle option 4 without initializing other variables
        project_name = get_project_name()
        project_path, _, _, _, _, _, _ = create_project_directory(project_name, choice)
        
        subdomain_folder = os.path.join(project_path, 'subdomain_info')
        os.makedirs(subdomain_folder, exist_ok=True)
        
        subdomains_txt = os.path.join(subdomain_folder, 'subdomains.txt')
        ips_txt = os.path.join(subdomain_folder, 'ips.txt')
        output_csv = os.path.join(subdomain_folder, 'subdomain_results.csv')

        domain = input("Enter the domain to perform subdomain enumeration: ")
        enumerate_subdomains(domain, subdomains_txt)
        get_ips_from_hostnames(subdomains_txt, ips_txt)
        check_reachability(ips_txt, output_csv)

        # Add the subdomain results to the Excel file if it exists
        excel_output_file = os.path.join(project_path, 'nmap_scan_results.xlsx')
        if os.path.exists(excel_output_file):
            generate_excel_from_csv(
                os.path.join(project_path, 'nmap_tcp_udp_top_port_scan_csv_converted.csv'),
                full_tcp_csv,
                output_csv,
                excel_output_file
            )
        return

    # Initialize common variables before other options
    project_name = get_project_name()
    number_of_ips = get_number_of_ips()
    file_path = select_file()

    print(f"Selected file: {file_path}")

    with open(file_path, 'r') as file:
        ip_addresses = [line.strip() for line in file if line.strip()]

    if len(ip_addresses) != number_of_ips:
        print(f"Error: The number of IP addresses in the file ({len(ip_addresses)}) does not match the specified number of IP addresses ({number_of_ips}).")
        return

    duplicates = check_for_duplicates(ip_addresses)
    if duplicates:
        print("Duplicate IP addresses found:")
        for ip, positions in duplicates.items():
            print(f"{ip} appears at positions {positions}")
        user_input = get_input("\nDo you want to proceed with the batch division? (Y or yes to proceed, any other key to exit): ").lower()
        if user_input not in ('y', 'yes'):
            print("Exiting the tool.")
            return

    for ip in ip_addresses:
        if not validate_ip(ip):
            print(f"Error: Invalid IP address format detected: {ip}")
            return

    project_path, nmap_scans_path, top_port_tcp_scan_path, top_port_udp_scan_path, ssl_cert_scan_path, cipher_enum_scan_path, full_port_tcp_scan_path = create_project_directory(project_name, choice)

    host_ips_file = os.path.join(project_path, 'host_ips.txt')
    with open(host_ips_file, 'w') as file:
        for ip in ip_addresses:
            file.write(f"{ip}\n")

    print(f"\nIP addresses saved to {host_ips_file}")

    batch_files = [host_ips_file]
    if len(ip_addresses) > 6:
        num_batches = get_number_of_batches()
        batches = divide_ips_into_batches(ip_addresses, num_batches)
        batch_files = save_batches(batches, project_path)

        for i, batch in enumerate(batches, start=1):
            print(f"Batch {i}: {len(batch)} IP addresses")

    nmap_host_scan_output = os.path.join(nmap_scans_path, 'nmap_host_Running_status')
    subprocess.run(['nmap', '-sn', '-iL', host_ips_file, '-oN', nmap_host_scan_output])

    print(f"Nmap host running status scan output saved to {nmap_host_scan_output}")

    # Initialize all_data with empty lists for each batch
    all_data = [[] for _ in range(len(batch_files))]

    if choice == '1':
        handle_tcp_udp_ssl_cipher_scans(batch_files, project_path, top_port_tcp_scan_path, top_port_udp_scan_path, ssl_cert_scan_path, cipher_enum_scan_path, all_data, host_ips_file)
    elif choice == '2':
        full_tcp_csv = handle_full_port_tcp_scan(batch_files, project_path, full_port_tcp_scan_path, all_data)

        sv_output_directory = os.path.join(project_path, 'sv_full_port_results')
        os.makedirs(sv_output_directory, exist_ok=True)
        
        csv_update_file = full_tcp_csv  # Assuming the csv_update_file is the same as full_tcp_csv in this context
        perform_sv_scan_from_csv(full_tcp_csv, sv_output_directory, csv_update_file)
    elif choice == '3':
        handle_tcp_udp_ssl_cipher_scans(batch_files, project_path, top_port_tcp_scan_path, top_port_udp_scan_path, ssl_cert_scan_path, cipher_enum_scan_path, all_data, host_ips_file)
        full_tcp_csv = handle_full_port_tcp_scan(batch_files, project_path, full_port_tcp_scan_path, all_data)

        sv_output_directory = os.path.join(project_path, 'sv_full_port_results')
        os.makedirs(sv_output_directory, exist_ok=True)
        
        csv_update_file = full_tcp_csv  # Assuming the csv_update_file is the same as full_tcp_csv in this context
        perform_sv_scan_from_csv(full_tcp_csv, sv_output_directory, csv_update_file)
        
        excel_output_file = os.path.join(project_path, 'nmap_scan_results.xlsx')
        generate_excel_from_csv(
            os.path.join(project_path, 'nmap_tcp_udp_top_port_scan_csv_converted.csv'),
            full_tcp_csv,
            os.path.join(project_path, 'subdomain_info', 'subdomain_results.csv'),
            excel_output_file
        )
    else:
        print("Invalid choice. Exiting the tool.")
        return

if __name__ == "__main__":
    main()







