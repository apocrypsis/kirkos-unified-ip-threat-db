import os
import re
import sys
import json
import zipfile
import requests
import tempfile
import pytricia
from netaddr import IPSet
from mmdb_writer import MMDBWriter


OXL_IP_JSON_URL = "https://geoip.oxl.app/file/asn_ipv4_full.json.zip"
OXL_IP_LIST_REPO_URL = "https://github.com/O-X-L/risk-db-lists/archive/refs/heads/main.zip"

SHARED_TEMP_DIR_OBJ = tempfile.TemporaryDirectory()
SHARED_TEMP_PATH = os.path.abspath(SHARED_TEMP_DIR_OBJ.name)

# Use pytricia for fast lookups of CIDR blocks.
trie = pytricia.PyTricia()

def _error_and_exit(err_msg: str):
    print(err_msg)
    sys.exit(1)

def _download_and_extract(url: str, subfolder_name: str, max_size_mb: int = 100):
    print(f"Downloading file from {url}")
    try:
        target_dir = os.path.join(SHARED_TEMP_PATH, subfolder_name)
        os.makedirs(target_dir, exist_ok=True)
        abs_target_dir = os.path.abspath(target_dir)
    except Exception as dir_err:
        _error_and_exit(f"Error creating temporary directory {target_dir}: {str(dir_err)}")
        
    try:
        resp = requests.get(url, timeout=30, stream=True)
    except Exception as dl_err:
        _error_and_exit(f"Error downloading file from {url}: {str(dl_err)}")

    if not resp.status_code == 200:
        _error_and_exit(f"HTTP 200 not received for {url}")

    # Create a temporary file for the download.
    # Specify delete=False so it doesn't get deleted on close.
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as temp_file:
        zip_tmp_path = temp_file.name

    # Write the file to temporary storage.
    with open(zip_tmp_path, "wb") as f:
        for chunk in resp.iter_content(chunk_size=65536):
            if chunk:
                f.write(chunk)

    # Extraction code based on 
    # https://medium.com/@01one/complete-guide-how-to-zip-and-unzip-files-with-python-c0107700b392

    filename = os.path.basename(zip_tmp_path)

    max_size_bytes = max_size_mb * 1024 * 1024
    try:
        current_total_size = 0
        print(f"Extracting into subfolder: {abs_target_dir}...")
        with zipfile.ZipFile(zip_tmp_path, "r") as zip_ref:
            try:
                zip_ref.testzip()
            except Exception as e:
                _error_and_exit(f"Zip file validation failed for {filename}: {e}")

            for member in zip_ref.infolist():
                # Check to ensure file paths are relative to target download dir.
                abs_filepath = os.path.abspath(os.path.join(abs_target_dir, member.filename))
                common_path = os.path.commonpath([abs_target_dir, abs_filepath])
                if abs_target_dir != common_path:
                    _error_and_exit(f"Member files have absolute paths or dot segments within {filename}")

                # Ensure file size is manageable.
                current_total_size += member.file_size
                if current_total_size > max_size_bytes:
                    _error_and_exit(
                        f"Zip file {filename} too large: "
                        f"{current_total_size/1024/1024:.1f}MB is greater than "
                        f"allowed max of {max_size_mb}MB"
                    )

                zip_ref.extract(member, path=abs_target_dir)
        return abs_target_dir

    finally:
        if os.path.exists(zip_tmp_path):
            os.remove(zip_tmp_path)

def download_and_parse_oxl_ip_json():
    oxl_json_location = _download_and_extract(OXL_IP_JSON_URL, "oxl_json")
    json_path = os.path.join(oxl_json_location, "asn_ipv4_full.json")
    if not os.path.exists(json_path):
        _error_and_exit(f"JSON file does not exist at {json_path}")
    
    print(f"Parsing OXL JSON")
    raw_json = {}
    try:
        with open(json_path) as f:
            raw_json = json.load(f)
    except Exception as json_err:
        _error_and_exit(f"Error loading JSON {json_path}")
    
    for asn in raw_json:
        ipv4 = raw_json[asn].get("ipv4", [])
        org = raw_json[asn].get("organization", {})
        org_name = org.get("name", "").lower()
    
        if not isinstance(ipv4, list):
            if isinstance(ipv4, str):
                ipv4 = [ipv4]
            else:
                _error_and_exit("ipv4 field does not hold string or list value.")

        for ip_address in ipv4:
            trie[ip_address] = {
                "asn": asn,
                "org": org_name
            }

def download_and_parse_oxl_risk_lists():
    risk_ips = {}
    repo_dl_location = _download_and_extract(OXL_IP_LIST_REPO_URL, "oxl_risk_lists")
    ip_list_path = os.path.join(repo_dl_location, "risk-db-lists-main", "ip")
    
    print(f"Parsing OXL risk lists")
    # Separate out the "kind_<category>" files from the "top_<int>" files.
    type_files = []
    top_files = []
    for root, dirs, filenames in os.walk(ip_list_path):
        for filename in filenames:
            if filename.startswith("kind_maybe_hacked"): continue
            if filename.endswith(".csv"): continue
            filepath = os.path.join(root, filename)
            if filename.startswith("kind_"):
                type_files.append(filepath)
            elif filename.startswith("top"):
                top_files.append(filepath)

    # Extract and assign the type to every IP within the file.
    # Note that we run the risk of missing some classifications if 
    # a single IP is classified as multiple types.
    ips = {}
    for type_file in type_files:
        type_filename = os.path.basename(type_file)
        kind = type_filename.replace("kind_", "").replace(".txt", "")
        with open(type_file) as f:
            ips = {line.strip() for line in f if line.strip()}
        
        for ip in ips:
            # Support only IPv4 addresses for now.
            if ":" in ip:
                continue
            if "/" not in ip: 
                ip = ip + "/32"
            risk_ips[ip] = {
                "type": kind
            }

    # Use the file with the most reported IPs.
    largest_file = max(top_files, key=lambda x: int(re.search(r'\d+', x).group()))
    reported_ips = {}
    with open(largest_file) as f:
        reported_ips = {reported_ip.strip() for reported_ip in f if reported_ip.strip()}
    for reported_ip in reported_ips:
        if ":" in reported_ip:
            continue
        if "/" not in reported_ip: 
            reported_ip = reported_ip + "/32"
        if reported_ip not in risk_ips:
            risk_ips[reported_ip] = {}
        risk_ips[reported_ip]["reported"] = True
    return risk_ips

def enrich_risk_lists(parsed_risk_lists: dict):
    print(f"Enriching risk lists")
    for ip in parsed_risk_lists:
        if ip in trie:
            org_info_object = trie[ip]
            parsed_risk_lists[ip]["asn"] = org_info_object["asn"]
            parsed_risk_lists[ip]["org"] = org_info_object["org"]

def generate_mmdb(parsed_risk_lists):
    print(f"Generating MMDB")
    writer = MMDBWriter()
    
    # First insert the larger CIDR blocks from Pytricia.
    for cidr_string in trie.keys():
        payload = trie[cidr_string]
        writer.insert_network(IPSet([cidr_string]), payload)
    
    # Insert the /32 addresses from the JSON.
    for ip_32_string, payload in parsed_risk_lists.items():
        writer.insert_network(IPSet([ip_32_string]), payload)

    print(f"Writing MMDB to file")
    writer.to_db_file("ip_intel.mmdb")
    
def main():
    try:
        download_and_parse_oxl_ip_json()
        parsed_risk_lists = download_and_parse_oxl_risk_lists()
        enrich_risk_lists(parsed_risk_lists)
        generate_mmdb(parsed_risk_lists)
    finally:
        SHARED_TEMP_DIR_OBJ.cleanup()

if __name__ == "__main__":
    main()