import os
import re
import sys
import time
import json
import ijson
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

def _error_and_exit(err_msg: str):
    print(f"::error::{err_msg}") 
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
        # Stream the data, rather than downloading all at once.
        with requests.get(url, timeout=30, stream=True) as resp:
            if not resp.status_code == 200:
                _error_and_exit(f"HTTP 200 not received for {url}")

            # Create a temporary file for the download.
            # Specify delete=False so it doesn't get deleted on close.
            with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as temp_file:
                zip_tmp_path = temp_file.name

            # Write the file to temporary storage in chunks.
            with open(zip_tmp_path, "wb") as f:
                for chunk in resp.iter_content(chunk_size=65536):
                    if chunk: # filter out keep-alive chunks
                        f.write(chunk)

    except Exception as dl_err:
        _error_and_exit(f"Error downloading file from {url}: {str(dl_err)}")

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
    # Cache common ASN/orgs.
    string_cache = {}
    payload_cache = {}

    # Use pytricia for fast lookups of CIDR blocks.
    trie = pytricia.PyTricia()

    try:
        with open(json_path, "rb") as infile:
            # Get items from root.
            kv_pairs = ijson.kvitems(infile, "")

            for asn, asn_obj in kv_pairs:
                if not isinstance(asn_obj, dict):
                    continue

                ipv4 = asn_obj.get("ipv4", [])
                raw_asn = asn
                raw_org = asn_obj.get("info", {}).get("name", "").lower() or asn_obj.get("organization", {}).get("name", "").lower()
                
                # Cache individual strings to reuse them.
                if raw_asn not in string_cache:
                    string_cache[raw_asn] = sys.intern(str(raw_asn))
                if raw_org not in string_cache:
                    string_cache[raw_org] = sys.intern(str(raw_org))
                
                cached_asn = string_cache[raw_asn]
                cached_org = string_cache[raw_org]
                
                # Cache the payload combination.
                combo_key = (cached_asn, cached_org)
                if combo_key not in payload_cache:
                    payload_cache[combo_key] = {
                        "asn": cached_asn,
                        "org": cached_org
                    }

                if not isinstance(ipv4, list):
                    if isinstance(ipv4, str):
                        ipv4 = [ipv4]
                    else:
                        print("WARN: ipv4 field does not hold string or list value for ASN {asn}.")
                        continue
                
                for ip_address in ipv4:
                    trie[ip_address] = payload_cache[combo_key]

        return (json_path, trie)

    except Exception as json_err:
        _error_and_exit(f"Error loading JSON {json_path}")
    

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
    ips = set()
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

def enrich_risk_lists(parsed_risk_lists: dict, trie):
    print(f"Enriching risk lists")
    for ip in parsed_risk_lists:
        if ip in trie:
            org_info_object = trie[ip]
            parsed_risk_lists[ip]["asn"] = org_info_object["asn"]
            parsed_risk_lists[ip]["org"] = org_info_object["org"]

def generate_mmdb(json_path, parsed_risk_lists, trie):
    print(f"Generating MMDB")

    writer = MMDBWriter()
    
    # First insert all the IPv4 blocks from the Pytricia object.
    try:
        for cidr_string in trie.keys():
            writer.insert_network(IPSet([cidr_string]), trie[cidr_string])

    except Exception as writer_err:
        _error_and_exit(f"Error writing CIDR blocks to mmdb: {str(writer_err)}")           
    
    try:
        # Insert the /32 addresses from the risk lists.
        for ip_32_string, payload in parsed_risk_lists.items():
            writer.insert_network(IPSet([ip_32_string]), payload)
    except Exception as risk_writer_err:
        _error_and_exit(f"Error writing risk data to mmdb: {str(risk_writer_err)}")  

    print(f"Writing to MMDB")

    # Free up some memory before writing to file.
    parsed_risk_lists.clear()
    trie = None

    try:
        writer.to_db_file("ip_intel.mmdb")
    except Exception as write_err:
        print(f"Error writing to MMDB: {str(write_err)}")
    
def main():
    try:
        start_time = time.perf_counter()

        (oxl_json_path, trie) = download_and_parse_oxl_ip_json()
        parsed_risk_lists = download_and_parse_oxl_risk_lists()
        enrich_risk_lists(parsed_risk_lists, trie)

        elapsed_time = time.perf_counter() - start_time
        print(f"Elapsed time prior to MMDB generation: {elapsed_time:.2f} seconds")
        generate_mmdb(oxl_json_path, parsed_risk_lists, trie)

        end_time = time.perf_counter()
        total_elapsed_time = end_time - start_time
        print(f"Total execution time: {total_elapsed_time:.2f} seconds")

    except Exception as err:
        _error_and_exit(f"Error during execution: {str(err)}")
    finally:
        SHARED_TEMP_DIR_OBJ.cleanup()

if __name__ == "__main__":
    main()