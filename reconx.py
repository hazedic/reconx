#!/usr/bin/env python3
import subprocess
import os
import sys
from concurrent.futures import ThreadPoolExecutor
import argparse
import logging
import json
from urllib.parse import urlparse
import shutil
import time
from colorama import init, Fore, Style
import urllib3
import dns.resolver
import dns.reversename
import random

init()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class ColoredFormatter(logging.Formatter):
    FORMATS = {
        logging.DEBUG: Fore.YELLOW + "%(asctime)s - %(levelname)s - %(message)s" + Style.RESET_ALL,
        logging.INFO: Fore.GREEN + "%(asctime)s - %(levelname)s - %(message)s" + Style.RESET_ALL,
        logging.WARNING: Fore.MAGENTA + "%(asctime)s - %(levelname)s - %(message)s" + Style.RESET_ALL,
        logging.ERROR: Fore.RED + "%(asctime)s - %(levelname)s - %(message)s" + Style.RESET_ALL,
    }
    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)

logging.basicConfig(level=logging.INFO, handlers=[logging.StreamHandler(sys.stdout)], force=True)
logging.getLogger().handlers[0].setFormatter(ColoredFormatter())

class SimpleParser(argparse.ArgumentParser):
    def __init__(self, *args, **kwargs):
        kwargs.setdefault("formatter_class", argparse.ArgumentDefaultsHelpFormatter)
        super().__init__(*args, **kwargs)
    def error(self, message):
        self.print_help()
        sys.exit(2)

parser = SimpleParser(description="ReconX: Automated reconnaissance tool")
parser.add_argument("domain", help="Target domain to scan (e.g., example.com)")
parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed command logs")
parser.add_argument("-s", "--screenshot", action="store_true", help="Take screenshots of subdomains")
parser.add_argument("-w", "--wide", action="store_true", help="Perform reverse DNS lookup in target’s /24 network")
args = parser.parse_args()

if args.verbose:
    logging.getLogger().setLevel(logging.DEBUG)
else:
    logging.getLogger().setLevel(logging.INFO)

def log_info(message):
    logging.info(message)

CONFIG_FILE = "config.json"
DEFAULT_CONFIG = {
    "subfinder_threads": 100,
    "httpx_threads": 50,
    "httpx_timeout": 5,
    "katana_depth": 5,
    "katana_concurrency": 20,
    "exclude_extensions": "ttf,woff,woff2,svg,png,jpg,jpeg,gif,mp4,mp3,pdf,css,js,ico,eot",
    "dns_resolvers": "8.8.8.8,1.1.1.1",
    "gowitness_timeout": 20,
    "required_tools": [
        "subfinder",
        "assetfinder",
        "amass",
        "httpx",
        "waymore",
        "katana",
        "gospider",
        "gowitness",
        "subzy"
    ]
}

def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
            logging.debug(f"Loaded configuration from {CONFIG_FILE}: {config}")
            return config
    logging.debug(f"Using default configuration: {DEFAULT_CONFIG}")
    return DEFAULT_CONFIG

CONFIG = load_config()

def check_tool_installed(tool):
    return shutil.which(tool) is not None

def check_required_tools():
    missing_tools = [tool for tool in CONFIG['required_tools'] if not check_tool_installed(tool)]
    if missing_tools:
        logging.error(f"The following required tools are missing: {', '.join(missing_tools)}")
        logging.error("Please install them and try again.")
        exit(1)

def count_lines(file_path):
    if file_path and os.path.exists(file_path):
        with open(file_path, 'r') as f:
            return sum(1 for line in f if line.strip())
    return 0

def run_command(command, output_file=None, task_description="Processing", input_file=None):
    if input_file and not os.path.exists(input_file):
        logging.error(f"Input file missing for {task_description}: {input_file} does not exist")
        return None
    if input_file and count_lines(input_file) == 0:
        logging.warning(f"Input file is empty for {task_description}: {input_file}")
    try:
        start_time = time.time()
        logging.debug(f"  - Command: {command}")
        result = subprocess.run(command, shell=True, capture_output=True, text=True, errors='replace')
        if output_file and result.stdout:
            with open(output_file, 'w') as f:
                f.write(result.stdout)
            lines = count_lines(output_file)
            log_info(f"✓ {task_description} completed - {lines} items processed in {time.time() - start_time:.2f}s")
            return output_file
        if result.returncode != 0:
            logging.error(f"Task failed: {task_description}\nError: {result.stderr.strip()}")
            return None
        lines = len(result.stdout.splitlines())
        log_info(f"✓ {task_description} completed - {lines} items processed in {time.time() - start_time:.2f}s")
        return result.stdout
    except Exception as e:
        logging.error(f"Exception in {task_description}: {str(e)}")
        return None

def run_parallel(commands, phase_name="Parallel tasks"):
    results = []
    total_tasks = len(commands)
    successful_tasks = 0
    max_workers = min(os.cpu_count() * 2, total_tasks) or 4
    log_info(f"Starting {phase_name} ({total_tasks} tasks)")
    log_info("─" * 50)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(run_command, cmd['command'], cmd.get('output'), cmd.get('task'), cmd.get('input')): cmd for cmd in commands}
        for future in futures:
            result = future.result()
            if result:
                successful_tasks += 1
                results.append(result)
            progress = successful_tasks / total_tasks
            bar_length = 20
            filled = int(bar_length * progress)
            bar = "█" * filled + "─" * (bar_length - filled)
            logging.info(f"Progress: [{bar}] {successful_tasks}/{total_tasks} tasks ({progress * 100:.1f}%)")
    log_info("─" * 50)
    log_info(f"{phase_name} automated with {successful_tasks}/{total_tasks} successful tasks")
    return results

def normalize_url(url):
    try:
        parsed = urlparse(url.strip())
        if not parsed.scheme or not parsed.netloc:
            return None
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}".rstrip('/')
    except Exception:
        return None

def merge_and_deduplicate(files, output_file):
    if not files:
        logging.warning("No files to merge. Creating empty output file.")
        with open(output_file, 'w') as f:
            f.write('')
        return output_file
    unique_urls = set()
    for file in files:
        with open(file, 'r') as f:
            for line in f:
                normalized = normalize_url(line)
                if normalized:
                    unique_urls.add(normalized)
    with open(output_file, 'w') as f:
        f.write('\n'.join(sorted(unique_urls)))
    lines = len(unique_urls)
    log_info(f"✓ URL merging and deduplication completed - {lines} unique URLs saved to {output_file}")
    return output_file

def dns_query(resolver, domain, record_type='A'):
    try:
        resp = resolver.resolve(domain, record_type, raise_on_no_answer=False)
        if resp:
            return resp
        logging.debug(f"{domain} has no {record_type} records")
        return None
    except dns.exception.Timeout:
        logging.error(f"Timeout querying {domain} ({record_type})")
        return None
    except dns.resolver.NXDOMAIN:
        logging.debug(f"{domain} does not exist ({record_type})")
        return None
    except dns.resolver.NoAnswer:
        logging.debug(f"No {record_type} answer for {domain}")
        return None
    except Exception as e:
        logging.error(f"Failed to query {domain} ({record_type}): {e}")
        return None

def wide_scan(resolver, ip):
    base_ip = '.'.join(ip.split('.')[:-1])
    logging.info(f"Scanning /24 range: {base_ip}.0/24")
    nearby_hosts = []
    for i in range(1, 255):
        test_ip = f"{base_ip}.{i}"
        try:
            reverse_name = dns.reversename.from_address(test_ip)
            ptr_resp = dns_query(resolver, reverse_name, 'PTR')
            if ptr_resp:
                for ptr in ptr_resp:
                    nearby_hosts.append(f"{test_ip} -> {ptr.target}")
        except Exception:
            continue
    return nearby_hosts

def dns_recon(domain, subdomain_file, wide=True):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = CONFIG['dns_resolvers'].split(',')
    output_file = f"scan_{domain}/dns_recon_results.txt"
    results = []
    wildcard_test = f"wild{random.randint(1000, 9999)}.{domain}"
    wildcard_resp = dns_query(resolver, wildcard_test)
    if wildcard_resp:
        results.append("Wildcard DNS detected")
    else:
        results.append("No wildcard DNS detected")
    ns_resp = dns_query(resolver, domain, 'NS')
    if ns_resp:
        results.append("Name Servers:")
        for ns in ns_resp:
            results.append(f"  - {ns.target}")
    soa_resp = dns_query(resolver, domain, 'SOA')
    if soa_resp:
        results.append("SOA Record:")
        for soa in soa_resp:
            results.append(f"  - {soa.mname}")
    with open(subdomain_file, 'r') as f:
        subdomains = [line.strip() for line in f if line.strip()]
    found_ips = []
    for sub in subdomains:
        a_resp = dns_query(resolver, sub, 'A')
        if a_resp:
            results.append(f"Found: {sub}")
            for r in a_resp:
                ip = r.address
                results.append(f"  - {ip}")
                found_ips.append(ip)
    if wide and found_ips:
        results.append("Wide Scan Results:")
        for ip in found_ips:
            nearby_hosts = wide_scan(resolver, ip)
            results.extend(nearby_hosts)
    with open(output_file, 'w') as f:
        f.write('\n'.join(results))
    log_info(f"✓ DNS reconnaissance completed - results saved to {output_file}")
    return output_file

def automate_scan(domain):
    output_dir = f"scan_{domain}"
    os.makedirs(output_dir, exist_ok=True)
    subfinder_domains = f"{output_dir}/subfinder_domains.txt"
    assetfinder_domains = f"{output_dir}/assetfinder_domains.txt"
    amass_domains = f"{output_dir}/amass_domains.txt"
    merged_domains = f"{output_dir}/merged_domains.txt"
    httpx_alive_domains = f"{output_dir}/httpx_alive_domains.txt"
    waymore_urls = f"{output_dir}/waymore_urls.txt"
    katana_urls = f"{output_dir}/katana_urls.txt"
    gospider_urls = f"{output_dir}/gospider_urls.txt"
    merged_urls = f"{output_dir}/merged_urls.txt"
    gowitness_db = f"{output_dir}/gowitness.sqlite3"
    subzy_results = f"{output_dir}/subzy_results.txt"
    log_info(f"Starting reconnaissance for {domain}")
    log_info("═" * 50)
    initial_commands = [
        {"command": f"subfinder -d {domain} -t {CONFIG['subfinder_threads']} -silent -nW", "output": subfinder_domains, "task": "Subdomain enumeration with subfinder"},
        {"command": f"assetfinder -subs-only {domain}", "output": assetfinder_domains, "task": "Subdomain enumeration with assetfinder"},
        {"command": f"timeout 600s amass enum -active -d {domain} -r {CONFIG['dns_resolvers']} -v | awk '{{print $1}}' | grep -v '^[0-9]' > {amass_domains}", "output": amass_domains, "task": "Subdomain enumeration with amass"}
    ]
    subdomain_results = run_parallel(initial_commands, phase_name="Subdomain enumeration")
    if not subdomain_results:
        logging.error("No subdomains enumerated successfully. Aborting.")
        return
    merge_result = run_command(
        rf"cat {subfinder_domains} {assetfinder_domains} {amass_domains} | awk '{{print $1}}' | grep -E '^[a-zA-Z0-9.-]+\.{domain}$' | sort -u -f | grep -v '^\*'",
        merged_domains,
        "Merging subdomain results"
    )
    if not merge_result:
        logging.error("Failed to merge subdomains. Aborting.")
        return
    log_info("─" * 50)
    log_info("Starting DNS reconnaissance")
    dns_recon_result = dns_recon(domain, merged_domains, wide=args.wide)
    alive_result = run_command(
        rf"httpx -list {merged_domains} -threads {CONFIG['httpx_threads']} -timeout {CONFIG['httpx_timeout']} -silent -mc 200,301,302,304,307,308,403,401,503,500 -follow-redirects -cl | awk '{{print $1}}'",
        httpx_alive_domains,
        "Checking alive domains with httpx",
        input_file=merged_domains
    )
    if not alive_result or count_lines(httpx_alive_domains) == 0:
        logging.warning("No alive domains found with httpx. Using merged domains as fallback.")
        shutil.copy(merged_domains, httpx_alive_domains)
        alive_result = httpx_alive_domains
    if count_lines(httpx_alive_domains) == 0:
        logging.error("No valid domains available for URL crawling. Aborting.")
        return
    log_info("─" * 50)
    gospider_output_dir = f"{output_dir}/gospider_output"
    os.makedirs(gospider_output_dir, exist_ok=True)
    scan_commands = [
        {"command": rf"waymore -i {domain} -mode U -oU {waymore_urls}", "output": waymore_urls, "task": "URL crawling with waymore"},
        {"command": f"katana -list {httpx_alive_domains} -d {CONFIG['katana_depth']} -c {CONFIG['katana_concurrency']} -js-crawl -ef {CONFIG['exclude_extensions']} -fs rdn", "output": katana_urls, "task": "URL crawling with katana", "input": httpx_alive_domains},
        {"command": rf"gospider -S {httpx_alive_domains} -d 5 -c 30 -t 20 -o {gospider_output_dir} --whitelist-domain {domain} --blacklist 'png|jpg|jpeg|gif|mp4|pdf' --js --sitemap --robots -a -w -r --subs -m 15 > {gospider_urls}", "output": gospider_urls, "task": "URL crawling with gospider", "input": httpx_alive_domains}
    ]
    url_results = []
    for cmd in scan_commands:
        result = run_command(cmd['command'], cmd['output'], cmd['task'], cmd.get('input'))
        if result:
            url_results.append(result)
    merge_urls_result = merge_and_deduplicate(url_results, merged_urls)
    if not merge_urls_result:
        logging.warning("No URLs collected. Reconnaissance completed with empty results.")
        return
    log_info("─" * 50)
    subzy_cmd = f"subzy run --targets {merged_domains} > {subzy_results}"
    subzy_result = run_command(subzy_cmd, subzy_results, "Checking for subdomain takeovers with subzy", input_file=merged_domains)
    if args.screenshot:
        log_info("─" * 50)
        gowitness_cmd = f"gowitness scan file -f {merged_domains} --save-content --write-db --write-db-uri sqlite://{gowitness_db} --screenshot-path {output_dir}/screenshots --timeout {CONFIG['gowitness_timeout']}"
        run_command(gowitness_cmd, task_description="Capturing screenshots with gowitness", input_file=merged_domains)
    logging.info("═" * 50)
    logging.info(f"Reconnaissance completed! Final results saved in {merged_urls}")
    logging.info("Summary:")
    logging.info(f"  - Subdomains found: {count_lines(merged_domains)}")
    logging.info(f"  - Alive domains: {count_lines(httpx_alive_domains)}")
    logging.info(f"  - Total URLs crawled: {count_lines(merged_urls)}")
    if dns_recon_result:
        logging.info(f"  - DNS recon results: {dns_recon_result}")
    if subzy_result:
        logging.info(f"  - Subdomain takeover results: {subzy_results} ({count_lines(subzy_results)} potential issues)")
    if args.screenshot and os.path.exists(gowitness_db):
        logging.info(f"  - Screenshots saved: {gowitness_db}")
    logging.info("═" * 50)

if __name__ == "__main__":
    check_required_tools()
    automate_scan(args.domain)
