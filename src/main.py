#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Author: Dexogen <dexogen@gmail.com>
Description:
Date: 2024/01/03
Version: 1.0
Licence: MIT
"""


import os
import sys
import time
import json
import yaml
import logging
import requests
import ipaddress
import threading
import subprocess
from inotify_simple import INotify, flags


def read_config():
    env_config = {}
    try:
        env_config["proxmox_host"] = os.environ["PROXMOX_HOST"]
        env_config["api_token_id"] = os.environ["API_TOKEN_ID"]
        env_config["api_token_secret"] = os.environ["API_TOKEN_SECRET"]
        env_config["network_cidr"] = os.environ["NETWORK_CIDR"]
        env_config["dns_domain"] = os.environ["DNS_DOMAIN"]

        return env_config
    except KeyError as e:
        log(f"Missing environment variable: {e}", 'error')
        sys.exit(1)


config = read_config()

PROXMOX_HOST = config["proxmox_host"]
API_TOKEN_ID = config["api_token_id"]
API_TOKEN_SECRET = config["api_token_secret"]
NETWORK_CIDR = config["network_cidr"]
DNS_DOMAIN = config["dns_domain"]

DNSMASQ_CONF = "/etc/dnsmasq.d/pve.conf"
DNSMASQ_STATIC = "/etc/dnsmasq.d/pve.static"
DNSMASQ_ARP = "/etc/dnsmasq.d/pve.arp"
DNSMASQ_LEASES = "/var/lib/misc/dnsmasq.leases"

VERIFY_SSL = os.getenv("VERIFY_SSL", "true").lower() == "true"
SYNC_INTERVAL = int(os.getenv("SYNC_INTERVAL", 300))
ARP_SCAN_INTERVAL = int(os.getenv("ARP_CHECK_INTERVAL", 30))
LOG_LEVEL = getattr(logging, os.getenv('LOG_LEVEL', 'ERROR').upper(), logging.ERROR)

logging.basicConfig(
    stream=sys.stdout,
    level=LOG_LEVEL,
    format='%(asctime)s %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S,%f'
)


def log(msg, level='info'):
    if level == 'debug':
        logging.debug(msg)
    elif level == 'info':
        logging.info(msg)
    elif level == 'warning':
        logging.warning(msg)
    elif level == 'error':
        logging.error(msg)
    elif level == 'critical':
        logging.critical(msg)


def get_headers():
    return {
        "Authorization": f"PVEAPIToken={API_TOKEN_ID}={API_TOKEN_SECRET}",
        "Content-Type": "application/json"
    }


def safe_get(url, params=None):
    try:
        r = requests.get(url, headers=get_headers(), verify=VERIFY_SSL, params=params, timeout=5)
        r.raise_for_status()
        return r.json().get("data", {}), None
    except requests.RequestException as e:
        return None, str(e)


def safe_get_text(url, params=None):
    try:
        r = requests.get(url, headers=get_headers(), verify=VERIFY_SSL, params=params, timeout=5)
        r.raise_for_status()
        return r.text, None
    except requests.RequestException as e:
        return None, str(e)


def in_network(ip_str, network_cidr):
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip in ipaddress.ip_network(network_cidr, strict=False)
    except ValueError:
        return False


def parse_lxc_ip(config_str):
    import re
    m = re.search(r"ip=([\d.]+)/\d+", config_str or "")
    return m.group(1) if m else None


def parse_cloudinit_dump(raw_json_str):
    try:
        outer = json.loads(raw_json_str or "")
    except json.JSONDecodeError:
        return None
    try:
        data = yaml.safe_load(outer.get("data", ""))
    except yaml.YAMLError:
        return None
    if not isinstance(data, dict):
        return None
    version = data.get("version")
    if version == 1:
        for item in data.get("config", []):
            if item.get("type") == "physical":
                for sb in item.get("subnets", []):
                    if sb.get("type") == "static":
                        return sb.get("address")
    elif version == 2:
        for iface in data.get("ethernets", {}).values():
            for addr in iface.get("addresses", []):
                return addr.split("/")[0] if "/" in addr else addr
    return None


def restart_dnsmasq():
    try:
        subprocess.run(['supervisorctl', '-c', '/etc/supervisord.conf', 'restart', 'dnsmasq'], check=True)
        log("Restarted dnsmasq service.")
    except subprocess.CalledProcessError as e:
        log(f"Failed to restart dnsmasq: {e}", 'error')


def sync_with_proxmox():
    log("Synchronizing with Proxmox API...")
    url = f"{PROXMOX_HOST}/api2/json/cluster/resources"
    vm_list, err = safe_get(url, params={"type": "vm"})
    if err or not vm_list:
        log(f"Error accessing Proxmox: {err or 'empty VM list'}", 'error')
        return {}, False

    static_lines = []
    dynamic_names = []
    static_ips = {}
    known_fqdns = set()

    for vm in vm_list:
        vm_type = vm.get("type")
        vmid = vm.get("vmid")
        node = vm.get("node")
        name = vm.get("name") or f"vm{vmid}"
        if not (vm_type and vmid and node):
            continue

        ip = None
        if vm_type == "lxc":
            url_conf = f"{PROXMOX_HOST}/api2/json/nodes/{node}/lxc/{vmid}/config"
            conf, e2 = safe_get(url_conf)
            if conf:
                ip_ = parse_lxc_ip(conf.get("net0", ""))
                if ip_ and in_network(ip_, NETWORK_CIDR):
                    ip = ip_
        elif vm_type == "qemu":
            url_dump = f"{PROXMOX_HOST}/api2/json/nodes/{node}/qemu/{vmid}/cloudinit/dump"
            txt, e3 = safe_get_text(url_dump, {"type": "network"})
            if txt:
                ip_ = parse_cloudinit_dump(txt)
                if ip_ and in_network(ip_, NETWORK_CIDR):
                    ip = ip_

        if ip:
            fqdn = f"{name}.{DNS_DOMAIN}"
            static_lines.append(f"address=/{fqdn}/{ip}")
            static_ips[name] = ip
            known_fqdns.add(fqdn)
        else:
            dynamic_names.append(name)

    try:
        with open(DNSMASQ_CONF, "w") as f:
            f.write("\n".join(static_lines) + "\n")
        with open(DNSMASQ_STATIC, "w") as f:
            f.write("\n".join(dynamic_names) + "\n")
    except OSError as e:
        log(f"Error writing dnsmasq files: {e}", 'error')
        return {}, False

    log(f"Synchronized: {len(static_lines)} static, {len(dynamic_names)} dynamic entries.")
    return static_ips, True


def cleanup_leases():
    log("Cleaning up outdated DHCP leases...")
    try:
        with open(DNSMASQ_LEASES, "r") as f:
            leases = f.readlines()
    except OSError:
        leases = []

    static_fqdns = {}
    try:
        with open(DNSMASQ_CONF, "r") as f:
            for line in f:
                if line.startswith("address=/"):
                    parts = line.strip().split('/')
                    if len(parts) >= 3:
                        fqdn = parts[1]
                        ip = parts[2]
                        hostname = fqdn.split('.')[0]
                        static_fqdns[hostname] = ip
    except OSError:
        pass

    dynamic_hostnames = set()
    try:
        with open(DNSMASQ_STATIC, "r") as f:
            for line in f:
                hostname = line.strip()
                if hostname:
                    dynamic_hostnames.add(hostname)
    except OSError:
        pass

    known_hostnames = set(static_fqdns.keys()).union(dynamic_hostnames)
    to_remove = []
    for lease in leases:
        parts = lease.strip().split()
        if len(parts) < 4:
            continue
        _, mac, ip, client = parts[:4]
        if client not in known_hostnames:
            to_remove.append((ip, mac))
        elif client in static_fqdns and ip != static_fqdns[client]:
            to_remove.append((ip, mac))

    if to_remove:
        log(f"Found {len(to_remove)} leases to remove.")
        new_leases = leases.copy()
        for ip, mac in to_remove:
            new_leases = [lease for lease in new_leases if not (ip == lease.split()[2] and mac == lease.split()[1])]
            log(f"Released lease: {ip} ({mac})")
        try:
            with open(DNSMASQ_LEASES, "w") as f:
                f.writelines(new_leases)
        except OSError as e:
            log(f"Error writing leases: {e}", 'error')
            return
        restart_dnsmasq()


def collect_arp():
    ips = []
    try:
        result = subprocess.run(['arp-scan', '-l', '-q', '-x'], capture_output=True, text=True, check=True)
        for line in result.stdout.strip().split('\n'):
            parts = line.split()
            if len(parts) >= 2:
                ips.append(parts[0])
    except subprocess.CalledProcessError as e:
        log(f"Error running arp-scan: {e}", 'error')
    except Exception as e:
        log(f"Unexpected error in collect_arp: {e}", 'error')
    return ips


def write_pve_arp(arp_ips):
    try:
        with open(DNSMASQ_ARP, "w") as f:
            f.write("\n".join(arp_ips) + "\n")
        log(f"Written {len(arp_ips)} ARP entries to pve.arp.")
    except OSError as e:
        log(f"Error writing pve.arp: {e}", 'error')


def monitor_arp_scan(callback, interval):
    prev_arp = set()
    while True:
        current_arp = set(collect_arp())
        if current_arp != prev_arp:
            callback()
            prev_arp = current_arp
        time.sleep(interval)


def monitor_leases(callback):
    try:
        inotify = INotify()
        watch_flags = flags.MODIFY
        inotify.add_watch(DNSMASQ_LEASES, watch_flags)
    except Exception as e:
        log(f"Error setting up inotify for leases: {e}", 'error')
        return

    while True:
        try:
            events = inotify.read(timeout=1000)
            for event in events:
                if flags.MODIFY in flags.from_mask(event.mask):
                    callback()
        except Exception as e:
            log(f"Error in inotify: {e}", 'error')
            time.sleep(ARP_SCAN_INTERVAL)


def periodic_sync():
    while True:
        time.sleep(SYNC_INTERVAL)
        static_ips, success = sync_with_proxmox()
        if success:
            cleanup_leases()
            write_pve_arp(static_ips.values())
            restart_dnsmasq()


def on_network_change():
    log("Network change detected. Updating configuration...")
    static_ips, success = sync_with_proxmox()
    if success:
        cleanup_leases()
        write_pve_arp(static_ips.values())
        restart_dnsmasq()


def main():
    static_ips, success = sync_with_proxmox()
    if success:
        cleanup_leases()
        write_pve_arp(static_ips.values())
        restart_dnsmasq()

    threading.Thread(target=monitor_arp_scan, args=(on_network_change, ARP_SCAN_INTERVAL), daemon=True).start()
    threading.Thread(target=monitor_leases, args=(on_network_change,), daemon=True).start()
    threading.Thread(target=periodic_sync, daemon=True).start()

    log("pve_dns_daemon started.")
    while True:
        time.sleep(60)


if __name__ == "__main__":
    main()
