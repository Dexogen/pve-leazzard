<p align="center">
  <img src="./assets/logo-256.png" />
</p>


# PVE-Leazzard
![Workflow](https://github.com/dexogen/pve-leazzard/actions/workflows/docker-build.yml/badge.svg)
![amd64](https://img.shields.io/badge/architecture-amd64%2Farm64%0A-9ca)
![GitHub Tag](https://img.shields.io/github/v/tag/dexogen/pve-leazzard)

A DNS/DHCP server based on [dnsmasq](https://thekelleys.org.uk/dnsmasq/doc.html) ~~and hacks~~ with automatic generation of DNS records for dynamic and static IPs using ARP scanning and the [Proxmox API](https://pve.proxmox.com/pve-docs/api-viewer/index.html).

--------------------

## Table of contents

- [But why?](#but-why)
- [Preparation](#preparation)
   * [Ubiquiti UDM/UX](#ubiquiti-udmux)
- [Installation](#installation)
- [Variables](#variables)
- [Demo ](#demo)
- [Roadmap](#roadmap)
- [Pre-built images](#pre-built-images)
   * [GitHub Container Registry](#github-container-registry)
   * [Docker Hub](#docker-hub)
- [Links](#links)


## But why?

I managed IP addresses and DNS records manually for a long time, but during the recent New Year holidays while reconfiguring the lab network once again, I realized that this cannot continue and something needed to be done.

I did not want to use heavyweight DNS servers because additional logic would still need to be written for them, so I chose dnsmasq.

The server's task is to assign IP addresses via DHCP within a specific domain and automatically create static records when necessary. Additionally, the server must "understand" when a VM/LXC container receives a static address or switches to using DHCP.

During the selection of the approach, I had to solve several problems:
1. Initially, I planned to obtain information about static addresses from the Proxmox API in two ways: from the `cloud-init` configuration and, if it was absent, from the `qemu-guest-agent`. I had to abandon the agent because API requests in such cases took an unacceptably long time (2-3 seconds per VM).
2. I needed to devise a way to promptly receive updates from Proxmox without creating excessive load on the API. The solution was ARP monitoring. Almost perfect, except for some cases:
    - If a server was reconfigured from dynamic to static without changing the address, no changes in ARP would occur;
    - If a server disappeared from ARP, it is impossible to definitively decide to release the IP, i.e., it is unknown whether the server was removed or simply turned off.

    I also did not want to set a short lease time for addresses to avoid increasing unnecessary DHCP traffic. Thus, in addition to ARP, periodic checks are still needed.
3. The system should consist of the smallest number of components. In this case, exactly two - the DNS/DHCP server and the monitoring script. Fewer components mean fewer points of failure.


## Preparation

Your router, which also serves as a DNS server, must be able to forward DNS zones. I use the Ubiquiti ecosystem, where the entire Dream Machine series can do this. However, OpenWRT and many other routers also have this functionality. I will provide instructions for my equipment and would be happy if you supplement the instructions with your experience with other network equipment.

### Ubiquiti UDM/UX

1. Create a network: `Settings` > `Networks` > `New Virtual Network`. Most settings are optional except for a few:
   - Auto-Scale Network: `[ ]` (uncheck)
   - Host Address: `10.0.0.1` (the address of your gateway in the new network, can be any, required later during setup)
   - Netmask: `/23` (mask of your choice)
   - Advanced: `Manual`
   - DHCP Mode: `None` (otherwise there will be a DHCP conflict)
2. Create a DNS forwarding rule: `Settings` > `Routing` > `DNS` > `Create Entry`:
   - Type: `Forward Domain`
   - Domain Name: `lab` (your own top-level domain)
   - DNS Server: `10.0.0.2` (the address of your pve-leazzard server)

You can also set up security rules and restrict access to and from this network, but this is beyond the scope of the instructions and depends entirely on your needs. For dns-leazzard, essentially only access to the Proxmox API is necessary; everything else can be closed.


## Installation

1. Create a role with the necessary set of permissions:
   ```bash
   pveum role add Leazzard --privs "Datastore.Audit Mapping.Audit Pool.Audit SDN.Audit Sys.Audit VM.Audit VM.Monitor"
   ```
2. Create a user token and save it in a secure place:
   ```bash
   root@dex-pve-1:~# pveum user token add root@pam leazzard
   ┌──────────────┬──────────────────────────────────────┐
   │ key          │ value                                │
   ╞══════════════╪══════════════════════════════════════╡
   │ full-tokenid │ root@pam!leazzard                    │
   ├──────────────┼──────────────────────────────────────┤
   │ info         │ {"privsep":1}                        │
   ├──────────────┼──────────────────────────────────────┤
   │ value        │ 00000000-0000-0000-0000-000000000000 │
   └──────────────┴──────────────────────────────────────┘
   ```
3. Assign permissions to the token:
   ```bash
   pveum acl modify / -token 'root@pam!leazzard ' -role Leazzard
   ```
4. Create a VM/LXC with a **static IP address** in the required network. In our example, this is the `10.0.0.0/23` network. My DNS server will have the address `10.0.0.2`, following the gateway address `10.0.0.1`.
5. Install Docker and docker-compose in any convenient way. Just in case, here is a fragment of my installation script:
   ```bash
   # Install some dependencies and tools
   apt update && apt install curl jq git -y
   
   # Install docker
   curl -fsSL https://get.docker.com | bash
   
   # Install docker-compose
   tag="$(curl -s https://api.github.com/repos/docker/compose/releases/latest | jq -r '.tag_name')"
   curl -L "https://github.com/docker/compose/releases/download/$tag/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
   chmod +x /usr/local/bin/docker-compose
   
   # Replace overlay2 with fuse-overlayfs
   if grep -q "container=lxc" /proc/1/environ 2>/dev/null; then
     echo "LXC environment detected"
     apt install fuse-overlayfs -y
     echo '{
       "storage-driver": "fuse-overlayfs"
     }' > /etc/docker/daemon.json
     systemctl restart docker
   else
     apt install qemu-guest-agent -y
     systemctl enable qemu-guest-agent && systemctl start qemu-guest-agent
   fi
   ```
   If you decide to use my installation script in LXC - do not forget to enable in Proxmox settings: `Your LXC` > `Options` > `Features` > `FUSE: [v]`. Docker with overlay2 inside LXC eventually consumes a lot of space and never frees it.
6. Connect via SSH and create `docker-compose.yml`:
   ```yaml
      services:
        pve-leazzard:
          image: dexogen/pve-leazzard:latest
          environment:
            PROXMOX_HOST: "https://your-proxmox.host:port" # can omit the port if 443
            API_TOKEN_ID: "root@pam!leazzard"
            API_TOKEN_SECRET: "00000000-0000-0000-0000-000000000000"
            VERIFY_SSL: "true" # only if you have a valid certificate
            NETWORK_CIDR: "10.0.0.0/23" # your main prefix
            DHCP_RANGE: "10.0.1.1,10.0.1.254,255.255.254.0,12h" # DHCP issuance range
            DHCP_OPTION: "option:router,10.0.0.1" # router address
            DNS_DOMAIN: "lab" # your custom domain
            SYNC_INTERVAL: "300" # sync interval with PVE when there are no ARP events
            ARP_CHECK_INTERVAL: "15" # ARP scanning interval
            LOG_LEVEL: "ERROR" # logging level ERROR/INFO
          network_mode: "host" # without this, the ARP scanner will not work
          cap_add:
            - NET_ADMIN
          restart: always
          # optional, for debugging convenience
          volumes:
            - ./dnsmasq:/etc/dnsmasq.d
            - ./leases:/var/lib/misc
   ```
7. Ensure that nothing is using port 53; otherwise, the container will not start correctly. Now we can start the container:
   ```bash
   docker-compose up -d
   ```


## Variables

| Variable            | Required | Example                                 |
| ------------------- | -------- | --------------------------------------- |
| `PROXMOX_HOST`      | `true`   | `https://your-proxmox.host:port`        |
| `API_TOKEN_ID`      | `true`   | `root@pam!leazzard`                     |
| `API_TOKEN_SECRET`  | `true`   | `00000000-0000-0000-0000-000000000000`  |
| `DNS_DOMAIN`        | `true`   | `lab`                                   |
| `NETWORK_CIDR`      | `true`   | `10.0.0/23`                             |
| `DHCP_RANGE`        | `true`   | `10.0.1.1,10.0.1.254,255.255.254.0,12h` |
| `DHCP_OPTION`       | `true`   | `option:router,10.0.0.1`                |
| `VERIFY_SSL`        |          | `true` (default) / `false`              |
| `SYNC_INTERVAL`     |          | `300` (default)                         |
| `ARP_SCAN_INTERVAL` |          | `30` (default)                          |
| `LOG_LEVEL`         |          | `ERROR` (default) / `INFO`              |


## Demo 
<p align="center">
   <a href="https://www.youtube.com/watch?v=CGoHqqH4Ak8" target="_blank">
    <img src="http://img.youtube.com/vi/CGoHqqH4Ak8/maxresdefault.jpg" alt="Watch the video" width="720" height="420" border="10" />
   </a>
</p>


## Roadmap

1. There is a logic flaw somewhere in the code that causes dnsmasq to perform multiple restarts on the first launch. Additionally, dnsmasq restarts within the `SYNC_INTERVAL` even when there are no visible changes. I need to figure out why.
2. Integrate a simple Prometheus exporter to provide a list of static and dynamic domains.


## Pre-built images

### [GitHub Container Registry](https://github.com/dexogen/pve-leazzard/pkgs/container/pve-leazzard)

Works on GitHub Actions.

```bash
docker pull ghcr.io/dexogen/pve-leazzard:latest
```


### [Docker Hub](https://hub.docker.com/r/dexogen/pve-leazzard)

Works on my home GitLab.

```bash
docker pull dexogen/pve-leazzard:latest
```


## Links

- https://pve.proxmox.com/pve-docs/api-viewer/index.html
- https://thekelleys.org.uk/dnsmasq/doc.html