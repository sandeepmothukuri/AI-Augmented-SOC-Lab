#!/usr/bin/env python3
"""
Wazuh Agent Auto-Registration Script
=====================================
Automatically registers new endpoints with the Wazuh Manager via the REST API.
Supports Linux, Windows, and macOS agents.

Usage:
    python register-agent.py --hostname webserver01 --ip 192.168.1.50 --os linux
    python register-agent.py --hostname windc01 --ip 192.168.1.10 --os windows --group servers
    python register-agent.py --list-agents
    python register-agent.py --delete-agent <agent_id>

Environment Variables:
    WAZUH_API_HOST   - Wazuh Manager API host (default: https://localhost:55000)
    WAZUH_API_USER   - API username (default: wazuh)
    WAZUH_API_PASS   - API password
"""

import argparse
import base64
import json
import logging
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

WAZUH_API_HOST = os.getenv("WAZUH_API_HOST", "https://localhost:55000")
WAZUH_API_USER = os.getenv("WAZUH_API_USER", "wazuh")
WAZUH_API_PASS = os.getenv("WAZUH_API_PASS", "wazuh")

# SSL context — disable cert verification for self-signed lab certs
SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE


def _get_token() -> str:
    """Authenticate with Wazuh REST API and return JWT token."""
    credentials = base64.b64encode(f"{WAZUH_API_USER}:{WAZUH_API_PASS}".encode()).decode()
    req = urllib.request.Request(
        f"{WAZUH_API_HOST}/security/user/authenticate",
        headers={"Authorization": f"Basic {credentials}"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, context=SSL_CTX, timeout=10) as resp:
            data = json.loads(resp.read())
            token = data["data"]["token"]
            logger.info("Authenticated with Wazuh Manager at %s", WAZUH_API_HOST)
            return token
    except urllib.error.HTTPError as exc:
        logger.error("Authentication failed: HTTP %s — %s", exc.code, exc.read().decode())
        sys.exit(1)
    except Exception as exc:
        logger.error("Cannot reach Wazuh API at %s: %s", WAZUH_API_HOST, exc)
        sys.exit(1)


def _api_request(method: str, path: str, token: str, payload: dict | None = None) -> dict:
    """Generic Wazuh API request."""
    url = f"{WAZUH_API_HOST}{path}"
    body = json.dumps(payload).encode() if payload else None
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        method=method,
    )
    try:
        with urllib.request.urlopen(req, context=SSL_CTX, timeout=15) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        error_body = exc.read().decode()
        logger.error("API error %s on %s %s: %s", exc.code, method, path, error_body)
        sys.exit(1)


def register_agent(token: str, hostname: str, ip: str, os_type: str, group: str) -> None:
    """Register a new agent with the Wazuh Manager."""
    payload = {
        "name": hostname,
        "ip": ip,
    }
    response = _api_request("POST", "/agents", token, payload)
    agent_id = response["data"]["id"]
    agent_key = response["data"]["key"]

    logger.info("[OK] Agent registered successfully")
    logger.info("   Agent ID  : %s", agent_id)
    logger.info("   Agent Name: %s", hostname)
    logger.info("   Agent IP  : %s", ip)

    # Assign to group if specified
    if group:
        _api_request(
            "PUT",
            f"/agents/{agent_id}/group/{group}",
            token,
        )
        logger.info("   Group     : %s", group)

    # Print agent key for ossec-authd or manual installation
    print("\n" + "=" * 60)
    print("AGENT REGISTRATION KEY (copy to endpoint)")
    print("=" * 60)
    print(agent_key)
    print("=" * 60)

    # Print installation instructions
    _print_install_instructions(hostname, ip, os_type, agent_key)


def _print_install_instructions(hostname: str, ip: str, os_type: str, key: str) -> None:
    """Print agent installation instructions for the target OS."""
    manager_ip = WAZUH_API_HOST.replace("https://", "").replace("http://", "").split(":")[0]

    print(f"\n{'=' * 60}")
    print(f"INSTALLATION INSTRUCTIONS FOR: {hostname} ({os_type.upper()})")
    print("=" * 60)

    if os_type == "linux":
        print(
            f"""
1. Install Wazuh agent on {hostname}:
   curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor > /usr/share/keyrings/wazuh.gpg
   echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list
   apt-get update && apt-get install -y wazuh-agent

2. Import the registration key:
   /var/ossec/bin/manage_agents -i '{key}'

3. Configure the manager address:
   sed -i 's/MANAGER_IP/{manager_ip}/' /var/ossec/etc/ossec.conf

4. Start the agent:
   systemctl enable wazuh-agent && systemctl start wazuh-agent
"""
        )
    elif os_type == "windows":
        print(
            f"""
1. Download Wazuh agent MSI from:
   https://packages.wazuh.com/4.x/windows/wazuh-agent-4.x.x.msi

2. Install with manager and key:
   .\\wazuh-agent-4.x.x.msi /q WAZUH_MANAGER="{manager_ip}" WAZUH_REGISTRATION_KEY="{key}"

3. Start the service:
   NET START WazuhSvc

   OR via PowerShell:
   Start-Service -Name WazuhSvc
"""
        )
    elif os_type == "macos":
        print(
            f"""
1. Install Wazuh agent via pkg:
   curl -O https://packages.wazuh.com/4.x/macos/wazuh-agent-4.x.x.pkg
   sudo installer -pkg wazuh-agent-4.x.x.pkg -target /

2. Import key and set manager:
   /Library/Ossec/bin/manage_agents -i '{key}'
   sudo sed -i '' 's/MANAGER_IP/{manager_ip}/' /Library/Ossec/etc/ossec.conf

3. Start the agent:
   sudo /Library/Ossec/bin/wazuh-control start
"""
        )


def list_agents(token: str) -> None:
    """List all registered agents."""
    response = _api_request("GET", "/agents?limit=100&offset=0", token)
    agents = response.get("data", {}).get("affected_items", [])

    if not agents:
        logger.info("No agents registered.")
        return

    print(f"\n{'ID':<10}{'Name':<25}{'IP':<18}{'Status':<12}{'OS':<20}{'Version'}")
    print("-" * 95)
    for agent in agents:
        agent_id = agent.get("id", "N/A")
        name = agent.get("name", "N/A")
        ip = agent.get("ip", "N/A")
        status = agent.get("status", "N/A")
        os_info = agent.get("os", {}).get("name", "N/A") if agent.get("os") else "N/A"
        version = agent.get("version", "N/A")
        print(f"{agent_id:<10}{name:<25}{ip:<18}{status:<12}{os_info:<20}{version}")

    print(f"\nTotal: {len(agents)} agent(s)")


def delete_agent(token: str, agent_id: str) -> None:
    """Remove an agent from the Wazuh Manager."""
    _api_request(
        "DELETE",
        f"/agents?agents_list={agent_id}&status=all&older_than=0s",
        token,
    )
    logger.info("[OK] Agent %s deleted successfully", agent_id)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Wazuh Agent Auto-Registration Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command")

    # register subcommand
    reg_parser = subparsers.add_parser("register", help="Register a new agent")
    reg_parser.add_argument("--hostname", required=True, help="Agent hostname")
    reg_parser.add_argument("--ip", required=True, help="Agent IP address")
    reg_parser.add_argument(
        "--os",
        choices=["linux", "windows", "macos"],
        default="linux",
        dest="os_type",
        help="Target OS type (default: linux)",
    )
    reg_parser.add_argument("--group", default="", help="Agent group to assign (default: default)")

    # list subcommand
    subparsers.add_parser("list", help="List all registered agents")

    # delete subcommand
    del_parser = subparsers.add_parser("delete", help="Delete an agent by ID")
    del_parser.add_argument("agent_id", help="Agent ID to delete")

    # Legacy flat args (backward compat)
    parser.add_argument("--hostname", help=argparse.SUPPRESS)
    parser.add_argument("--ip", help=argparse.SUPPRESS)
    parser.add_argument("--os", dest="os_type", default="linux", help=argparse.SUPPRESS)
    parser.add_argument("--group", default="", help=argparse.SUPPRESS)
    parser.add_argument("--list-agents", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--delete-agent", dest="delete_agent_id", help=argparse.SUPPRESS)

    args = parser.parse_args()
    token = _get_token()

    # Subcommand routing
    if args.command == "register":
        register_agent(token, args.hostname, args.ip, args.os_type, args.group)
    elif args.command == "list":
        list_agents(token)
    elif args.command == "delete":
        delete_agent(token, args.agent_id)
    # Legacy flat-arg routing
    elif getattr(args, "list_agents", False):
        list_agents(token)
    elif getattr(args, "delete_agent_id", None):
        delete_agent(token, args.delete_agent_id)
    elif getattr(args, "hostname", None):
        register_agent(token, args.hostname, args.ip, args.os_type, args.group)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
