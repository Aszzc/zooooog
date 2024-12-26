import logging
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import base64
import json
import configparser
from abc import ABC, abstractmethod

# Configure logging
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s: %(message)s')

# Utility Functions
def construct_url(endpoint, path, params=None):
    """Constructs the API URL with optional query parameters."""
    url = f"https://{endpoint}/RESTF-1.0.3/rest/{path}"
    if params:
        url += f"?{params}"
    logging.debug(f"Constructed URL: {url}")
    return url

# Abstract Protocol Parser
class ProtocolParser(ABC):
    @abstractmethod
    def parse(self, config_data):
        """Parses the configuration data and returns a formatted string."""
        pass

class WireguardParser(ProtocolParser):
    def parse(self, config_data):
        config = configparser.ConfigParser()
        config.read_string(config_data)
        try:
            private_key = config.get('Interface', 'PrivateKey', fallback=None)
            public_key = config.get('Peer', 'PublicKey', fallback=None)
            endpoint = config.get('Peer', 'Endpoint', fallback=None)
            if private_key and endpoint:
                return (f'wg://{endpoint}?publicKey={public_key}'
                        f'&privateKey={private_key}&ip=10.20.5.34&dns=8.8.8.8&udp=1')
        except Exception as e:
            logging.error(f"Error parsing WireGuard config: {e}")
        return None

class ShadowsocksParser(ProtocolParser):
    def parse(self, config_data):
        try:
            config_json = json.loads(config_data)
            user_info = f"{config_json.get('method', '')}:{config_json.get('password', '')}"
            encoded_user_info = base64.urlsafe_b64encode(user_info.encode()).decode()
            return f"ss://{encoded_user_info}@{config_json.get('server', '')}:{config_json.get('server_port', 0)}"
        except Exception as e:
            logging.error(f"Error parsing Shadowsocks config: {e}")
        return None

class VmessParser(ProtocolParser):
    def parse(self, config_data):
        try:
            outbound = json.loads(config_data).get("outbounds", [{}])[0]
            vnext = outbound.get("settings", {}).get("vnext", [{}])[0]
            address = vnext.get("address", "")
            port = vnext.get("port", 0)
            user = vnext.get("users", [{}])[0]
            vmess_config = {
                "v": "2",
                "ps": "",
                "add": address,
                "port": port,
                "id": user.get("id", ""),
                "aid": user.get("alterId", 0),
                "net": outbound.get("streamSettings", {}).get("network", "tcp"),
                "type": "none",
                "tls": outbound.get("streamSettings", {}).get("security", "none"),
            }
            vmess_base64 = base64.urlsafe_b64encode(json.dumps(vmess_config).encode()).decode()
            return f"vmess://{vmess_base64}"
        except Exception as e:
            logging.error(f"Error parsing VMess config: {e}")
        return None

class VlessParser(ProtocolParser):
    def parse(self, config_data):
        try:
            data = json.loads(config_data)
            outbound = data.get('outbounds', [{}])[0]
            vnext = outbound.get('settings', {}).get('vnext', [{}])[0]
            user = vnext.get('users', [{}])[0]
            stream_settings = outbound.get('streamSettings', {})
            server_name = stream_settings.get('tlsSettings', {}).get('serverName', '')

            return (f"vless://{user.get('id', '')}@{vnext.get('address', '')}:{vnext.get('port', '')}"
                    f"?security={stream_settings.get('security', 'none')}&type={stream_settings.get('network', '')}"
                    f"&sni={server_name}&path={stream_settings.get('wsSettings', {}).get('path', '')}")
        except Exception as e:
            logging.error(f"Error parsing VLESS config: {e}")
        return None

class ParserRegistry:
    def __init__(self):
        self.parsers = {}

    def register_parser(self, protocol, parser):
        """Registers a parser for a specific protocol."""
        self.parsers[protocol] = parser

    def parse(self, protocol, config_data):
        parser = self.parsers.get(protocol)
        if parser:
            return parser.parse(config_data)
        logging.warning(f"No parser found for protocol: {protocol}")
        return None

class StorageHandler(ABC):
    @abstractmethod
    def save(self, data, flag):
        pass

class FileStorageHandler(StorageHandler):
    def __init__(self, file_path):
        self.file_path = file_path
        self.unique_configs = set()

    def save(self, data, flag):
        if data not in self.unique_configs:
            self.unique_configs.add(data)
            with open(self.file_path, 'a') as file:
                file.write(f"{data}#{flag}\n")

class ConfigDownloader:
    def __init__(self, username, password, endpoint, storage_handler, parser_registry):
        self.username = username
        self.password = password
        self.endpoint = endpoint
        self.storage_handler = storage_handler
        self.parser_registry = parser_registry
        self.headers = {
            'User-Agent': 'ZoogVPN 6.8.2.5/Windows 10 Home build 22631',
            'Host': endpoint,
        }

    def get_servers(self):
        """Fetches the list of servers from the API."""
        try:
            url = construct_url(self.endpoint, 'api/servers_v2', f"email={self.username}&password={self.password}")
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            return response.json().get('servers', [])
        except requests.RequestException as e:
            logging.error(f"Error fetching servers: {e}")
            return []

    def fetch_and_save_config(self, config_name, flag):
        # if not any(a in config_name for a in ['wireguard','ssr','vr','vms','xr']):
        if not any(a in config_name for a in ['ssr','vr']):
            return
            
        if not any(a in config_name for a in ['us','hk','sg','uk']):
            return
        """Fetches and parses a configuration, then saves it using the storage handler."""
        try:
            url = construct_url(self.endpoint, 'api/server_config', f"config_name={config_name}&email={self.username}&password={self.password}")
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            data = response.text
            logging.info(data)
            if 'password' in data:
                protocol = 'shadowsocks'
            elif 'vless' in data:
                protocol = 'vless'
            elif 'vmess' in data:
                protocol = 'vmess'
            elif 'Peer' in data:
                protocol = 'wireguard'
            else:
                protocol = 'vless'
            parsed_data = self.parser_registry.parse(protocol, data)
            if parsed_data:
                self.storage_handler.save(parsed_data, flag)
            return
        except requests.RequestException as e:
            logging.error(f"Error fetching config {config_name}: {e}")

    def download_configs_multithreaded(self):
        servers = self.get_servers()
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [
                executor.submit(self.fetch_and_save_config, protocol_info.get('configName', ""), server.get('name', ""))
                for server in servers
                for protocol_info in server.get('protocols', [])
            ]
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    logging.error(f"Error in thread execution: {e}")

if __name__ == "__main__":
    storage_handler = FileStorageHandler('v2ray.txt')
    parser_registry = ParserRegistry()
    parser_registry.register_parser('shadowsocks', ShadowsocksParser())
    parser_registry.register_parser('vmess', VmessParser())
    parser_registry.register_parser('vless', VlessParser())
    parser_registry.register_parser('wireguard', WireguardParser())

    downloader = ConfigDownloader(
        username='kbxrddos@anonaddy.me',
        password='CB81A7ADD39999451A4303DCCF9881FC',
        endpoint='suibian.yeahfast.com',
        storage_handler=storage_handler,
        parser_registry=parser_registry
    )
    downloader.download_configs_multithreaded()
