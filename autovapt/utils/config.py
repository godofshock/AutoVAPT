"""
AutoVAPT Configuration Manager
Loads and validates config.yaml, provides defaults for all settings.
"""

import os
import yaml


DEFAULTS = {
    "nmap": {
        "timing": "T3",
        "top_ports": 1000,
        "version_detection": True,
        "script_scan": True,
        "os_detection": True,
    },
    "nikto": {
        "timeout": 300,
        "tuning": "1234567890",
    },
    "nvd_api": {
        "base_url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
        "api_key": "",          # Set NVD_API_KEY env var for higher rate limits
        "results_per_page": 10,
        "timeout": 15,
    },
    "metasploit": {
        "host": "127.0.0.1",
        "port": 55553,
        "username": "msf",
        "password": "msf",
        "ssl": False,
        "timeout": 60,
    },
    "risk": {
        "critical_threshold": 9.0,
        "high_threshold": 7.0,
        "medium_threshold": 4.0,
        "asset_criticality": "medium",   # low / medium / high
    },
    "report": {
        "company_name": "AutoVAPT Security Assessment",
        "assessor_name": "Aagnik",
        "logo_path": "",
    },
    "scan": {
        "intensity": "medium",
        "max_threads": 10,
        "timeout": 600,
    },
}


class Config:
    """Loads config.yaml and merges with defaults."""

    def __init__(self, config_path: str = "config.yaml"):
        self._data = self._deep_copy(DEFAULTS)

        if os.path.exists(config_path):
            with open(config_path, "r") as f:
                user_cfg = yaml.safe_load(f) or {}
            self._merge(self._data, user_cfg)

        # Allow env-var override for the NVD API key
        env_key = os.environ.get("NVD_API_KEY", "")
        if env_key:
            self._data["nvd_api"]["api_key"] = env_key

    def get(self, *keys, default=None):
        """config.get('nmap', 'timing') → 'T3'"""
        node = self._data
        for k in keys:
            if not isinstance(node, dict) or k not in node:
                return default
            node = node[k]
        return node

    def _merge(self, base: dict, override: dict):
        for k, v in override.items():
            if k in base and isinstance(base[k], dict) and isinstance(v, dict):
                self._merge(base[k], v)
            else:
                base[k] = v

    @staticmethod
    def _deep_copy(d):
        import copy
        return copy.deepcopy(d)
