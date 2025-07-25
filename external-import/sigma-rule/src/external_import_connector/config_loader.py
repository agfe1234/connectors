import os
from pathlib import Path

import yaml
from pycti import get_config_variable


class ConfigConnector:
    def __init__(self):
        """
        Initialize the connector with necessary configurations
        """

        # Load configuration file
        self.load = self._load_config()
        self._initialize_configurations()



    @staticmethod
    def _load_config() -> dict:
        """
        Load the configuration from the YAML file
        :return: Configuration dictionary
        """
        config_file_path = Path(__file__).parents[1].joinpath("config.yml")
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )

        return config

    def _initialize_configurations(self) -> None:
        """
        Connector configuration variables
        :return: None
        """
        # OpenCTI configurations
        self.duration_period = get_config_variable(
            "CONNECTOR_DURATION_PERIOD",
            ["connector", "duration_period"],
            self.load,
        )

        # Connector extra parameters
        self.api_base_url = get_config_variable(
            "CONNECTOR_SIGMA_RULE_API_BASE_URL",
            ["connector_sigma_rule", "api_base_url"],
            self.load,
        )

        self.api_key = get_config_variable(
            "CONNECTOR_SIGMA_RULE_API_KEY",
            ["connector_sigma_rule", "api_key"],
            self.load,
        )

        self.tlp_level = get_config_variable(
            "CONNECTOR_SIGMA_RULE_TLP_LEVEL",
            ["connector_sigma_rule", "tlp_level"],
            self.load,
            default="clear",
        )

        # MITRE/CVE path constants and namespace
        from uuid import UUID
        self.MITRE_TACTIC_PATH = get_config_variable(
            "CONNECTOR_SIGMA_RULE_MITRE_TACTIC_PATH",
            ["connector_sigma_rule", "mitre_tactic_path"],
            self.load,
            default="https://attack.mitre.org/tactics/{}"
        )
        
        self.MITRE_TECHNIQUE_PATH = get_config_variable(
            "CONNECTOR_SIGMA_RULE_MITRE_TECHNIQUE_PATH",
            ["connector_sigma_rule", "mitre_technique_path"],
            self.load,
            default="https://attack.mitre.org/techniques/{}"
        )
        
        self.MITRE_SOFTWARE_PATH = get_config_variable(
            "CONNECTOR_SIGMA_RULE_MITRE_SOFTWARE_PATH",
            ["connector_sigma_rule", "mitre_software_path"],
            self.load,
            default="https://attack.mitre.org/software/{}"
        )
        
        self.MITRE_GROUP_PATH = get_config_variable(
            "CONNECTOR_SIGMA_RULE_MITRE_GROUP_PATH",
            ["connector_sigma_rule", "mitre_group_path"],
            self.load,
            default="https://attack.mitre.org/groups/{}"
        )
        
        self.CVE_PATH = get_config_variable(
            "CONNECTOR_SIGMA_RULE_CVE_PATH",
            ["connector_sigma_rule", "cve_path"],
            self.load,
            default="https://nvd.nist.gov/vuln/detail/{}"
        )
        
        namespace_str = get_config_variable(
            "CONNECTOR_SIGMA_RULE_NAMESPACE",
            ["connector_sigma_rule", "namespace"],
            self.load,
            default="860f4c0f-8c26-5889-b39d-ce94368bc416"
        )
        self.namespace = UUID(namespace_str)
