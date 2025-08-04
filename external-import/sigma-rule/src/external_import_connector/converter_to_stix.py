import ipaddress
import re
import uuid
import stix2
import validators
import yaml
from pycti import Identity, MarkingDefinition, StixCoreRelationship
from datetime import datetime, timezone

class ConverterToStix:
    def _process_tags_and_labels(self, data: dict):
        references = []
        for tag in data.get('tags', []):
            tag = tag.lower()
            if match := re.match(r'detection\.(.*)', tag):
                references.append(dict(source_name='sigma-rule', external_id=match.group(1), description='detection'))
            elif match := re.match(r'(cve\..*)', tag):
                cve_id = match.group(1).replace(".", '-').upper()
                references.append(dict(source_name='cve', external_id=cve_id, url=self.config.CVE_PATH.format(cve_id)))
            elif match := re.match(r'attack\.(t.*)', tag):
                attack_id = match.group(1).upper()
                references.append(dict(source_name="mitre-attack", external_id=attack_id, url=self.config.MITRE_TECHNIQUE_PATH.format(attack_id)))
            elif match := re.match(r'attack\.(s.*)', tag):
                attack_id = match.group(1).upper()
                references.append(dict(source_name="mitre-attack", external_id=attack_id, url=self.config.MITRE_SOFTWARE_PATH.format(attack_id)))
            elif match := re.match(r'attack\.(g.*)', tag):
                attack_id = match.group(1).upper()
                references.append(dict(source_name="mitre-attack", external_id=attack_id, url=self.config.MITRE_GROUP_PATH.format(attack_id)))
            elif match := re.match(r'attack\.(.*)', tag):
                attack_id = match.group(1).replace('_', '-')
                references.append(dict(source_name='mitre-attack', external_id=attack_id, description='tactic'))
        return references

    def _generate_all_references(self, data: dict):
        return [
            {"source_name": "sigma-rule", "external_id": "reference", "url": reference}
            for reference in data.get("references", [])
        ]

    def create_sigma_indicator(self, rule: str):
        import re
        import yaml
        from datetime import datetime, date
        def as_date(d):
            if isinstance(d, datetime) or isinstance(d, date):
                return d
            # Try both common date formats
            try:
                return datetime.strptime(d, "%Y-%m-%d")
            except Exception:
                return datetime.strptime(d, "%Y/%m/%d")

        data = yaml.safe_load(rule)
        if not data:
            return None
        stix_id = 'indicator--' + str(uuid.uuid5(self.config.namespace, f"{data.get('id')}+sigma"))
        try:
            indicator = stix2.Indicator(
                id=stix_id,
                created=as_date(data.get('date')),
                modified=as_date(data.get('modified') if data.get('modified') else data.get('date')),
                name=data.get("title"),
                description=f"{data.get('description')}",
                pattern=rule,
                pattern_type="sigma",
                valid_from=as_date(data.get('date')),
                revoked=data.get('status') == 'deprecated',
                created_by_ref=self.author["id"],
                object_marking_refs=[self.tlp_marking["id"]],
                external_references=self._process_tags_and_labels(data) + self._generate_all_references(data),
            )
            return indicator
        except Exception:
            return None
    """
    Provides methods for converting various types of input data into STIX 2.1 objects.

    REQUIREMENTS:
    - generate_id() for each entity from OpenCTI pycti library except observables to create
    """

    def __init__(self, helper, config):
        self.helper = helper
        self.config = config
        self.author = self.create_author()
        self.tlp_marking = self._create_tlp_marking(level=self.config.tlp_level.lower())

    @staticmethod
    def create_author() -> dict:
        """
        Create Author for SigmaHQ
        :return: Author in Stix2 object
        """
        author = stix2.Identity(
            id=Identity.generate_id(name="SigmaHQ", identity_class="organization"),
            name="SigmaHQ",
            identity_class="organization",
            description="SigmaHQ is the official open community project for generic signature format for SIEM systems. See https://github.com/SigmaHQ/sigma",
            external_references=[
                stix2.ExternalReference(
                    source_name="SigmaHQ",
                    url="https://github.com/SigmaHQ/sigma",
                    description="SigmaHQ: Generic Signature Format for SIEM Systems."
                )
            ],
        )
        return author

    @staticmethod
    def _create_tlp_marking(level):
        mapping = {
            "white": stix2.TLP_WHITE,
            "clear": stix2.TLP_WHITE,
            "green": stix2.TLP_GREEN,
            "amber": stix2.TLP_AMBER,
            "amber+strict": stix2.MarkingDefinition(
                id=MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"),
                definition_type="statement",
                definition={"statement": "custom"},
                custom_properties={
                    "x_opencti_definition_type": "TLP",
                    "x_opencti_definition": "TLP:AMBER+STRICT",
                },
            ),
            "red": stix2.TLP_RED,
        }
        return mapping[level]

    def create_relationship(
        self, source_id: str, relationship_type: str, target_id: str
    ) -> dict:
        """
        Creates Relationship object
        :param source_id: ID of source in string
        :param relationship_type: Relationship type in string
        :param target_id: ID of target in string
        :return: Relationship STIX2 object
        """
        relationship = stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                relationship_type, source_id, target_id
            ),
            relationship_type=relationship_type,
            source_ref=source_id,
            target_ref=target_id,
            created_by_ref=self.author,
        )
        return relationship

    # ===========================#
    # Other Examples
    # ===========================#

    @staticmethod
    def _is_ipv6(value: str) -> bool:
        """
        Determine whether the provided IP string is IPv6
        :param value: Value in string
        :return: A boolean
        """
        try:
            ipaddress.IPv6Address(value)
            return True
        except ipaddress.AddressValueError:
            return False

    @staticmethod
    def _is_ipv4(value: str) -> bool:
        """
        Determine whether the provided IP string is IPv4
        :param value: Value in string
        :return: A boolean
        """
        try:
            ipaddress.IPv4Address(value)
            return True
        except ipaddress.AddressValueError:
            return False

    @staticmethod
    def _is_domain(value: str) -> bool:
        """
        Valid domain name regex including internationalized domain name
        :param value: Value in string
        :return: A boolean
        """
        is_valid_domain = validators.domain(value)

        if is_valid_domain:
            return True
        else:
            return False

    def create_obs(self, value: str):
        """
        Create observable using built-in Sigma logic.
        :param value: Sigma rule YAML string
        :return: Indicator object or None
        """
        indicator = self.create_sigma_indicator(value)
        if indicator:
            return indicator
        else:
            self.helper.connector_logger.error(
                "This observable value is not a valid Sigma YAML:",
                {"value": value},
            )
            return None
