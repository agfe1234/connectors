import os
import time
import IP2Location
import yaml
from typing import Dict
import pycountry
import stix2

from pycti import (
    Location,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
    get_config_variable,
)


class IP2LocationConnector:
    def __init__(self):
        # 설정 로딩
        config_file_path = f"{os.path.dirname(os.path.abspath(__file__))}/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config, playbook_compatible=True)

        # DB 파일 경로 로딩
        self.db_path = get_config_variable("IP2LOCATION_DB", ["ip2location", "db_path"], config)
        self.max_tlp = get_config_variable("IP2LOCATION_MAX_TLP", ["ip2location", "max_tlp"], config)
        self.db = IP2Location.IP2Location(self.db_path)

    def _generate_stix_bundle(self, stix_objects, stix_entity, country):
        country_location = stix2.Location(
            id=Location.generate_id(country.name, "Country"),
            name=country.name,
            country=(
                country.official_name
                if hasattr(country, "official_name")
                else country.name
            ),
            confidence=self.helper.connect_confidence_level,
            custom_properties={
                "x_opencti_location_type": "Country",
                "x_opencti_aliases": [
                    (
                        country.official_name
                        if hasattr(country, "official_name")
                        else country.name
                    )
                ],
            },            
        )
        stix_objects.append(country_location)

        observable_to_country = stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                "located-at", stix_entity["id"], country_location.id
            ),
            relationship_type="located-at",
            source_ref=stix_entity["id"],
            target_ref=country_location.id,
            confidence=self.helper.connect_confidence_level,
        )
        stix_objects.append(observable_to_country)
        return self.helper.stix2_create_bundle(stix_objects)

    def _process_message(self, data: Dict):
        opencti_entity = data["enrichment_entity"]

        # TLP 검사
        tlp = "TLP:CLEAR"
        for marking_definition in opencti_entity["objectMarking"]:
            if marking_definition["definition_type"] == "TLP":
                tlp = marking_definition["definition"]

        if not OpenCTIConnectorHelper.check_max_tlp(tlp, self.max_tlp):
            raise ValueError("TLP is higher than allowed maximum")

        stix_entity = data["stix_entity"]
        stix_objects = data["stix_objects"]
        ip = stix_entity["value"]

        # IP2Location에서 국가 정보 조회
        try:
            res = self.db.get_all(ip)
            if not res.country_short or res.country_short == "-" or res.country_short == "ZZ":
                raise ValueError(f"Invalid country for IP {ip}")
            country = pycountry.countries.get(alpha_2=res.country_short)
            if country is None:
                raise ValueError(f"No matching country found for code {res.country_short}")
        except Exception as e:
            raise ValueError(f"Error during IP2Location lookup: {str(e)}")

        bundle = self._generate_stix_bundle(stix_objects, stix_entity, country)
        bundles_sent = self.helper.send_stix2_bundle(bundle)
        return f"Sent {len(bundles_sent)} stix bundle(s) for IP2Location enrichment"

    def start(self):
        self.helper.listen(message_callback=self._process_message)


if __name__ == "__main__":
    connector = IP2LocationConnector()
    connector.start()

