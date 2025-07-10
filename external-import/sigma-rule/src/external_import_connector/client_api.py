import requests
import os
import zipfile
from sigma_tools import sigma_package_release


class ConnectorClient:
    def __init__(self, helper, config):
        """
        Initialize the client with necessary configurations
        """
        self.helper = helper
        self.config = config

        # Define headers in session and update when needed
        headers = {"Bearer": self.config.api_key}
        self.session = requests.Session()
        self.session.headers.update(headers)

    def _request_data(self, api_url: str, params=None):
        """
        Internal method to handle API requests
        :return: Response in JSON format
        """
        try:
            response = self.session.get(api_url, params=params)

            self.helper.connector_logger.info(
                "[API] HTTP Get Request to endpoint", {"url_path": api_url}
            )

            response.raise_for_status()
            return response

        except requests.RequestException as err:
            error_msg = "[API] Error while fetching data: "
            self.helper.connector_logger.error(
                error_msg, {"url_path": {api_url}, "error": {str(err)}}
            )
            return None

    def extract_zip(self, zip_path, extract_to):
        if os.path.exists(extract_to):
            # 안전하게 지움
            for root, dirs, files in os.walk(extract_to, topdown=False):
                for name in files:
                    os.remove(os.path.join(root, name))
                for name in dirs:
                    os.rmdir(os.path.join(root, name))
        else:
            os.makedirs(extract_to)

        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            zip_ref.extractall(extract_to)

    def generate_custom_sigma_zip(self, full_path, output_zip_path, rule_types):
        # 출력 디렉토리 생성
        output_dir = os.path.dirname(output_zip_path)
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        sigma_package_release.RULES_DICT = {
            key: os.path.abspath(os.path.join("rules", "all")) for key in sigma_package_release.RULES_DICT
        }

        class Args:
            pass

        args = Args()
        args.outfile = output_zip_path
        print("output경로")
        print(output_zip_path)
        args.statuses = sigma_package_release.STATUS[sigma_package_release.STATUS.index("test") :]
        args.levels = ["high", "critical"]
        args.rule_types = rule_types
        print("룰 선택 전")
        selected_rules = sigma_package_release.select_rules(args)
        print(f"선택된 룰 개수: {len(selected_rules)}")
        print("룰 선택 후")
        sigma_package_release.write_zip(args.outfile, selected_rules)
        print("zip파일 생성 후") 
    def get_entities(self, params=None) -> dict:
        """
        If params is None, retrieve all CVEs in National Vulnerability Database
        :param params: Optional Params to filter what list to return
        :return: A list of dicts of the complete collection of CVE from NVD
        """
        try:
            # ===========================
            # === Add your code below ===
            # ===========================

            # [1] 시그마 ZIP 다운로드
            response = self._request_data(self.config.api_base_url, params=params)
            local_zip = "sigma_all_rules.zip"

            with open(local_zip, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)

            # [2] rules/all/ 에 압축 해제
            rules_all_path = os.path.join("rules", "all")
            self.extract_zip(local_zip, extract_to=rules_all_path)

            # [3] 필터링된 룰 ZIP 생성 (rules/custom/Sigma-custom.zip)
            custom_zip_path = os.path.join("rules", "custom", "Sigma-custom.zip")
            self.generate_custom_sigma_zip(
                full_path=rules_all_path,
                output_zip_path=custom_zip_path,
                rule_types=["generic", "emerging-threats", "threat-hunting"],
            )

            # [4] rules/custom/ 에 압축 해제
            self.extract_zip(custom_zip_path, extract_to=os.path.join("rules", "custom"))
            print("zip파일 압축 푼 후 ") 
            # return response.json()
            # ===========================
            # === Add your code above ===
            # ===========================

            sample_path = "/home/watchtek/openCTI/connectors/connectors/external-import/sigma-rule/src/sample_sigma.yml"

            with open(sample_path, "r", encoding="utf-8") as fp:
                data = fp.read()

            # JSON 객체 그대로 반환
            return [{"value": data}]

#            return [{"value": "sample_rule where banana.name = 'test.exe' and coffee.command_line contains 'Run-Magic123'"}]



#            raise NotImplementedError

        except Exception as err:
            self.helper.connector_logger.error(err)
