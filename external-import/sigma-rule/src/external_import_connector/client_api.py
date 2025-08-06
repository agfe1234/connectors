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
            response = self.session.get(api_url, params=params, timeout=5)

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

    def extract_zip(self, zip_path, extract_to, strip_prefix=None):
        """
        zip_path: 압축 파일 경로
        extract_to: 압축 해제할 디렉토리
        strip_prefix: (선택) zip 내부 경로에서 이 prefix가 있으면 제거하고 해제
        """
        import shutil
        if os.path.exists(extract_to):
            shutil.rmtree(extract_to)
        os.makedirs(extract_to)

        def _strip_prefix(path, prefix):
            if prefix and path.startswith(prefix):
                return path[len(prefix):]
            return path

        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            for file_info in zip_ref.infolist():
                member_path = file_info.filename
                # prefix가 지정된 경우 제거
                target_rel_path = _strip_prefix(member_path, strip_prefix)
                if not target_rel_path or target_rel_path.endswith('/'):
                    continue  # 빈 경로나 디렉토리 엔트리는 건너뜀
                target_path = os.path.join(extract_to, target_rel_path)
                os.makedirs(os.path.dirname(target_path), exist_ok=True)
                with zip_ref.open(member_path) as source, open(target_path, 'wb') as target:
                    target.write(source.read())

    def generate_custom_sigma_zip(self, full_path, output_zip_path, rule_types):
        # 출력 디렉토리 생성
        output_dir = os.path.dirname(output_zip_path)
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        # rules/all 경로 설정
        rules_all_path = os.path.abspath(os.path.join("rules", "all"))
        
        sigma_package_release.RULES_DICT = {
            key: rules_all_path for key in sigma_package_release.RULES_DICT
        }

        class Args:
            pass

        args = Args()
        args.outfile = os.path.abspath(output_zip_path)  # 절대 경로로 변환
        args.statuses = sigma_package_release.STATUS[sigma_package_release.STATUS.index("stable") :]
        args.levels = ["high", "critical"]
        args.rule_types = rule_types
        
        selected_rules = sigma_package_release.select_rules(args)
        print(f"선택된 룰 개수: {len(selected_rules)}")
        
        sigma_package_release.write_zip(args.outfile, selected_rules)
        print(f"ZIP 파일 생성 완료: {args.outfile}")
        
        return args.outfile  # 생성된 파일 경로 반환 
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
            self.extract_zip(local_zip, extract_to=rules_all_path, strip_prefix=None)

            # [3] 필터링된 룰 ZIP 생성 (rules/custom/Sigma-custom.zip)
            custom_dir = os.path.join("rules", "custom")
            if not os.path.exists(custom_dir):
                os.makedirs(custom_dir)
            
            custom_zip_path = os.path.abspath(os.path.join(custom_dir, "Sigma-custom.zip"))
            print(f"[DEBUG] Absolute custom_zip_path: {custom_zip_path}")
            
            self.generate_custom_sigma_zip(
                full_path=rules_all_path,
                output_zip_path=custom_zip_path,
                rule_types=["generic", "emerging-threats", "threat-hunting"],
            )

            # ZIP 파일 존재 확인
            if not os.path.exists(custom_zip_path):
                raise FileNotFoundError(f"Custom ZIP file was not created: {custom_zip_path}")

            # [4] rules/custom/extracted/ 에 압축 해제 (ZIP 파일과 분리)
            extract_to_path = os.path.abspath(os.path.join("rules", "custom", "extracted"))
            print(f"Custom ZIP 파일 압축 해제 중: {custom_zip_path} -> {extract_to_path}")
            self.extract_zip(custom_zip_path, extract_to=extract_to_path, strip_prefix="all/")
            print("Custom ZIP 파일 압축 해제 완료") 
            # return response.json()
            # ===========================
            # === Add your code above ===
            # ===========================

            # JSON 객체 그대로 반환
            extracted_dir = os.path.abspath(os.path.join("rules", "custom", "extracted"))
            yml_values = []
            for root, _, files in os.walk(extracted_dir):
                for fname in files:
                    if fname.endswith('.yml'):
                        fpath = os.path.join(root, fname)
                        try:
                            with open(fpath, "r", encoding="utf-8") as fp:
                                data = fp.read()
                                yml_values.append({"value": data})
                        except Exception as e:
                            self.helper.connector_logger.error(f"[YML READ ERROR] {fpath}: {e}")
            return yml_values
#            return [{"value": "sample_rule where banana.name = 'test.exe' and coffee.command_line contains 'Run-Magic123'"}]



#            raise NotImplementedError

        except Exception as err:
            self.helper.connector_logger.error(err)
