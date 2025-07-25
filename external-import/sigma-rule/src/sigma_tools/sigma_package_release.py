#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Creates the Sigma release archive packages for different configurations

EXAMPLE
# python3 sigma-package-release.py --min-status test --levels high critical --rule-types generic --outfile Sigma-standard.zip
"""

import os
import sys
import argparse
import yaml
import zipfile
import datetime
import subprocess

STATUS = ["experimental", "test", "stable"]
LEVEL = ["informational", "low", "medium", "high", "critical"]
RULES_DICT = {
    "generic": "rules",
    "rules": "rules",
    "core": "rules",
    "emerging-threats": "rules-emerging-threats",
    "rules-emerging-threats": "rules-emerging-threats",
    "et": "rules-emerging-threats",
    "threat-hunting": "rules-threat-hunting",
    "th": "rules-threat-hunting",
    "rules-threat-hunting": "rules-threat-hunting",
}
RULES = [x for x in RULES_DICT.keys()]


def init_arguments(arguments: list) -> list:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "-o",
        "--outfile",
        help="Outputs the Sigma release package as ZIP archive",
        default="Sigma-standard.zip",
        required=True,
    )
    arg_status = parser.add_mutually_exclusive_group(required=True)
    arg_status.add_argument(
        "-s", "--statuses", nargs="*", choices=STATUS, help="Select status of rules"
    )
    arg_status.add_argument(
        "-ms",
        "--min-status",
        nargs="?",
        choices=STATUS,
        help="Sets the minimum status of rules to select",
    )
    arg_level = parser.add_mutually_exclusive_group(required=True)
    arg_level.add_argument(
        "-l", "--levels", nargs="*", choices=LEVEL, help="Select level of rules"
    )
    arg_level.add_argument(
        "-ml",
        "--min-level",
        nargs="?",
        choices=LEVEL,
        help="Sets the minimum level of rules to select",
    )
    parser.add_argument(
        "-r", "--rule-types", choices=RULES, nargs="*", help="Select type of rules"
    )
    args = parser.parse_args(arguments)

    if not args.outfile.endswith(".zip"):
        args.outfile = args.outfile + ".zip"

    if os.path.exists(args.outfile):
        print(
            "[E] '{}' already exists. Choose a different output file name.".format(
                args.outfile
            )
        )
        sys.exit(1)

    if args.rule_types == None:
        args.rule_types = ["generic"]
        print('[I] -r/--rule-types not defined: Using "generic" by default')

    if args.min_level != None:
        i = LEVEL.index(args.min_level)
        args.levels = LEVEL[i:]

    if args.min_status != None:
        i = STATUS.index(args.min_status)
        args.statuses = STATUS[i:]

    return args


def select_rules(args: dict) -> list:
    selected_rules = []

    def yield_next_rule_file_path(rule_path: str) -> str:
        for root, _, files in os.walk(rule_path):
            for file in files:
                if file.endswith(".yml"):
                    yield os.path.join(root, file)

    def get_rule_yaml(file_path: str) -> dict:
        data = []
        try:
            with open(file_path, encoding="utf-8") as f:
                yaml_parts = yaml.safe_load_all(f)
                for part in yaml_parts:
                    if part is not None:  # None 체크 추가
                        data.append(part)
        except Exception as e:
            print(f"[Warning] Error reading {file_path}: {e}")
        return data

    for rules_path_alias in args.rule_types:
        rules_path = RULES_DICT[rules_path_alias]
        
        for file in yield_next_rule_file_path(rule_path=rules_path):
            rule_yaml = get_rule_yaml(file_path=file)
            if len(rule_yaml) != 1:
                print(
                    "[E] rule {} is a multi-document file and will be skipped".format(
                        file
                    )
                )
                continue

            rule = rule_yaml[0]
            if rule is None:
                continue
                
            # 필드 존재 여부 체크
            if 'level' not in rule or 'status' not in rule:
                continue
                
            if rule["level"] in args.levels and rule["status"] in args.statuses:
                selected_rules.append(file)

    # 중복 제거
    return list(set(selected_rules))


def write_zip(outfile: str, selected_rules: list):
    # 기존 ZIP 파일이 있으면 삭제
    if os.path.exists(outfile):
        os.remove(outfile)
    
    # 출력 디렉토리 확인
    output_dir = os.path.dirname(outfile)
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # 중복 파일 이름 방지를 위한 집합
    added_files = set()
    
    try:
        with zipfile.ZipFile(
            outfile, mode="w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
        ) as zip:
            
            for rule_path in selected_rules:
                # 파일 존재 여부 확인
                if not os.path.exists(rule_path):
                    continue
                
                # 절대 경로를 상대 경로로 변환
                if rule_path.startswith('/'):
                    # 절대 경로에서 rules/ 이후 부분만 사용
                    if '/rules/' in rule_path:
                        arcname = rule_path.split('/rules/', 1)[1]
                    else:
                        arcname = os.path.basename(rule_path)
                else:
                    arcname = rule_path
                
                # 중복 파일 이름 체크
                if arcname in added_files:
                    # 중복인 경우 파일명을 수정
                    base, ext = os.path.splitext(arcname)
                    counter = 1
                    while f"{base}_{counter}{ext}" in added_files:
                        counter += 1
                    arcname = f"{base}_{counter}{ext}"
                
                added_files.add(arcname)
                zip.write(rule_path, arcname=arcname)

            # Write version info text file
            today = datetime.date.today().isoformat()
            try:
                label = subprocess.check_output(["git", "describe", "--always"], stderr=subprocess.DEVNULL).strip()
                commit_hash = subprocess.check_output(["git", "rev-parse", "HEAD"], stderr=subprocess.DEVNULL).strip()
                version = "Release Date: {}\nLabel: {}\nCommit-Hash: {}\n".format(
                    today, label.decode(), commit_hash.decode()
                )
            except (subprocess.CalledProcessError, FileNotFoundError):
                # Git이 없거나 git 명령이 실패한 경우
                version = "Release Date: {}\nLabel: N/A\nCommit-Hash: N/A\n".format(today)
            
            zip.writestr("version.txt", version)
            
    except Exception as e:
        print(f"[Error] Error creating ZIP file: {e}")
        raise
    
    return


def main(arguments: list) -> int:
    args = init_arguments(arguments)

    print("[I] Parsing and selecting rules, this will take some time...")
    selected_rules = select_rules(args)
    print("[I] Selected {} rules".format(len(selected_rules)))

    write_zip(args.outfile, selected_rules)
    print("[I] Written all rules to output ZIP file '{}'".format(args.outfile))


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
