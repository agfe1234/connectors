#  Utilities: helper functions, classes, or modules that provide common, reusable functionality across a codebase
from typing import List

def generate_all_references(data:dict) -> List[dict]:
    return [
        {"source_name": "sigma-rule", "external_id": "reference", "description": reference}
        for reference in data.get("references", [])
    ]
