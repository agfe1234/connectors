#!/usr/bin/env python3

import sys
import os
import yaml
import json
import uuid

sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

# Mock config object for testing
class MockConfig:
    def __init__(self):
        self.tlp_level = "white"
        self.namespace = uuid.NAMESPACE_DNS
        self.CVE_PATH = "https://cve.mitre.org/cgi-bin/cvename.cgi?name={}"
        self.MITRE_TECHNIQUE_PATH = "https://attack.mitre.org/techniques/{}"
        self.MITRE_SOFTWARE_PATH = "https://attack.mitre.org/software/{}"
        self.MITRE_GROUP_PATH = "https://attack.mitre.org/groups/{}"

config = MockConfig()

from external_import_connector.converter_to_stix import ConverterToStix
from datetime import datetime, timezone

# Mock helper for testing
class MockHelper:
    def __init__(self):
        self.connector_logger = self
    
    def error(self, message, *args, **kwargs):
        print(f"ERROR: {message}")
    
    def info(self, message, *args, **kwargs):
        print(f"INFO: {message}")

def test_converter():
    # Read sample Sigma rule
    with open('src/sample_sigma.yml', 'r') as f:
        yaml_content = f.read()
    
    # Mock helper
    helper = MockHelper()
    
    # Create converter instance
    converter = ConverterToStix(helper, config)
    
    # Test the conversion
    print("Testing Sigma rule conversion...")
    print(f"YAML content length: {len(yaml_content)} characters")
    
    try:
        # Call create_obs with YAML content
        result = converter.create_obs(yaml_content)
        
        if result:
            print("✅ Conversion successful!")
            print(f"STIX object ID: {result.get('id', 'No ID')}")
            print(f"Name: {result.get('name', 'No name')}")
            print(f"Pattern type: {result.get('pattern_type', 'No pattern type')}")
            print(f"External references count: {len(result.get('external_references', []))}")
            print(f"Labels count: {len(result.get('labels', []))}")
            
            # Print full result object
            print("\n=== Full Result Object ===")
            # If result is a JSON string, pretty-print it
            if isinstance(result, str):
                try:
                    parsed = json.loads(result)
                    print(json.dumps(parsed, indent=2, default=str))
                except Exception:
                    print(result)
            elif hasattr(result, 'serialize'):
                print(json.dumps(result.serialize(), indent=2, default=str))
            else:
                print(json.dumps(result, indent=2, default=str))
            print("=========================\n")
            
            # Print external references
            if result.get('external_references'):
                print("\nExternal References:")
                for ref in result.get('external_references', []):
                    print(f"  - {ref.get('source_name')}: {ref.get('external_id')} - {ref.get('description', '')}")
            
            # Print some labels
            if result.get('labels'):
                print(f"\nLabels: {result.get('labels')[:5]}...")  # Show first 5 labels
                
        else:
            print("❌ Conversion failed - no result returned")
            
    except Exception as e:
        print(f"❌ Conversion failed with error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_converter()
