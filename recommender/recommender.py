import json
import re

class ExploitRecommender:
    def __init__(self, mappings_path="data/mappings.json"):
        self.mappings_path = mappings_path
        self.mappings = self._load_mappings()

    def _load_mappings(self):
        try:
            with open(self.mappings_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"[-] Error loading mappings: {e}")
            return []

    def recommend(self, service_info):
        """
        Takes a service info dictionary and returns a list of suggested exploits.
        service_info keys: service_name, version
        """
        suggestions = []
        svc_name = service_info.get('service_name', '')
        version = service_info.get('version', '')

        for mapping in self.mappings:
            s_regex = mapping.get('service_regex', '.*')
            v_regex = mapping.get('version_regex', '.*')

            if re.search(s_regex, svc_name, re.IGNORECASE) and re.search(v_regex, version, re.IGNORECASE):
                suggestions.append(mapping.get('exploit'))
                
        return suggestions
