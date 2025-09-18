import requests
import re

def fetch_cisa_data(max_items=10):
    """
    Fetches the latest Known Exploited Vulnerabilities from CISA's KEV feed.
    
    Args:
        max_items (int): Max number of items to return.
    
    Returns:
        list: List of vulnerability dictionaries.
    """
    try:
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        data = response.json()

        results = []
        for entry in data.get("vulnerabilities", [])[:max_items]:
            cve_id = entry.get("cveID", "N/A")
            notes = entry.get("notes", "")
            date_added = entry.get("dateAdded", "") or entry.get("date_added", "")

            # Extract URLs and IPs from notes
            urls = re.findall(r'https?://[^\s,;]+', notes)
            ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', notes)
            iocs = list(set(urls + ips))

            results.append({
                "id": cve_id,
                "title": cve_id,
                "description": notes.strip(),
                "iocs": iocs,
                "severity": entry.get("severity", "Unknown"),
                "published": date_added,
                "source": "CISA KEV"
            })

        return results

    except Exception as e:
        print("CISA fetch error:", e)
        return []

# Example usage:
if __name__ == "__main__":
    advisories = fetch_cisa_data(5)
    for adv in advisories:
        print(adv)
