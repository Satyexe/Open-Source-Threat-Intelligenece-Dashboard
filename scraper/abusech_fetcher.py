import requests
def fetch_abusech_data(max_items=10):
    try:
        url = "https://mb-api.abuse.ch/api/v1/"
        payload = {"query":"get_recent","limit": max_items}
        r = requests.post(url, data=payload, timeout=15)
        r.raise_for_status()
        data = r.json()
        results = []
        for item in data.get('data', [])[:max_items]:
            title = item.get('sha256_hash') or item.get('sha256') or 'malware-sample'
            signature = item.get('signature', '') or item.get('signature_description','')
            family = item.get('malware_family','')
            desc = signature
            if family:
                desc = f"{desc} | family: {family}"
            results.append({
                'id': title,
                'title': title,
                'description': desc,
                'iocs': [],
                'severity': 'Unknown',
                'published': item.get('first_seen','') or item.get('date',''),
                'source': 'MalwareBazaar'
            })
        return results
    except Exception as e:
        print('AbuseCH fetch error', e)
        return []
