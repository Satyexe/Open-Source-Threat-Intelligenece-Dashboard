import requests
from datetime import datetime, timedelta
import re
from urllib.parse import urlparse

def _extract_domains_from_references(cve_obj):
    domains = set()
    refs = cve_obj.get('references', {}).get('reference_data', []) if isinstance(cve_obj.get('references',{}), dict) else []
    for r in refs:
        url = r.get('url') if isinstance(r, dict) else None
        if url:
            try:
                host = urlparse(url).hostname
                if host:
                    host = host.split(':')[0]
                    domains.add(host)
            except:
                pass
    desc = ''
    for d in cve_obj.get('descriptions', []) or []:
        if d.get('lang') == 'en':
            desc = d.get('value','')
            break
    ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', desc)
    for ip in ips:
        domains.add(ip)
    return list(domains)

def fetch_nvd_data(max_items=10):
    try:
        end_date = datetime.utcnow().isoformat() + "Z"
        start_date = (datetime.utcnow() - timedelta(days=1)).isoformat() + "Z"
        url = (
            f"https://services.nvd.nist.gov/rest/json/cves/2.0?lastModStartDate={start_date}&lastModEndDate={end_date}&resultsPerPage={max_items}"
        )
        r = requests.get(url, timeout=15)
        r.raise_for_status()
        data = r.json()
        results = []
        for item in data.get('vulnerabilities', []):
            cve = item.get('cve', {}) or {}
            cve_id = cve.get('id') or 'N/A'
            desc = ''
            for d in cve.get('descriptions', []) or []:
                if d.get('lang') == 'en':
                    desc = d.get('value','')
                    break
            severity = 'Unknown'
            metrics = cve.get('metrics',{}) or {}
            cvss = None
            for k in ('cvssMetricV31','cvssMetricV30','cvssMetricV2'):
                if metrics.get(k):
                    try:
                        cvss = metrics.get(k)[0].get('cvssData',{}).get('baseScore')
                    except:
                        cvss = None
                    break
            if cvss:
                severity = f'CVSS {cvss}'
            iocs = _extract_domains_from_references(cve)
            results.append({
                'id': cve_id,
                'title': cve_id,
                'description': desc,
                'iocs': iocs,
                'severity': severity,
                'published': cve.get('published',''),
                'source': 'NVD'
            })
        return results
    except Exception as e:
        print('NVD fetch error', e)
        return []
