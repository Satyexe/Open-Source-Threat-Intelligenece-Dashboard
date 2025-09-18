import os, json, re, socket, time, requests
from urllib.parse import urlparse

CACHE_FILE = os.path.join(os.path.dirname(__file__), '..', 'geo_cache.json')

def _load_cache():
    try:
        with open(CACHE_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except:
        return {}

def _save_cache(c):
    try:
        with open(CACHE_FILE, 'w', encoding='utf-8') as f:
            json.dump(c, f, indent=2)
    except Exception as e:
        print('geo cache save error:', e)

def _is_ip(s):
    return bool(re.match(r'^(?:\d{1,3}\.){3}\d{1,3}$', s))

def _extract_domain(s):
    try:
        if '://' in s:
            p = urlparse(s)
            return p.hostname
        return s
    except:
        return None

def _geolocate_ip(ip):
    try:
        url = f'https://ipwhois.app/json/{ip}'
        r = requests.get(url, timeout=8)
        data = r.json()
        if data.get('success', True) is False:
            return None
        lat = data.get('latitude') or data.get('lat')
        lon = data.get('longitude') or data.get('lon')
        return {
            'lat': lat,
            'lon': lon,
            'city': data.get('city') or '',
            'country': data.get('country') or '',
            'query': ip
        }
    except Exception as e:
        print('geolocate ip error', e)
        return None

def geolocate_iocs(ioc_list):
    cache = _load_cache()
    results = {}
    for i in ioc_list:
        key = i.strip()
        if not key:
            continue
        if key in cache:
            results[key] = cache[key]
            continue
        dom = _extract_domain(key) or key
        ip = None
        if _is_ip(dom):
            ip = dom
        else:
            try:
                ip = socket.gethostbyname(dom)
            except Exception as e:
                ip = None
        if ip:
            info = _geolocate_ip(ip)
            if info:
                cache[key] = info
                results[key] = info
                time.sleep(0.8)
                continue
        cache[key] = None
        results[key] = None
    _save_cache(cache)
    return results
