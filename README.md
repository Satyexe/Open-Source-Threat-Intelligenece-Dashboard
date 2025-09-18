# Open Threat Intel Dashboard - Enhanced

## Features
- Aggregates advisories from multiple public sources (NVD, CISA KEV, MalwareBazaar, Exploit-DB)
- Shows detailed advisory list with descriptions and extracted IOCs
- Global map (Leaflet) with geolocated IOCs (uses ipwhois.app for geolocation)
- Alerts panel for high-severity advisories (CVSS >= 7 or CISA KEV entries)
- Download advisories as CSV
- Client-side IOC search and detail modal for each advisory

## How to run (VS Code)
1. Extract the ZIP.
2. Open the folder in VS Code.
3. Open a terminal in VS Code.
4. Create and activate a virtual environment:
   - Windows:
     ```
     python -m venv venv
     venv\\Scripts\\activate
     ```
   - macOS / Linux:
     ```
     python3 -m venv venv
     source venv/bin/activate
     ```
5. Install requirements:
   ```
   pip install -r requirements.txt
   ```
6. Run:
   ```
   python app.py
   ```
7. Visit: http://127.0.0.1:5000

## Notes
- The geo lookup uses https://ipwhois.app (free tier). If you prefer a different provider, update `utils/geo.py`.
- Some advisories don't include IOCs; the map will only show items for which a resolvable IP or domain exists.
- If any feed fails due to network or rate limits, the app still runs with available feeds.
