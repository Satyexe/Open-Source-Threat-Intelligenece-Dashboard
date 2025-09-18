import json
from flask import Flask, render_template, jsonify, Response
from scraper.nvd_fetcher import fetch_nvd_data
from scraper.cisa_fetcher import fetch_cisa_data
from scraper.uscert_fetcher import fetch_uscert_data
from scraper.exploitdb_fetcher import fetch_exploitdb_data
from utils.geo import geolocate_iocs

app = Flask(__name__, static_folder='static', template_folder='templates')


def collect_advisories(max_items_each=25):
    """Collect advisories from multiple threat intelligence sources."""
    advisories = []

    sources = [
        ("NVD", fetch_nvd_data),
        ("CISA KEV", fetch_cisa_data),
        ("US-CERT", fetch_uscert_data),
        ("ExploitDB", fetch_exploitdb_data)
    ]

    for name, fetcher in sources:
        try:
            advisories.extend(fetcher(max_items=max_items_each))
        except Exception as e:
            print(f"[ERROR] {name} fetch failed: {e}")

    # Ensure minimal required keys exist
    for adv in advisories:
        adv.setdefault("title", "No title")
        adv.setdefault("description", "")
        adv.setdefault("severity", "Unknown")
        adv.setdefault("published", "")
        adv.setdefault("source", "Unknown")
        adv.setdefault("iocs", [])

    return advisories


@app.route("/")
def index():
    advisories = collect_advisories(15)

    # Gather all IOCs for geolocation
    all_iocs = {ioc for adv in advisories for ioc in adv.get("iocs", [])}
    geo = geolocate_iocs(list(all_iocs))

    markers = []
    for adv in advisories:
        for ioc in adv.get("iocs", []):
            info = geo.get(ioc)
            if info and info.get("lat") and info.get("lon"):
                markers.append({
                    "ioc": ioc,
                    "title": adv.get("title"),
                    "source": adv.get("source"),
                    "lat": info["lat"],
                    "lon": info["lon"],
                    "city": info.get("city", ""),
                    "country": info.get("country", "")
                })

    # Alerts: High severity or from CISA/US-CERT
    alerts = []
    for adv in advisories:
        sev = adv.get("severity", "")
        try:
            num = float("".join(c for c in str(sev) if (c.isdigit() or c == "."))) \
                  if any(ch.isdigit() for ch in str(sev)) else 0
        except:
            num = 0
        if num >= 7 or adv.get("source") in ("CISA KEV", "US-CERT"):
            alerts.append(adv)

    # Summary counts by source
    summary = {}
    for adv in advisories:
        summary[adv.get("source", "Unknown")] = summary.get(adv.get("source", "Unknown"), 0) + 1

    # ----------------------
    # CVE Stats Calculations
    # ----------------------
    from datetime import datetime, timedelta
    today = datetime.utcnow().date()
    days_7 = today - timedelta(days=7)
    days_30 = today - timedelta(days=30)

    def parse_date(date_str):
        try:
            return datetime.fromisoformat(date_str.replace("Z", "+00:00")).date()
        except:
            try:
                return datetime.strptime(date_str, "%a, %d %b %Y %H:%M:%S %Z").date()
            except:
                return None

    created_today = created_7 = created_30 = 0
    updated_today = updated_7 = updated_30 = 0

    cvss_bins = [0] * 10  # CVSS 0–9

    for adv in advisories:
        pub_date = parse_date(adv.get("published", ""))
        if pub_date:
            if pub_date == today:
                created_today += 1
            if pub_date >= days_7:
                created_7 += 1
            if pub_date >= days_30:
                created_30 += 1

        # Updated date could be added if available
        # if adv.get("updated")...

        # CVSS binning
        sev = adv.get("severity", "")
        if sev.startswith("CVSS"):
            try:
                score = float(sev.split()[1])
                idx = min(int(score), 9)
                cvss_bins[idx] += 1
            except:
                pass

    cve_stats = {
        "created_today": created_today,
        "updated_today": updated_today,
        "created_7": created_7,
        "updated_7": updated_7,
        "created_30": created_30,
        "updated_30": updated_30,
    }

    return render_template(
        "dashboard.html",
        advisories=advisories,
        markers=markers,
        alerts=alerts,
        summary=summary,
        cve_stats=cve_stats,
        cvss_bins=cvss_bins
    )



@app.route("/api/advisories")
def api_advisories():
    advisories = collect_advisories(50)
    return jsonify(advisories)


@app.route("/download/advisories.csv")
def download_csv():
    advisories = collect_advisories(100)

    import io, csv
    mem = io.StringIO()
    writer = csv.writer(mem)
    writer.writerow(["source", "title", "severity", "published", "description", "iocs"])
    for adv in advisories:
        writer.writerow([
            adv.get("source", ""),
            adv.get("title", ""),
            adv.get("severity", ""),
            adv.get("published", ""),
            adv.get("description", "").replace("\n", " "),
            ";".join(adv.get("iocs", []))
        ])
    mem.seek(0)
    return Response(
        mem.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=advisories.csv"}
    )


if __name__ == "__main__":
    app.run(debug=True)
