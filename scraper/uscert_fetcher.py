import requests
from bs4 import BeautifulSoup

def fetch_uscert_data(max_items=10):
    """
    Fetch latest alerts from US-CERT (CISA NCAS).
    
    Args:
        max_items (int): Maximum number of alerts to fetch.
    
    Returns:
        list: List of alerts with consistent fields.
    """
    try:
        url = "https://www.cisa.gov/uscert/ncas/alerts.xml"
        response = requests.get(url, timeout=15)
        response.raise_for_status()

        soup = BeautifulSoup(response.content, "xml")
        items = soup.find_all("item", limit=max_items)

        results = []
        for item in items:
            title = item.title.text.strip() if item.title else "No Title"
            link = item.link.text.strip() if item.link else ""
            description = item.description.text.strip() if item.description else ""
            published = item.pubDate.text.strip() if item.pubDate else ""

            results.append({
                "id": link or title,  # Using link as ID if available
                "title": title,
                "description": description,
                "iocs": [],
                "severity": "Unknown",  # US-CERT feed doesn't provide severity
                "published": published,
                "source": "US-CERT"
            })

        return results

    except Exception as e:
        print("US-CERT fetch error:", e)
        return []

# Example test
if __name__ == "__main__":
    alerts = fetch_uscert_data(5)
    for alert in alerts:
        print(alert)
