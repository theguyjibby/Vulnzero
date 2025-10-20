
from zapv2 import ZAPv2
import os
import time

class ZapScanner:
    def __init__(self, api_key="rp5g8evoht806pqkj0lh0v0149", proxy: str | None = None):
        proxy_url = proxy or os.getenv("ZAP_PROXY", "http://127.0.0.1:8080")
        self.zap = ZAPv2(apikey=api_key, proxies={'http': proxy_url, 'https': proxy_url})

    def scan(self, target, context_name: str = None, ajax_spider: bool = True, recurse: bool = True, max_children: int = 0):
        self.zap.urlopen(target)
        # Traditional spider
        spider_id = self.zap.spider.scan(target, recurse=recurse, maxchildren=max_children)
        while int(self.zap.spider.status(spider_id)) < 100:
            time.sleep(2)
        # AJAX spider (useful for JS-heavy sites)
        if ajax_spider:
            try:
                self.zap.ajaxSpider.scan(target, inscope='true')
                # Poll until completed or timeout
                ajax_wait = 0
                while self.zap.ajaxSpider.status() in ['running', 'stopped'] and ajax_wait < 120:
                    time.sleep(2)
                    ajax_wait += 2
            except Exception:
                pass
        # Passive scan wait (let passive scanner process)
        passive_wait = 0
        while int(self.zap.pscan.records_to_scan) > 0 and passive_wait < 120:
            time.sleep(2)
            passive_wait += 2
        # Active scan with broader policy (default policy; beta/alpha rules require ZAP config)
        ascan_id = self.zap.ascan.scan(target)
        while int(self.zap.ascan.status(ascan_id)) < 100:
            time.sleep(5)
        alerts = self.zap.core.alerts(baseurl=target)
        normalized = []
        for a in alerts:
            normalized.append({
                'source': 'zap',
                'alert': a.get('alert'),
                'title': a.get('alert'),
                'description': a.get('description'),
                'severity': (a.get('risk') or '').lower(),
                'url': a.get('url'),
                'param': a.get('param'),
                'evidence': a.get('evidence'),
                'remediation': a.get('solution'),
            })
        return normalized


if __name__ == "__main__":
    target = "http://192.168.206.129"
    zap_scanner = ZapScanner()
    alerts = zap_scanner.scan(target)
    for alert in alerts:
        print(f"Alert: {alert['alert']}, Severity: {alert['severity']}, URL: {alert['url']}")
