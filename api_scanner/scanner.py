"""Core scanner implementation."""
import re
import json
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from bs4 import BeautifulSoup
from .checks import run_all_checks

DEFAULT_USER_AGENT = "api-scanner/0.1 (+https://github.com)"

class Scanner:
    def __init__(self, base_url, paths=None, timeout=10, threads=10, headers=None):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.threads = threads
        self.headers = headers or {"User-Agent": DEFAULT_USER_AGENT}
        self.paths = paths or ["/", "/api/", "/health", "/login", "/admin", "/status", "/v1/", "/v2/", "/swagger.json", "/openapi.json"]
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        self.findings = []

    def _norm(self, path):
        if path.startswith('http'):
            return path
        return urllib.parse.urljoin(self.base_url + '/', path.lstrip('/'))

    def discover(self):
        """Discover reachable endpoints from the paths list and page links on root pages."""
        urls = set()
        # probe configured paths
        for p in self.paths:
            urls.add(self._norm(p))

        # simple crawl of root and api root pages to collect <a> hrefs
        to_crawl = [self.base_url, urllib.parse.urljoin(self.base_url + '/', '/api/')]
        try:
            for url in to_crawl:
                resp = self.session.get(url, timeout=self.timeout)
                if resp.status_code == 200 and 'text/html' in resp.headers.get('Content-Type', ''):
                    soup = BeautifulSoup(resp.text, 'html.parser')
                    for a in soup.find_all('a', href=True):
                        href = a['href']
                        # only keep same-host links
                        parsed = urllib.parse.urlparse(href)
                        if parsed.netloc and parsed.netloc != urllib.parse.urlparse(self.base_url).netloc:
                            continue
                        urls.add(self._norm(href))
        except Exception:
            pass

        return sorted(urls)

    def scan_endpoint(self, url):
        """Send requests and run checks for a single endpoint."""
        result = {
            'url': url,
            'responses': {},
            'issues': []
        }
        methods = ['GET', 'POST']
        for m in methods:
            try:
                if m == 'GET':
                    resp = self.session.get(url, timeout=self.timeout)
                else:
                    # safe POST attempt with empty body
                    resp = self.session.post(url, timeout=self.timeout)
                r = {
                    'status_code': resp.status_code,
                    'headers': dict(resp.headers),
                    'body_snippet': (resp.text[:400] + '...') if resp.text else '',
                }
                result['responses'][m] = r
            except Exception as e:
                result['responses'][m] = {'error': str(e)}

        # run checks (security header checks, CORS, reflection, sqli, sensitive data)
        issues = run_all_checks(url, self.session, timeout=self.timeout)
        result['issues'] = issues
        return result

    def run(self):
        targets = self.discover()
        if not targets:
            targets = [self.base_url]
        results = []
        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(self.scan_endpoint, u): u for u in targets}
            for fut in as_completed(futures):
                try:
                    r = fut.result()
                    results.append(r)
                except Exception as e:
                    results.append({'url': futures[fut], 'error': str(e)})
        self.findings = results
        return results

    def to_json(self):
        return json.dumps({'base': self.base_url, 'results': self.findings}, indent=2)

