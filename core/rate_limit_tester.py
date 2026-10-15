import requests
import time
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class RateLimitTester:
    """
    Hedefte rate limit var mı kontrol et.
    
    Kullanım:
        tester = RateLimitTester("https://api.hedef.com/endpoint", max_requests=50)
        result = tester.test()
    """

    def __init__(self, url, max_requests=50, delay=0.0, timeout=5):
        self.url = url
        self.max_requests = max_requests
        self.delay = delay
        self.timeout = timeout
        self.is_cancelled = is_cancelled 
        self.requests = []

    def test(self):
        """Rate limit testi."""
        result = {
            "url": self.url,
            "total_sent": 0,
            "success": 0,
            "blocked": 0,
            "blocked_at": None,
            "status_codes": {},
            "rate_limit_exists": False,
            "vulnerable": False,
        }

        headers = {"User-Agent": "RedStrike-Suite/1.0"}

        for i in range(self.max_requests):
            if self.is_cancelled and self.is_cancelled():
                result["cancelled"] = True
                break
            
            
            try:
                r = requests.get(
                    self.url,
                    headers=headers,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=True
                )

                result["total_sent"] += 1
                code = r.status_code
                result["status_codes"][code] = result["status_codes"].get(code, 0) + 1

                if code == 429:
                    result["blocked"] += 1
                    result["blocked_at"] = i + 1
                    result["rate_limit_exists"] = True
                    break
                elif code in (403, 503):
                    result["blocked"] += 1
                    result["blocked_at"] = i + 1
                    result["rate_limit_exists"] = True
                    break
                elif code == 200:
                    result["success"] += 1
                else:
                    result["success"] += 1

                if self.delay > 0:
                    time.sleep(self.delay)

            except requests.exceptions.Timeout:
                result["blocked"] += 1
                result["blocked_at"] = i + 1
                break
            except requests.exceptions.ConnectionError:
                break
            except Exception:
                break

        # Zafiyet kontrolü
        if result["success"] >= self.max_requests and not result["rate_limit_exists"]:
            result["vulnerable"] = True

        return result