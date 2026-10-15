import time
import threading


class RateLimiter:
    """
    Rate limiter — saniyede max X istek.
    
    Kullanım:
        rl = RateLimiter(max_per_second=10)
        for url in urls:
            rl.wait()
            requests.get(url)
    """

    def __init__(self, max_per_second=10):
        self.max_per_second = max_per_second
        self.requests = []
        self.lock = threading.Lock()
        self.enabled = True

    def wait(self):
        """Gerekirse bekle, sonra izin ver."""
        if not self.enabled:
            return

        with self.lock:
            now = time.time()
            self.requests = [t for t in self.requests if now - t < 1.0]

            if len(self.requests) >= self.max_per_second:
                sleep_time = 1.0 - (now - self.requests[0])
                if sleep_time > 0:
                    time.sleep(sleep_time)

            self.requests.append(time.time())

    def enable(self):
        self.enabled = True

    def disable(self):
        self.enabled = False

    def set_rate(self, max_per_second):
        self.max_per_second = max_per_second