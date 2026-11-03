import time
import psutil

class NetworkMonitor:
    """System-wide network counters and measured transfer rates."""
    def __init__(self):
        self.previous_stats = psutil.net_io_counters()
        self.previous_time = time.perf_counter()

    def get_stats(self):
        current = psutil.net_io_counters()
        now = time.perf_counter()
        elapsed = max(now - self.previous_time, 1e-6)
        received = max(current.bytes_recv - self.previous_stats.bytes_recv, 0)
        sent = max(current.bytes_sent - self.previous_stats.bytes_sent, 0)
        result = {
            "download_mbps": received * 8 / elapsed / 1_000_000,
            "upload_mbps": sent * 8 / elapsed / 1_000_000,
            "total_received_mb": current.bytes_recv / (1024 ** 2),
            "total_sent_mb": current.bytes_sent / (1024 ** 2),
            "packets_received": current.packets_recv,
            "packets_sent": current.packets_sent,
        }
        self.previous_stats, self.previous_time = current, now
        return result
