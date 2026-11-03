from collections import deque, Counter
import time

class TrafficSpikeDetector:
    """Simple configurable packet-count threshold over a rolling time window."""
    def __init__(self, window_seconds=60):
        self.window_seconds = window_seconds
        self.events = deque()

    def update(self, packet_records):
        now = time.time()
        for record in packet_records:
            self.events.append((float(record["timestamp"]), record["src_ip"]))
        cutoff = now - self.window_seconds
        while self.events and self.events[0][0] < cutoff:
            self.events.popleft()

    def counts_by_source(self):
        return Counter(ip for _, ip in self.events)

    def alerts(self, threshold):
        return [{"src_ip": ip, "packets_in_window": count}
                for ip, count in self.counts_by_source().most_common()
                if count >= threshold]
