from datetime import datetime
from queue import Queue, Empty, Full
from threading import Lock

from scapy.all import AsyncSniffer, IP, IPv6, TCP, UDP, ICMP, IFACES


class PacketCapture:
    """Capture packet metadata only, without saving payload contents."""

    def __init__(self, max_queue_size=20000):
        self._queue = Queue(maxsize=max_queue_size)
        self._sniffer = None
        self._lock = Lock()
        self.dropped_from_queue = 0
        self.last_error = None

    @staticmethod
    def available_interfaces():
        """Return friendly interface names, for example Wi-Fi or Ethernet."""
        try:
            names = [iface.name for iface in IFACES.values() if getattr(iface, "name", None)]
            return list(dict.fromkeys(names))
        except Exception:
            return []

    @property
    def is_running(self):
        return self._sniffer is not None and self._sniffer.running

    def start(self, interface="Wi-Fi"):
        if self.is_running:
            return
        self.last_error = None
        selected_interface = interface or "Wi-Fi"
        try:
            self._sniffer = AsyncSniffer(
                iface=selected_interface,
                prn=self._handle_packet,
                store=False,
            )
            self._sniffer.start()
        except Exception as exc:
            self._sniffer = None
            self.last_error = str(exc)
            raise RuntimeError(
                f"Could not start packet capture on '{selected_interface}': {exc}"
            ) from exc

    def stop(self):
        sniffer = self._sniffer
        self._sniffer = None
        if sniffer is not None:
            try:
                if sniffer.running:
                    sniffer.stop()
            except Exception as exc:
                self.last_error = str(exc)

    def _handle_packet(self, packet):
        try:
            if IP in packet:
                layer = packet[IP]
                src, dst, proto_num = layer.src, layer.dst, int(layer.proto)
            elif IPv6 in packet:
                layer = packet[IPv6]
                src, dst, proto_num = layer.src, layer.dst, int(layer.nh)
            else:
                return

            if TCP in packet:
                protocol = "TCP"
            elif UDP in packet:
                protocol = "UDP"
            elif ICMP in packet:
                protocol = "ICMP"
            else:
                protocol = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}.get(
                    proto_num, f"IP-{proto_num}"
                )

            timestamp = float(packet.time)
            record = {
                "timestamp": timestamp,
                "time": datetime.fromtimestamp(timestamp).strftime("%H:%M:%S.%f")[:-3],
                "src_ip": str(src),
                "dst_ip": str(dst),
                "protocol": protocol,
                "packet_size": int(len(packet)),
            }
            try:
                self._queue.put_nowait(record)
            except Full:
                with self._lock:
                    self.dropped_from_queue += 1
        except Exception:
            # A malformed or unsupported packet should not terminate the sniffer.
            return

    def get_packets(self, limit=5000):
        result = []
        for _ in range(limit):
            try:
                result.append(self._queue.get_nowait())
            except Empty:
                break
        return result
