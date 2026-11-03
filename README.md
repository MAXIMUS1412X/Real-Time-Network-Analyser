Real-Time Network Traffic Analyzer
Setup (Windows / VS Code)
Install Python 3.10+ and Npcap: https://npcap.com/#download
Open this folder in VS Code.
Install dependencies: `python -m pip install -r requirements.txt`
Run the app: `python -m streamlit run app.py`
Select the active interface (usually Wi-Fi), then click Start.
Dashboard buttons
The sidebar has separate page buttons:
Overview — current system-wide network statistics and recent captured packets.
Traffic Analysis — download/upload trends, averages and bandwidth threshold warnings.
IP & Protocol — protocol distribution, top source IPs, and top destination IPs.
System Resources — CPU and RAM usage alongside network activity.
History & Reports — saved measurements, history charts, and CSV downloads.
Alerts — bandwidth threshold events and source-IP packet-count alerts.
DAA Lab — the existing linear/binary search, sorting, and algorithm benchmarking tools on real captured packet records.
Data sources and files
`psutil` provides system-wide network counters and calculated transfer rates.
`psutil` also supplies CPU and memory utilization readings.
Scapy captures visible IP packet metadata: timestamp, source IP, destination IP, protocol, and packet size. Payload contents are not saved.
Live system readings are appended to `data/network\_history.csv` while monitoring is running.
Captured packet metadata and alert history can be downloaded from the interface.
`psutil` system-wide counters and Scapy interface-specific packet capture are different measurements, so their totals may not match. Bandwidth threshold alerts are indicators for review, not proof of an attack. Only capture traffic you are authorized to inspect.
DAA complexity
Linear Search: O(n) worst-case.
Binary Search: O(log n) after ordering records by the selected key.
Bubble Sort: O(n²) average/worst-case; optimized best-case O(n).
Quick Sort: O(n log n) average, O(n²) worst-case.
Merge Sort: O(n log n) time, O(n) auxiliary space.
Windows notes
Packet capture may require Npcap and elevated permissions. Select the active adapter; the Wi-Fi interface is often the correct choice for a wireless connection. VPN, driver and permission settings can affect packet visibility.
