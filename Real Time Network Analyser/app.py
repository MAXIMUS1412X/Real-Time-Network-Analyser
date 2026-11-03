import csv
import time
from pathlib import Path

import pandas as pd
import plotly.express as px
import psutil
import streamlit as st
from streamlit_autorefresh import st_autorefresh

from network_monitor import NetworkMonitor
from packet_capture import PacketCapture
from algorithms import linear_search, binary_search, bubble_sort, quick_sort, merge_sort
from alerts import TrafficSpikeDetector

st.set_page_config(page_title="Real-Time Network Traffic Analyzer", page_icon="🌐", layout="wide")
st.title("🌐 Real-Time Network Traffic Analyzer")
st.caption("Live network monitoring, traffic analysis, resource usage, reports and DAA algorithms")

DATA_DIR = Path(__file__).parent / "data"
DATA_DIR.mkdir(exist_ok=True)
HISTORY_FILE = DATA_DIR / "network_history.csv"
HISTORY_COLUMNS = [
    "timestamp", "time", "download_mbps", "upload_mbps",
    "total_received_mb", "total_sent_mb", "packets_received", "packets_sent",
    "cpu_percent", "memory_percent"
]

# Keep the existing app components and DAA functions.
if "monitoring" not in st.session_state: st.session_state.monitoring = False
if "monitor" not in st.session_state: st.session_state.monitor = NetworkMonitor()
if "capture" not in st.session_state: st.session_state.capture = PacketCapture()
if "packets" not in st.session_state: st.session_state.packets = []
if "speed_history" not in st.session_state: st.session_state.speed_history = []
if "resource_history" not in st.session_state: st.session_state.resource_history = []
if "detector" not in st.session_state: st.session_state.detector = TrafficSpikeDetector(60)
if "last_stats" not in st.session_state: st.session_state.last_stats = None
if "capture_error" not in st.session_state: st.session_state.capture_error = None
if "active_page" not in st.session_state: st.session_state.active_page = "Overview"
if "alert_history" not in st.session_state: st.session_state.alert_history = []
if "last_bandwidth_alert_time" not in st.session_state: st.session_state.last_bandwidth_alert_time = 0.0

# Sidebar: live controls plus separate navigation buttons.
st.sidebar.header("Monitoring Controls")
interfaces = PacketCapture.available_interfaces()
default_index = next((i for i, name in enumerate(interfaces) if name.lower() == "wi-fi"), 0) if interfaces else 0
interface = st.sidebar.selectbox("Capture interface", interfaces, index=default_index) if interfaces else None
packet_threshold = st.sidebar.number_input(
    "Alert threshold: packets per source IP in 60 seconds", min_value=5, max_value=100000, value=100, step=5
)
bandwidth_threshold = st.sidebar.number_input(
    "Bandwidth alert threshold (Mbps)", min_value=0.1, max_value=10000.0, value=20.0, step=1.0
)
start_col, stop_col = st.sidebar.columns(2)
if start_col.button("▶ Start", use_container_width=True):
    try:
        st.session_state.capture.start(interface)
        st.session_state.monitor = NetworkMonitor()  # fresh rate baseline
        st.session_state.monitoring = True
        st.session_state.capture_error = None
    except Exception as exc:
        st.session_state.monitoring = False
        st.session_state.capture_error = str(exc)
if stop_col.button("⏹ Stop", use_container_width=True):
    try:
        st.session_state.capture.stop()
    except Exception as exc:
        st.session_state.capture_error = str(exc)
    st.session_state.monitoring = False

st.sidebar.divider()
st.sidebar.header("Dashboard Pages")
pages = ["Overview", "Traffic Analysis", "IP & Protocol", "System Resources", "History & Reports", "Alerts", "DAA Lab"]
for page in pages:
    if st.sidebar.button(page, key=f"nav_{page}", use_container_width=True,
                         type="primary" if st.session_state.active_page == page else "secondary"):
        st.session_state.active_page = page
        st.rerun()

if st.session_state.monitoring:
    st.sidebar.success("Monitoring is running")
    st_autorefresh(interval=1000, key="live_refresh")
else:
    st.sidebar.info("Monitoring is stopped")
if st.session_state.capture_error:
    st.error("Packet capture failed. Check Npcap, the selected interface and permissions. Details: " + st.session_state.capture_error)

# Collect live system data and packet metadata once per Streamlit refresh.
if st.session_state.monitoring:
    new_packets = st.session_state.capture.get_packets(5000)
    if new_packets:
        st.session_state.packets.extend(new_packets)
        st.session_state.packets = st.session_state.packets[-5000:]
        st.session_state.detector.update(new_packets)

    stats = st.session_state.monitor.get_stats()
    stats["timestamp"] = time.time()
    stats["time"] = time.strftime("%Y-%m-%d %H:%M:%S")
    stats["cpu_percent"] = psutil.cpu_percent(interval=None)
    stats["memory_percent"] = psutil.virtual_memory().percent
    st.session_state.last_stats = stats

    speed_record = {
        "time": time.strftime("%H:%M:%S"), "timestamp": stats["timestamp"],
        "Download (Mbps)": stats["download_mbps"], "Upload (Mbps)": stats["upload_mbps"]
    }
    st.session_state.speed_history.append(speed_record)
    st.session_state.speed_history = st.session_state.speed_history[-600:]
    st.session_state.resource_history.append({
        "time": speed_record["time"], "timestamp": stats["timestamp"],
        "CPU usage (%)": stats["cpu_percent"], "Memory usage (%)": stats["memory_percent"]
    })
    st.session_state.resource_history = st.session_state.resource_history[-600:]

    # Persist actual psutil readings for later review/export.
    file_exists = HISTORY_FILE.exists() and HISTORY_FILE.stat().st_size > 0
    with HISTORY_FILE.open("a", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=HISTORY_COLUMNS)
        if not file_exists:
            writer.writeheader()
        writer.writerow({key: stats.get(key, "") for key in HISTORY_COLUMNS})

    # Bandwidth spike alert: threshold crossing, with a 30-second cooldown to avoid spam.
    if max(stats["download_mbps"], stats["upload_mbps"]) >= bandwidth_threshold:
        now = time.time()
        if now - st.session_state.last_bandwidth_alert_time >= 30:
            st.session_state.alert_history.append({
                "time": stats["time"], "type": "Bandwidth threshold exceeded",
                "details": f'Download {stats["download_mbps"]:.3f} Mbps; Upload {stats["upload_mbps"]:.3f} Mbps'
            })
            st.session_state.last_bandwidth_alert_time = now

# Helper functions for page content.
def show_live_metrics():
    s = st.session_state.last_stats
    if not s:
        st.info("Click Start in the sidebar to begin monitoring.")
        return
    cols = st.columns(4)
    cols[0].metric("Download speed", f'{s["download_mbps"]:.3f} Mbps')
    cols[1].metric("Upload speed", f'{s["upload_mbps"]:.3f} Mbps')
    cols[2].metric("Total received", f'{s["total_received_mb"]:.2f} MB')
    cols[3].metric("Total sent", f'{s["total_sent_mb"]:.2f} MB')
    cols = st.columns(4)
    cols[0].metric("System packets received", f'{s["packets_received"]:,}')
    cols[1].metric("System packets sent", f'{s["packets_sent"]:,}')
    cols[2].metric("Captured this session", f'{len(st.session_state.packets):,}')
    cols[3].metric("CPU / RAM", f'{s["cpu_percent"]:.0f}% / {s["memory_percent"]:.0f}%')


def show_packet_table():
    packets = st.session_state.packets
    if not packets:
        st.info("No packet records captured yet. Start monitoring and generate ordinary network activity.")
        return
    packet_df = pd.DataFrame(packets)
    visible_df = packet_df[["time", "src_ip", "dst_ip", "protocol", "packet_size"]].rename(columns={
        "time": "Time", "src_ip": "Source IP", "dst_ip": "Destination IP",
        "protocol": "Protocol", "packet_size": "Packet size (bytes)"
    })
    st.write(f"Retaining the latest {len(visible_df):,} packet records (maximum 5,000).")
    st.dataframe(visible_df, use_container_width=True, height=300)
    st.download_button("Download captured metadata as CSV", visible_df.to_csv(index=False).encode("utf-8"),
                       "captured_packet_metadata.csv", "text/csv", key="download_packets")


# Pages are displayed separately through the sidebar buttons.
page = st.session_state.active_page
if page == "Overview":
    st.header("Overview — Live Network Statistics")
    show_live_metrics()
    if st.session_state.speed_history:
        speed_df = pd.DataFrame(st.session_state.speed_history)
        st.plotly_chart(px.line(speed_df, x="timestamp", y=["Download (Mbps)", "Upload (Mbps)"],
                                title="System-wide network speed", labels={"timestamp": "Sample time", "value": "Mbps", "variable": "Direction"}),
                        use_container_width=True)
    st.caption("psutil measures system-wide counters; Scapy captures packets visible on the selected interface. These totals may differ.")
    st.subheader("Recent captured packet metadata")
    show_packet_table()

elif page == "Traffic Analysis":
    st.header("Traffic Analysis")
    st.write("Analyze the live bandwidth measurements collected by psutil. A threshold crossing is a traffic warning, not proof of an attack.")
    show_live_metrics()
    if st.session_state.speed_history:
        speed_df = pd.DataFrame(st.session_state.speed_history)
        st.plotly_chart(px.line(speed_df, x="timestamp", y=["Download (Mbps)", "Upload (Mbps)"],
                                title="Download and upload bandwidth over time", labels={"timestamp": "Sample time", "value": "Mbps", "variable": "Direction"}),
                        use_container_width=True)
        s = st.session_state.last_stats
        avg_down = speed_df["Download (Mbps)"].mean()
        avg_up = speed_df["Upload (Mbps)"].mean()
        c = st.columns(3)
        c[0].metric("Average download (retained samples)", f"{avg_down:.3f} Mbps")
        c[1].metric("Average upload (retained samples)", f"{avg_up:.3f} Mbps")
        c[2].metric("Configured alert threshold", f"{bandwidth_threshold:.1f} Mbps")
        if s and max(s["download_mbps"], s["upload_mbps"]) >= bandwidth_threshold:
            st.warning(f'Current traffic crossed the threshold: download {s["download_mbps"]:.3f} Mbps, upload {s["upload_mbps"]:.3f} Mbps.')
        else:
            st.success("Current bandwidth is below the configured threshold.")
        st.subheader("Recent bandwidth measurements")
        st.dataframe(speed_df.tail(30).iloc[::-1], use_container_width=True, hide_index=True)
    else:
        st.info("Start monitoring to build a live bandwidth history.")

elif page == "IP & Protocol":
    st.header("IP and Protocol Analysis")
    packets = st.session_state.packets
    if packets:
        packet_df = pd.DataFrame(packets)
        left, right = st.columns(2)
        with left:
            protocol_counts = packet_df.groupby("protocol").size().reset_index(name="Packets").sort_values("Packets", ascending=False)
            st.plotly_chart(px.pie(protocol_counts, names="protocol", values="Packets", title="Captured packets by protocol"), use_container_width=True)
            st.dataframe(protocol_counts.rename(columns={"protocol": "Protocol"}), use_container_width=True, hide_index=True)
        with right:
            source_counts = packet_df.groupby("src_ip").size().reset_index(name="Packets").sort_values("Packets", ascending=False).head(10)
            st.plotly_chart(px.bar(source_counts, x="src_ip", y="Packets", title="Top 10 source IP addresses"), use_container_width=True)
            dest_counts = packet_df.groupby("dst_ip").size().reset_index(name="Packets").sort_values("Packets", ascending=False).head(10)
            st.plotly_chart(px.bar(dest_counts, x="dst_ip", y="Packets", title="Top 10 destination IP addresses"), use_container_width=True)
        st.subheader("Captured packet details")
        show_packet_table()
    else:
        st.info("Start packet capture to analyze source IPs, destination IPs and protocols.")

elif page == "System Resources":
    st.header("System Resource Monitoring")
    st.write("CPU and memory are sampled alongside network statistics to help compare system load with network activity.")
    s = st.session_state.last_stats
    if s:
        c = st.columns(2)
        c[0].metric("CPU utilization", f'{s["cpu_percent"]:.1f}%')
        c[1].metric("Memory utilization", f'{s["memory_percent"]:.1f}%')
    if st.session_state.resource_history:
        resource_df = pd.DataFrame(st.session_state.resource_history)
        st.plotly_chart(px.line(resource_df, x="timestamp", y=["CPU usage (%)", "Memory usage (%)"],
                                title="CPU and memory utilization over time", labels={"timestamp": "Sample time", "value": "Utilization (%)", "variable": "Resource"}),
                        use_container_width=True)
        if st.session_state.speed_history:
            speed_df = pd.DataFrame(st.session_state.speed_history)
            combined = pd.merge(resource_df, speed_df[["timestamp", "Download (Mbps)", "Upload (Mbps)" ]], on="timestamp", how="inner")
            st.subheader("Network bandwidth alongside resource usage")
            st.plotly_chart(px.line(combined, x="timestamp", y=["Download (Mbps)", "Upload (Mbps)"],
                                    title="Bandwidth while observing CPU and memory", labels={"timestamp": "Sample time", "value": "Mbps", "variable": "Direction"}),
                            use_container_width=True)
            st.dataframe(combined.tail(30).iloc[::-1], use_container_width=True, hide_index=True)
    else:
        st.info("Start monitoring to collect CPU, RAM and network measurements.")

elif page == "History & Reports":
    st.header("Historical Data and Reports")
    st.write("Live psutil measurements are appended to a CSV file in the project's `data` folder while monitoring is running.")
    if HISTORY_FILE.exists() and HISTORY_FILE.stat().st_size > 0:
        try:
            history_df = pd.read_csv(HISTORY_FILE)
            st.metric("Saved measurement rows", f"{len(history_df):,}")
            if not history_df.empty:
                if "timestamp" in history_df.columns:
                    history_df["timestamp"] = pd.to_numeric(history_df["timestamp"], errors="coerce")
                st.plotly_chart(px.line(history_df.tail(1000), x="time", y=["download_mbps", "upload_mbps"],
                                        title="Saved bandwidth history (latest 1,000 samples)",
                                        labels={"time": "Recorded time", "value": "Mbps", "variable": "Direction"}),
                                use_container_width=True)
                st.dataframe(history_df.tail(100).iloc[::-1], use_container_width=True, hide_index=True)
                st.download_button("Download complete network history CSV", HISTORY_FILE.read_bytes(),
                                   "network_history.csv", "text/csv", key="download_history")
                st.download_button("Download visible history as CSV", history_df.tail(100).to_csv(index=False).encode("utf-8"),
                                   "recent_network_history.csv", "text/csv", key="download_recent_history")
        except Exception as exc:
            st.error(f"Could not read the history file: {exc}")
    else:
        st.info("No saved history yet. Start monitoring; measurements will be logged automatically.")

elif page == "Alerts":
    st.header("Alert Center")
    st.write("Alerts summarize high bandwidth readings and high packet counts per source IP. They are indicators for review, not definitive security findings.")
    s = st.session_state.last_stats
    if s and max(s["download_mbps"], s["upload_mbps"]) >= bandwidth_threshold:
        st.warning(f'Current bandwidth is above threshold ({bandwidth_threshold:.1f} Mbps).')
    else:
        st.success("Current bandwidth is below the configured threshold, or monitoring has not started.")
    packet_alerts = st.session_state.detector.alerts(int(packet_threshold))
    st.subheader("Source IP packet-count alerts (rolling 60-second window)")
    if packet_alerts:
        st.warning("One or more source IPs crossed the packet-count threshold.")
        st.dataframe(pd.DataFrame(packet_alerts), use_container_width=True, hide_index=True)
    else:
        st.info("No source IP has crossed the configured packet-count threshold.")
    st.subheader("Bandwidth alert history")
    if st.session_state.alert_history:
        alert_df = pd.DataFrame(st.session_state.alert_history)
        st.dataframe(alert_df.iloc[::-1], use_container_width=True, hide_index=True)
        st.download_button("Download alert history CSV", alert_df.to_csv(index=False).encode("utf-8"),
                           "network_alert_history.csv", "text/csv", key="download_alerts")
    else:
        st.info("No bandwidth threshold alerts recorded in this app session yet.")

elif page == "DAA Lab":
    st.header("DAA Algorithm Lab — Real Captured Data")
    st.write("The existing DAA controls continue to operate on actual packet metadata captured in this session. No random data is substituted for live records.")
    packets = st.session_state.packets
    if not packets:
        st.warning("Capture some packets first; the DAA lab will then use those records.")
    else:
        search_tab, sort_tab, bench_tab = st.tabs(["Search captured packets", "Sort captured packets", "Benchmark algorithms"])
        with search_tab:
            field = st.selectbox("Search field", ["src_ip", "dst_ip", "protocol"],
                                 format_func=lambda x: {"src_ip": "Source IP", "dst_ip": "Destination IP", "protocol": "Protocol"}[x])
            values = sorted({str(p.get(field, "")) for p in packets})
            target = st.text_input("Exact value to find", value=values[0] if values else "")
            method = st.radio("Algorithm", ["Linear Search", "Binary Search"], horizontal=True)
            if st.button("Search captured packets"):
                if method == "Linear Search":
                    start = time.perf_counter(); idx = linear_search(packets, field, target); elapsed = time.perf_counter() - start
                    rows = [packets[idx]] if idx >= 0 else []
                    st.caption("Worst-case complexity: O(n).")
                else:
                    ordered = sorted(packets, key=lambda r: str(r.get(field, "")).lower())
                    start = time.perf_counter(); idx = binary_search(ordered, field, target); elapsed = time.perf_counter() - start
                    rows = [ordered[idx]] if idx >= 0 else []
                    st.caption("Search complexity: O(log n); sorting prerequisite is excluded from the timed search.")
                st.metric("Search execution time", f"{elapsed * 1000:.4f} ms")
                if rows:
                    st.success("Matching packet found (showing one matching record).")
                    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
                else:
                    st.warning("No matching record found.")
        with sort_tab:
            sort_field = st.selectbox("Sort key", ["timestamp", "packet_size", "src_ip", "dst_ip", "protocol"],
                                      format_func=lambda x: {"timestamp": "Timestamp", "packet_size": "Packet size", "src_ip": "Source IP", "dst_ip": "Destination IP", "protocol": "Protocol"}[x])
            sort_method = st.selectbox("Sorting algorithm", ["Merge Sort", "Quick Sort", "Bubble Sort"])
            max_records = min(len(packets), 1000)
            n_records = st.slider("Most recent records to sort", 1, max_records, min(200, max_records))
            st.caption("Bubble Sort is capped at 1,000 records to keep the interface responsive.")
            if st.button("Sort actual captured packets"):
                batch = packets[-n_records:]
                sorter = {"Merge Sort": merge_sort, "Quick Sort": quick_sort, "Bubble Sort": bubble_sort}[sort_method]
                start = time.perf_counter(); ordered = sorter(batch, sort_field); elapsed = time.perf_counter() - start
                st.metric("Sorting execution time", f"{elapsed * 1000:.4f} ms")
                st.caption({"Merge Sort": "O(n log n) time; O(n) auxiliary space.", "Quick Sort": "O(n log n) average; O(n²) worst-case.", "Bubble Sort": "O(n²) average/worst-case; O(n) best-case with early exit."}[sort_method])
                out_df = pd.DataFrame(ordered).drop(columns=["timestamp"], errors="ignore")
                st.dataframe(out_df, use_container_width=True, height=300)
        with bench_tab:
            st.write("Compare all three sorting algorithms on the same recent captured batch.")
            max_bench = min(len(packets), 500)
            n_bench = st.slider("Records per benchmark", min_value=1, max_value=max_bench, value=min(100, max_bench), key="bench_n")
            bench_field = st.selectbox("Benchmark sort key", ["packet_size", "timestamp", "src_ip", "protocol"], key="bench_field")
            if st.button("Benchmark all sorting algorithms"):
                batch = packets[-n_bench:]
                expected = sorted([r.get(bench_field) for r in batch])
                rows = []
                for name, sorter in [("Bubble Sort", bubble_sort), ("Quick Sort", quick_sort), ("Merge Sort", merge_sort)]:
                    start = time.perf_counter(); result = sorter(batch, bench_field); elapsed = time.perf_counter() - start
                    correct = [r.get(bench_field) for r in result] == expected
                    rows.append({"Algorithm": name, "Records": len(batch), "Execution time (ms)": elapsed * 1000, "Correctly sorted": correct})
                result_df = pd.DataFrame(rows)
                st.dataframe(result_df, use_container_width=True, hide_index=True)
                st.plotly_chart(px.bar(result_df, x="Algorithm", y="Execution time (ms)", title=f"Sort comparison on {len(batch)} captured packets"), use_container_width=True)
                st.caption("Small batches can be affected by timer noise. Repeat on several batch sizes for a reproducible report.")

st.divider()
st.caption("Metadata only: packet payloads are not saved. Capture only traffic you are authorized to inspect.")
