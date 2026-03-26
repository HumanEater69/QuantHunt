import concurrent.futures
import csv
import math
import socket
import ssl
import sys
import time
from typing import Any

MSS = 1460
IW = 10
MIN_RTO = 200.0
PACKET_LOSS_RATE = 0.01

CLASSICAL_SIZE = 2500
PQC_HYBRID_SIZE = 16800

def calculate_tcp_flights(payload_size: int) -> int:
    """
    Calculates extra network round trips (Flights) based on TCP slow start.
    Mathematical formula: Flights = ceil(log2((N_seg / iw) + 1))
    """
    n_seg = math.ceil(payload_size / MSS)
    if n_seg <= IW:
        return 0
    return math.ceil(math.log2((n_seg / IW) + 1))

def simulate_latency(rtt_ms: float, payload_size: int, loss_rate: float) -> dict[str, float]:
    """Applies the mathematical model to project complete handshake TTFB."""
    n_seg = math.ceil(payload_size / MSS)
    flights = calculate_tcp_flights(payload_size)

    t_prop = rtt_ms * (2 + flights)

    p_success = (1 - loss_rate) ** n_seg
    if p_success <= 0:
        p_success = 0.0001

    rto = max(MIN_RTO, 3 * rtt_ms)
    t_loss = ((1 - p_success) / p_success) * rto

    crypto_overhead = 5.0
    total_ttfb = t_prop + t_loss + crypto_overhead

    return {
        "segments": float(n_seg),
        "extra_flights": float(flights),
        "t_loss_ms": round(t_loss, 2),
        "total_latency_ms": round(total_ttfb, 2),
    }

def profile_domain(domain: str) -> dict[str, Any]:
    """Connects to a domain to measure baseline TCP RTT and TLS handshake time."""
    port = 443
    result: dict[str, Any] = {
        "Domain": domain,
        "Status": "Failed",
        "Base_RTT_ms": 0.0,
        "Classical_TLS_ms": 0.0,
    }

    try:

        start_tcp = time.time()
        sock = socket.create_connection((domain, port), timeout=5)
        rtt = (time.time() - start_tcp) * 1000
        result["Base_RTT_ms"] = round(rtt, 2)

        context = ssl.create_default_context()
        start_tls = time.time()
        ssock = context.wrap_socket(sock, server_hostname=domain)
        tls_time = (time.time() - start_tls) * 1000
        result["Classical_TLS_ms"] = round(tls_time, 2)

        ssock.close()
        result["Status"] = "Success"
    except Exception as exc:
        result["Status"] = f"Error: {exc}"

    return result

def _export_csv(rows: list[dict[str, Any]], filename: str) -> None:
    if not rows:
        return
    keys = list(rows[0].keys())
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(rows)

def _export_plot(results: list[dict[str, Any]], img_filename: str) -> bool:
    """Best-effort chart export; returns False if matplotlib is unavailable."""
    try:
        import matplotlib.pyplot as plt
    except Exception:
        return False

    ordered = sorted(results, key=lambda x: x["Base_RTT_ms"])
    domains = [r["Domain"] for r in ordered]
    classical = [r["Simulated_Classical_ms"] for r in ordered]
    pqc = [r["Simulated_PQC_ms"] for r in ordered]

    bar_width = 0.35
    idx = list(range(len(ordered)))

    plt.figure(figsize=(12, 6))
    plt.bar(idx, classical, bar_width, label="Classical TLS (RSA/ECC)", color="#4CAF50")
    plt.bar([i + bar_width for i in idx], pqc, bar_width, label="Hybrid PQC (ML-KEM + ML-DSA)", color="#F44336")

    plt.xlabel("Financial Domains", fontweight="bold")
    plt.ylabel("Simulated TTFB Latency (ms)", fontweight="bold")
    plt.title(f"Impact of PQC on TLS Latency (loss={PACKET_LOSS_RATE*100:.1f}%, iw={IW}, payload={PQC_HYBRID_SIZE}B)", fontweight="bold")
    plt.xticks([i + bar_width / 2 for i in idx], domains, rotation=45, ha="right")
    plt.legend()
    plt.tight_layout()
    plt.savefig(img_filename, dpi=300)
    return True

def run_research(target_domains: list[str]) -> None:
    if not target_domains:
        print("[-] No domains provided. Usage: python scripts/pqc_simulator.py domain1.com domain2.com")
        sys.exit(1)

    print(f"[*] Starting PQC network simulation on {len(target_domains)} domains...")
    print(f"[*] Packet loss: {PACKET_LOSS_RATE*100:.1f}% | PQC payload: {PQC_HYBRID_SIZE} bytes")

    results: list[dict[str, Any]] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_domain = {executor.submit(profile_domain, d): d for d in target_domains}
        for future in concurrent.futures.as_completed(future_to_domain):
            data = future.result()
            if data["Status"] == "Success":
                rtt = float(data["Base_RTT_ms"])
                class_sim = simulate_latency(rtt, CLASSICAL_SIZE, PACKET_LOSS_RATE)
                pqc_sim = simulate_latency(rtt, PQC_HYBRID_SIZE, PACKET_LOSS_RATE)

                data["Simulated_Classical_ms"] = class_sim["total_latency_ms"]
                data["Simulated_PQC_ms"] = pqc_sim["total_latency_ms"]
                data["Latency_Increase_%"] = round(((pqc_sim["total_latency_ms"] / class_sim["total_latency_ms"]) - 1) * 100, 2)
                data["PQC_Segments"] = int(pqc_sim["segments"])
                data["PQC_Extra_Flights"] = int(pqc_sim["extra_flights"])
                data["PQC_Tloss_ms"] = pqc_sim["t_loss_ms"]

                print(
                    f"[+] {data['Domain']}: RTT {rtt:.2f}ms -> PQC {data['Simulated_PQC_ms']}ms "
                    f"(+{data['Latency_Increase_%']}%)"
                )
            else:
                print(f"[-] {data['Domain']} failed: {data['Status']}")
            results.append(data)

    valid_results = [r for r in results if r["Status"] == "Success"]
    if not valid_results:
        print("[-] No successful domain profiles; nothing to export.")
        return

    csv_filename = "pqc_simulation_results.csv"
    _export_csv(valid_results, csv_filename)
    print(f"[*] Raw data saved: {csv_filename}")

    img_filename = "pqc_latency_chart.png"
    if _export_plot(valid_results, img_filename):
        print(f"[*] High-res chart saved: {img_filename}")
    else:
        print("[!] matplotlib not available. Skipped chart generation.")

    avg_increase = sum(r["Latency_Increase_%"] for r in valid_results) / len(valid_results)
    representative = valid_results[0]

    print("\n" + "=" * 60)
    print("RESEARCH SUMMARY")
    print("=" * 60)
    print(f"Sample size: {len(valid_results)} domains")
    print(f"Average PQC latency increase: {avg_increase:.2f}%")
    print(f"Representative extra flights: {representative['PQC_Extra_Flights']}")
    print("Conclusion: Without tuning IW or reducing cert-chain payload, PQC migration can materially increase TTFB on lossy networks.")

if __name__ == "__main__":
    run_research(sys.argv[1:])
