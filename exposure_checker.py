import csv
import ipaddress
import json
import socket
from datetime import datetime

import requests

APPROVED_TARGETS = ["127.0.0.1"]
APPROVED_PORTS = [18080, 19090, 20001, 20002]

HTTP_PORT = 18080
BANNER_PORTS = [19090, 20001]
TIMEOUT = 2


def load_lines(filename):
    try:
        with open(filename, "r", encoding="utf-8") as file:
            return [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        print(f"[ERROR] File not found: {filename}")
    except (OSError, UnicodeDecodeError) as error:
        print(f"[ERROR] Could not read {filename}: {error}")
    return []


def validate_targets(lines):
    targets = []

    for value in lines:
        try:
            ipaddress.ip_address(value)
        except ValueError:
            print(f"[REJECTED] Not a valid IP address: {value}")
            continue

        if value not in APPROVED_TARGETS:
            print(f"[REJECTED] Target is outside the approved local scope: {value}")
        elif value not in targets:
            targets.append(value)

    return targets


def validate_ports(lines):
    ports = []

    for value in lines:
        try:
            port = int(value)
        except ValueError:
            print(f"[REJECTED] Port is not a number: {value}")
            continue

        if port < 1 or port > 65535:
            print(f"[REJECTED] Port is out of range (1-65535): {port}")
        elif port not in APPROVED_PORTS:
            print(f"[REJECTED] Port is not approved: {port}")
        elif port not in ports:
            ports.append(port)

    return ports


def check_port(host, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(TIMEOUT)
            result = sock.connect_ex((host, port))
    except OSError as error:
        print(f"[ERROR] Could not check {host}:{port} - {error}")
        return "ERROR"

    if result == 0:
        return "OPEN"
    return "CLOSED"


def grab_banner(host, port):
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            banner = sock.recv(1024)
    except socket.timeout:
        return "Banner request timed out"
    except OSError as error:
        return f"Could not grab banner: {error}"

    if not banner:
        return "Connected but no banner was sent"
    return banner.decode("utf-8", errors="replace").strip()


def check_http(host, port):
    url = f"http://{host}:{port}/"

    try:
        response = requests.get(url, timeout=TIMEOUT, allow_redirects=False)
    except requests.exceptions.Timeout:
        return "HTTP request timed out"
    except requests.exceptions.RequestException as error:
        return f"HTTP request failed: {error}"

    content_type = response.headers.get("Content-Type", "Not provided")
    server = response.headers.get("Server", "Not provided")
    return (f"Status: {response.status_code} | Content-Type: {content_type} | "
            f"Server: {server} | Body: {response.text.strip()[:100]}")


def interpret_result(state, port):
    if state == "ERROR":
        return "UNKNOWN", "The check failed, Investigate and try again."

    if state == "CLOSED":
        return "INFO", "No TCP connection, No service was reachable at the time of the check."

    if port == HTTP_PORT:
        return "REVIEW", ("HTTP service is listening. Confirm it is expected. Plain HTTP is "
                          "not encrypted and response headers may reveal software details.")

    if port in BANNER_PORTS:
        return "REVIEW", ("TCP service is listening. Confirm it is expected and check "
                          "whether its banner reveals unnecessary information.")

    return "INVESTIGATE", ("The test script does not open this port. Identify the process "
                           "using it and confirm whether it is authorised.")


def analyse_targets(targets, ports):
    results = []

    for host in targets:
        for port in ports:
            state = check_port(host, port)
            evidence = "None collected"

            if state == "OPEN":
                if port == HTTP_PORT:
                    evidence = check_http(host, port)
                elif port in BANNER_PORTS:
                    evidence = grab_banner(host, port)

            priority, explanation = interpret_result(state, port)

            results.append({
                "host": host,
                "port": port,
                "state": state,
                "priority": priority,
                "evidence": evidence,
                "interpretation": explanation,
            })

    return results


def summarise(results):
    summary = {"OPEN": 0, "CLOSED": 0, "ERROR": 0}

    for result in results:
        summary[result["state"]] += 1

    return summary


def build_report(results, summary, scan_time):
    lines = [
        "LOCAL NETWORK EXPOSURE REPORT",
        "=" * 70,
        f"Scan time: {scan_time}",
        f"Ports checked: {len(results)}",
        f"Open: {summary['OPEN']} | Closed: {summary['CLOSED']} | Errors: {summary['ERROR']}",
    ]

    for result in results:
        lines.append("-" * 70)
        lines.append(f"{result['host']}:{result['port']}  {result['state']}  [{result['priority']}]")
        lines.append(f"  Evidence: {result['evidence']}")
        lines.append(f"  Interpretation: {result['interpretation']}")

    if summary["OPEN"] == 0:
        lines.append("No open ports found. Check that local_test_services.py is still running.")

    return "\n".join(lines)


def save_reports(report, results, summary, scan_time):
    try:
        with open("exposure_report.txt", "w", encoding="utf-8") as file:
            file.write(report + "\n")

        with open("exposure_report.csv", "w", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(file, fieldnames=list(results[0].keys()))
            writer.writeheader()
            writer.writerows(results)

        with open("exposure_report.json", "w", encoding="utf-8") as file:
            data = {"scan_time": scan_time, "summary": summary, "results": results}
            json.dump(data, file, indent=4)
    except OSError as error:
        print(f"[ERROR] Could not save the reports: {error}")
    else:
        print("\nSaved: exposure_report.txt, exposure_report.csv, exposure_report.json")


def main():
    targets = validate_targets(load_lines("targets.txt"))
    ports = validate_ports(load_lines("ports.txt"))

    if not targets or not ports:
        print("[STOPPED] At least one approved target and one approved port are required.")
        return

    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    results = analyse_targets(targets, ports)
    summary = summarise(results)
    report = build_report(results, summary, scan_time)

    print(report)
    save_reports(report, results, summary, scan_time)


if __name__ == "__main__":
    main()
