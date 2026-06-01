"""
tests/test_lab.py
─────────────────
Tests de integración contra el laboratorio vulnerable.
Requiere: docker-compose -f tests/docker-compose-lab.yml up -d
"""
import socket
import sys
import urllib.request


def check_port(host: str, port: int, label: str = "") -> bool:
    """Verifica si un puerto TCP está abierto."""
    try:
        s = socket.create_connection((host, port), timeout=3)
        s.close()
        status = f"  OPEN  {label} — {host}:{port}"
        print(f"  \033[32m✓\033[0m {status}")
        return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        print(f"  \033[31m✗\033[0m CLOSED {label} — {host}:{port}")
        return False


def check_http(url: str, expected_code: int = 200, label: str = "") -> bool:
    """Verifica que una URL devuelva el código esperado."""
    try:
        req = urllib.request.Request(url)
        resp = urllib.request.urlopen(req, timeout=5)
        code = resp.status
        ok = code == expected_code
        icon = "\033[32m✓\033[0m" if ok else "\033[33m⚠\033[0m"
        print(f"  {icon} HTTP {code} {label} — {url}")
        return ok
    except Exception as e:
        print(f"  \033[31m✗\033[0m ERROR {label} — {url}: {e}")
        return False


def main():
    host = "127.0.0.1"
    results = []

    print("\n" + "=" * 60)
    print("  ARGOS LAB VALIDATION")
    print("=" * 60 + "\n")

    print("1. Apache 2.4.49 @ 8080")
    r1 = check_port(host, 8080, "Apache")
    r1 &= check_http(f"http://{host}:8080/", 200, "index")
    results.append(r1)

    print("\n2. SSH weak credentials @ 2222")
    r2 = check_port(host, 2222, "SSH (admin:admin123)")
    results.append(r2)

    print("\n3. MySQL 5.7 no auth @ 3306")
    r3 = check_port(host, 3306, "MySQL (root, no pass)")
    results.append(r3)

    print("\n4. FTP anonymous @ 2121")
    r4 = check_port(host, 2121, "FTP (anonymous)")
    results.append(r4)

    print("\n5. Redis no auth @ 6379")
    r5 = check_port(host, 6379, "Redis (no pass)")
    results.append(r5)

    print("\n6. DVWA @ 8888")
    r6 = check_http(f"http://{host}:8888/", 200, "DVWA") or check_http(f"http://{host}:8888/", 302, "DVWA")
    results.append(r6)

    passed = sum(results)
    total = len(results)
    print(f"\n{'=' * 60}")
    print(f"  Result: {passed}/{total} targets reachable")
    print(f"{'=' * 60}\n")

    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
