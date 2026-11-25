"""Bounded localhost-only proxy benchmark; set a descriptive label as argument."""
import concurrent.futures
import http.client
import json
import statistics
import sys
import time

PATH = "http://127.0.0.1:18080/global-a?user_id=old&keep=query"
BODY = '{"user_id":"old","fixture":{"count":7,"keep":"safe"},"other":11}'


def one(_=None):
    start = time.perf_counter()
    connection = http.client.HTTPConnection("127.0.0.1", 8080, timeout=10)
    connection.request("POST", PATH, BODY, {"Content-Type": "application/json"})
    response = connection.getresponse()
    raw = response.read()
    elapsed = (time.perf_counter() - start) * 1000
    connection.close()
    if response.status != 200:
        raise RuntimeError(f"unexpected status {response.status}")
    return elapsed, json.loads(raw)


for _ in range(5):
    one()
samples = [one() for _ in range(30)]
latencies = sorted(item[0] for item in samples)
start = time.perf_counter()
with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
    parallel = list(pool.map(one, range(20)))
wall = time.perf_counter() - start
print(json.dumps({
    "label": sys.argv[1] if len(sys.argv) > 1 else "unlabeled",
    "warmups": 5, "serial_samples": len(samples), "concurrency": 4,
    "parallel_requests": len(parallel),
    "median_ms": round(statistics.median(latencies), 3),
    "p95_ms": round(latencies[28], 3),
    "max_ms": round(latencies[-1], 3),
    "parallel_throughput_per_s": round(len(parallel) / wall, 2),
    "parallel_max_ms": round(max(item[0] for item in parallel), 3),
    "sample_result": samples[0][1],
}))
