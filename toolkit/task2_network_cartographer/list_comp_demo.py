import random
import time
from concurrent.futures import ThreadPoolExecutor

from gateway_scanner import check_port

target_host = "172.16.19.101"
ports = [21, 22, 80, 9999]


def slow_job(n):
    time.sleep(0.2)
    return n * 10


def variable_job(n):
    time.sleep(random.uniform(0, 0.3))
    return n


with ThreadPoolExecutor(max_workers=4) as executor:
    futures = {executor.submit(variable_job, i): i for i in range(1, 6)}

    results = []
    for future, port in futures.items():
        results.append(future.result())
        print(f"port {port}: {future.result()}")


print("Collected:", results)
print("Sorted:   ", sorted(results))
