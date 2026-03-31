import time

request_log = {}


def compute_risk(ip):
    now = time.time()

    if ip not in request_log:
        request_log[ip] = []

    request_log[ip].append(now)

    # keep last 10 sec
    request_log[ip] = [
        t for t in request_log[ip] if now - t < 10
    ]

    freq = len(request_log[ip])

    if freq < 5:
        return 0.1
    elif freq < 15:
        return 0.5
    else:
        return 0.9


def decide_action(risk):
    if risk < 0.3:
        return "allow"
    elif risk < 0.7:
        return "throttle"
    else:
        return "block"