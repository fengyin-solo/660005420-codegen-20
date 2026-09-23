import re, json, math, time, random
import numpy as np
from collections import defaultdict, Counter
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="Log Anomaly Detector")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

LOG_TEMPLATES = {
    "nginx": {
        "pattern": r'(?P<timestamp>\S+ \+\d{4}) (?P<source>\S+) (?P<level>\w+) (?P<message>.+)',
        "sources": ["nginx", "api-gateway", "load-balancer"],
        "generator": lambda: {
            "timestamp": f"{random.randint(1,28):02d}/{'Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec'.split()[random.randint(0,11)]}/{2024}:{random.randint(0,23):02d}:{random.randint(0,59):02d}:{random.randint(0,59):02d} +0000",
            "source": random.choice(["nginx", "api-gateway", "load-balancer"]),
            "level": random.choices(["INFO", "WARN", "ERROR", "DEBUG"], weights=[50, 15, 5, 30])[0],
            "message": random.choice([
                'GET /api/users 200 0.032s', 'POST /api/orders 201 0.145s', 'GET /api/products 304 0.008s',
                'GET /static/main.js 200 0.002s', 'POST /api/login 401 0.023s', 'GET /admin 403 0.005s',
                'GET /api/health 200 0.001s', 'GET /api/orders?page=2 200 0.056s', 'connection timeout upstream',
                'SSL handshake failed', 'worker process exited on signal 9', 'upstream server unavailable'
            ])
        }
    },
    "apache": {
        "pattern": r'\[(?P<timestamp>[^\]]+)\] \[(?P<level>\w+)\] \[(?P<source>\S+)\] (?P<message>.+)',
        "sources": ["httpd", "mod_ssl", "mod_rewrite"],
        "generator": lambda: {
            "timestamp": f"{'Sun Mon Tue Wed Thu Fri Sat'.split()[random.randint(0,6)]} {'Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec'.split()[random.randint(0,11)]} {random.randint(1,28):02d} {random.randint(0,23):02d}:{random.randint(0,59):02d}:{random.randint(0,59):02d} {2024}",
            "source": random.choice(["httpd", "mod_ssl", "mod_rewrite"]),
            "level": random.choices(["notice", "warn", "error", "info"], weights=[40, 15, 5, 40])[0],
            "message": random.choice(["server configured", "caught SIGTERM", "resuming normal ops", "request exceeded limit",
                        "file does not exist", "client denied by server", "Invalid method in request"])
        }
    },
    "json_app": {
        "pattern": None,
        "sources": ["user-service", "order-service", "payment-service", "auth-service"],
        "generator": lambda: {
            "timestamp": f"{2024}-{random.randint(1,12):02d}-{random.randint(1,28):02d}T{random.randint(0,23):02d}:{random.randint(0,59):02d}:{random.randint(0,59):02d}.{random.randint(0,999):03d}Z",
            "source": random.choice(["user-service", "order-service", "payment-service", "auth-service"]),
            "level": random.choices(["INFO", "WARN", "ERROR", "DEBUG"], weights=[45, 20, 5, 30])[0],
            "message": random.choice([
                'User login successful user_id=10' + str(random.randint(100, 999)),
                'Order created order_id=ORD-' + str(random.randint(10000, 99999)),
                'Payment processed amount=' + str(random.randint(10, 999)),
                'Database connection pool exhausted',
                'Cache miss for key user_session_' + str(random.randint(100, 999)),
                'Circuit breaker opened for service payment',
                'Request latency exceeds threshold 5000ms',
                'NullPointerException at com.app.controller.UserController.getProfile'
            ])
        }
    },
    "custom": {
        "pattern": None,
        "sources": ["cron", "systemd", "kernel", "docker"],
        "generator": lambda: {
            "timestamp": str(int(time.time() - random.randint(0, 86400))),
            "source": random.choice(["cron", "systemd", "kernel", "docker"]),
            "level": random.choices(["info", "warning", "error", "debug"], weights=[40, 20, 5, 35])[0],
            "message": random.choice(["OOM killer invoked", "disk usage above 90%", "container restarted", "NTP sync lost",
                        "process oom_score_adj=500", "firewall rule updated", "mount point not found"])
        }
    }
}

# 每种日志类型可能上报的全部来源（用于计算在线率）
SOURCE_ROSTER = {
    "nginx": ["nginx", "api-gateway", "load-balancer"],
    "apache": ["httpd", "mod_ssl", "mod_rewrite"],
    "json_app": ["user-service", "order-service", "payment-service", "auth-service"],
    "custom": ["cron", "systemd", "kernel", "docker"],
}


def build_raw(log_type, e):
    """按日志类型生成对应的原始报文，保证与解析器正则一致。"""
    if log_type == "nginx":
        return f"{e['timestamp']} {e['source']} {e['level']} {e['message']}"
    if log_type == "json_app":
        return json.dumps({
            "ts": e["timestamp"], "level": e["level"],
            "source": e["source"], "msg": e["message"]
        }, ensure_ascii=False)
    if log_type == "custom":
        return f"{e['timestamp']} {e['level']} {e['source']} {e['message']}"
    # apache 统一的 [时间] [级别] [来源] 消息 报文
    return f"[{e['timestamp']}] [{e['level']}] [{e['source']}] {e['message']}"


CORRUPT_PREFIX = "##MALFORMED## "


def make_corrupt(raw):
    """模拟采集/传输异常导致的残缺报文：截断并加上乱码前缀，使其无法被解析。"""
    cut = max(8, int(len(raw) * random.uniform(0.4, 0.7)))
    return CORRUPT_PREFIX + raw[:cut]


def parse_raw(log_type, raw):
    """按类型解析原始报文，解析成功返回 True。统计“解析成功率”时与页面口径一致。"""
    if isinstance(raw, dict):
        return True
    if not isinstance(raw, str) or raw.startswith(CORRUPT_PREFIX):
        return False
    pattern = LOG_TEMPLATES.get(log_type, LOG_TEMPLATES["nginx"]).get("pattern")
    if pattern is None:
        if log_type == "json_app":
            try:
                obj = json.loads(raw)
                return isinstance(obj, dict) and all(k in obj for k in ("ts", "level", "source", "msg"))
            except (ValueError, TypeError):
                return False
        # custom: <unix秒> <级别> <来源> <消息>
        return bool(re.fullmatch(r"\d{10} \S+ \S+ .+", raw))
    return re.fullmatch(pattern, raw, re.DOTALL) is not None


class GenerateRequest(BaseModel):
    type: str = "nginx"
    count: int = 1000


class DetectRequest(BaseModel):
    logs: list
    rules: list = []
    query: str = ""
    type: str = "nginx"


@app.post("/api/generate")
def generate_logs(req: GenerateRequest):
    tmpl = LOG_TEMPLATES.get(req.type, LOG_TEMPLATES["nginx"])
    logs = []
    for i in range(req.count):
        entry = tmpl["generator"]()
        raw = build_raw(req.type, entry)
        # 约 6% 的报文在采集/传输过程中损坏，无法被解析
        if random.random() < 0.06:
            raw = make_corrupt(raw)
        logs.append({
            "id": i + 1,
            "timestamp": entry["timestamp"],
            "level": entry["level"],
            "source": entry["source"],
            "message": entry["message"],
            "raw": raw
        })
    return analyze_logs(logs, [], "", req.type)


@app.post("/api/detect")
def detect_anomalies(req: DetectRequest):
    return analyze_logs(req.logs, req.rules, req.query, req.type)


def analyze_logs(logs_data, rules, query, log_type="nginx"):
    logs = logs_data
    n = len(logs)
    if n == 0:
        return {
            "logs": [], "windows": [], "anomalies": [], "alerts": [],
            "totalLogs": 0, "totalParsed": 0,
            "sourceRoster": SOURCE_ROSTER.get(log_type, SOURCE_ROSTER["nginx"]),
            "logType": log_type
        }
    parsed_flags = [parse_raw(log_type, l.get("raw")) for l in logs]

    # Time windows (1min each for demonstration)
    window_size = 20
    windows = []
    for i in range(0, n, window_size):
        chunk = logs[i:i + window_size]
        levels = Counter(l["level"] for l in chunk)
        sources = Counter(l["source"] for l in chunk)
        parsed = sum(1 for j in range(i, min(i + window_size, n)) if parsed_flags[j])
        windows.append({
            "start": i, "end": min(i + window_size, n),
            "count": len(chunk),
            "parsed": parsed,
            "levels": dict(levels),
            "sources": dict(sources),
            "firstTimestamp": chunk[0].get("timestamp", "") if chunk else "",
            "lastTimestamp": chunk[-1].get("timestamp", "") if chunk else ""
        })

    # 3-sigma + IQR anomaly detection
    counts = [w["count"] for w in windows]
    mean = float(np.mean(counts))
    std = float(np.std(counts)) if len(counts) > 1 else 1.0
    q1 = float(np.percentile(counts, 25)) if len(counts) > 3 else mean - std
    q3 = float(np.percentile(counts, 75)) if len(counts) > 3 else mean + std
    iqr = q3 - q1 if q3 > q1 else 1.0

    anomalies = []
    for i, w in enumerate(windows):
        sigma_score = abs(w["count"] - mean) / max(std, 1e-5)
        iqr_low = q1 - 1.5 * iqr
        iqr_high = q3 + 1.5 * iqr
        iqr_score = 0.0
        if w["count"] < iqr_low or w["count"] > iqr_high:
            iqr_score = min(10.0, abs(w["count"] - (mean)) / max(iqr, 1e-5))
        anomalies.append({
            "windowIndex": i,
            "sigmaScore": round(sigma_score, 2),
            "iqrScore": round(iqr_score, 2),
            "isAnomaly": sigma_score > 2.5 or iqr_score > 3.0,
            "timestamp": logs[i * window_size]["timestamp"] if i * window_size < len(logs) else ""
        })

    # Alert rules
    alerts = []
    for i, rule in enumerate(rules):
        rule = rule if isinstance(rule, dict) else {}
        for w in windows:
            if rule.get("type") == "level" and w["levels"].get("ERROR", 0) > rule.get("threshold", 5):
                alerts.append({
                    "id": len(alerts) + 1, "ruleName": rule.get("name", "高频ERROR"),
                    "severity": "high", "message": f"窗口{w['start']}内ERROR日志{w['levels']['ERROR']}条超过阈值{rule.get('threshold',5)}",
                    "timestamp": time.strftime("%H:%M:%S")
                })
            if rule.get("type") == "count" and w["count"] > rule.get("threshold", 200):
                alerts.append({
                    "id": len(alerts) + 1, "ruleName": rule.get("name", "异常流量"),
                    "severity": "medium", "message": f"窗口{w['start']}日志量{w['count']}超过阈值",
                    "timestamp": time.strftime("%H:%M:%S")
                })

    # Full-text search with TF-IDF
    if query:
        query_terms = query.lower().split()
        scored = []
        for log in logs:
            raw_lower = log["raw"].lower()
            score = sum(1 for t in query_terms if t in raw_lower)
            if score > 0:
                scored.append((score, log))
        logs = [l for _, l in sorted(scored, key=lambda x: x[0], reverse=True)]

    # Add non-rule alerts for high anomaly windows  
    for a in anomalies:
        if a["isAnomaly"]:
            alerts.append({
                "id": len(alerts) + 1, "ruleName": "统计异常检测",
                "severity": "critical" if a["sigmaScore"] > 4 else "high",
                "message": f"窗口{a['windowIndex']}: 3-sigma={a['sigmaScore']}, IQR={a['iqrScore']}",
                "timestamp": a["timestamp"]
            })

    return {
        "logs": logs[:200],
        "windows": windows,
        "anomalies": anomalies,
        "alerts": alerts[:20],
        "totalLogs": n,
        "totalParsed": sum(parsed_flags),
        "sourceRoster": SOURCE_ROSTER.get(log_type, SOURCE_ROSTER["nginx"]),
        "logType": log_type
    }