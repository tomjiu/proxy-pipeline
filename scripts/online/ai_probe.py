#!/usr/bin/env python3
"""
节点质量评分 v3 —— 多维连通性画像

设计依据（实测 + 用户经验）：
  - "Grok 不跳挑战页 = IP 好"        → 挑战页出现与否是强信号
  - "GPT 过不去 = IP 差到一定程度"    → ChatGPT 451/硬封锁是强负面
  - 不能只看 AI，YouTube/Netflix 也是有效判据

评分维度：
  A. 风控严格的服务（权重高）
     - grok.com        无挑战直接 200 = 极佳
     - chatgpt.com     200 = 极佳；挑战 = 中性；451/封锁 = 差
  B. 地区/版权敏感
     - netflix.com     200 = IP 未被标记为机房
     - youtube.com     200 = Google 未拦截
  C. 基础连通
     - google.com      200 = 基础可用

分档（修正版）：
  tier S  — 至少 2 个高权重服务直接通过（无挑战）
  tier A  — 能通过 1 个，或有服务返回挑战页
  tier B  — 全部失败/封锁
  tier X  — 被明确地区封锁（451 等）

输出：每个服务的详细判定 + 综合评分
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import ProxyHandler, build_opener

ROOT = Path(__file__).resolve().parents[2]
DIST_CLEAN = ROOT / "dist" / "clean"
CONTROLLER = "127.0.0.1:9090"
MIXED_PORT = 7890
SELECT_GROUP = "PROXY"

# ── 挑战页 / 封锁特征 ──
CHALLENGE_PATTERNS = [
    r"just a moment", r"cf-chl-", r"challenge-platform",
    r"checking your browser", r"enable javascript and cookies",
    r"ddos protection by", r"__cf_chl", r"turnstile",
    r"verifying you are human", r"attention required",
]
GEOBLOCK_PATTERNS = [
    r"not available in your (country|region)", r"unavailable in your region",
    r"isn't available in your country", r"unsupported country",
    r"not currently supported in", r"无法在你", r"blocked in your",
]

# ── 服务定义 ──
# weight: 权重（越高越能区分 IP 质量）
# expect: 正常页面的特征词
SERVICES = {
    "grok": {
        "url": "https://grok.com/",
        "weight": 3,
        "expect": [r"grok"],
        "note": "无挑战=IP质量好",
    },
    "chatgpt": {
        "url": "https://chatgpt.com/",
        "weight": 3,
        "expect": [r"chatgpt", r"openai"],
        "note": "200=极佳 / 挑战=中性(CF对机房默认) / 451=差",
    },
    "netflix": {
        "url": "https://www.netflix.com/",
        "weight": 2,
        "expect": [r"netflix"],
        "note": "对机房IP敏感",
    },
    "youtube": {
        "url": "https://www.youtube.com/",
        "weight": 2,
        "expect": [r"youtube"],
        "note": "Google系风控",
    },
    "gemini": {
        "url": "https://gemini.google.com/",
        "weight": 2,
        "expect": [r"gemini", r"google"],
        "note": "Google 不太拦",
    },
    "google": {
        "url": "https://www.google.com/",
        "weight": 1,
        "expect": [r"google"],
        "note": "基础连通",
    },
    "claude": {
        "url": "https://claude.ai/",
        "weight": 3,
        "expect": [r"claude", r"anthropic"],
        "note": "风控严格",
    },
}

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")


def load_json(path: Path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def write_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def find_mihomo() -> str:
    env_path = os.environ.get("MIHOMO_BIN")
    if env_path and Path(env_path).exists():
        return env_path
    for n in ("mihomo", "mihomo.exe", "mihomo-x.exe", "verge-mihomo.exe"):
        p = ROOT / "bin" / n
        if p.exists():
            return str(p)
    for n in ("mihomo", "mihomo.exe"):
        w = shutil.which(n)
        if w:
            return w
    raise SystemExit("mihomo not found (./bin/mihomo or MIHOMO_BIN)")


def wait_api(proc: subprocess.Popen, timeout: float = 90) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            raise SystemExit(f"mihomo exited code={proc.returncode}")
        try:
            urllib.request.urlopen(f"http://{CONTROLLER}/version", timeout=2).read()
            return
        except Exception:
            time.sleep(0.5)
    raise SystemExit("mihomo API not ready")


def select_proxy(name: str) -> bool:
    q = urllib.parse.quote(SELECT_GROUP, safe="")
    req = urllib.request.Request(
        f"http://{CONTROLLER}/proxies/{q}",
        data=json.dumps({"name": name}).encode(), method="PUT",
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status in (200, 204)
    except Exception:
        return False


def classify(body: str, svc: str) -> tuple[str, str]:
    low = body.lower()
    for p in CHALLENGE_PATTERNS:
        if re.search(p, low):
            return "challenge", f"challenge:{p}"
    for p in GEOBLOCK_PATTERNS:
        if re.search(p, low):
            return "geoblocked", f"geo:{p}"
    spec = SERVICES[svc]
    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    title = (m.group(1).strip() if m else "").lower()
    for p in spec["expect"]:
        if re.search(p, title) or re.search(p, low):
            return "ok", f"title:{title[:35]}"
    if title:
        return "other", f"title:{title[:35]}"
    return "unknown", f"len={len(body)}"


def probe_one(opener, svc: str, spec: dict, timeout: float) -> dict:
    try:
        req = urllib.request.Request(spec["url"], headers={
            "User-Agent": UA,
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }, method="GET")
        with opener.open(req, timeout=timeout) as resp:
            code = resp.status
            body = resp.read(32768).decode("utf-8", errors="ignore")
        v, r = classify(body, svc)
        return {"code": code, "verdict": v, "reason": r}
    except urllib.error.HTTPError as e:
        try:
            body = e.read(32768).decode("utf-8", errors="ignore")
        except Exception:
            body = ""
        v, r = classify(body, svc)
        if v in ("unknown", "other"):
            if e.code == 451:
                v, r = "geoblocked", "http_451"
            elif e.code in (403, 429):
                v, r = "challenge", f"http_{e.code}"
            else:
                v, r = f"http_{e.code}", f"http_{e.code}"
        return {"code": e.code, "verdict": v, "reason": r}
    except urllib.error.URLError as e:
        rr = str(getattr(e, "reason", e))
        return {"code": None,
                "verdict": "timeout" if "timed out" in rr.lower() else "connect_fail",
                "reason": rr[:60]}
    except Exception as e:
        return {"code": None, "verdict": "error", "reason": type(e).__name__}


def score_and_tier(detail: dict) -> tuple[int, str, dict]:
    """
    计算质量分并分档。

    评分规则：
      ok        → +weight          （无挑战直接通过，最优）
      challenge → +weight * 0.3    （能连上但有验证，中性偏好）
      other     → +weight * 0.2    （有响应但非预期页）
      geoblocked / http_451 → -weight   （明确封锁，负面）
      timeout / connect_fail / error → 0

    分档（收紧版 —— 基于"Grok 不挑战 = IP 好"的判据）：

      tier S (优质)  必须满足以下之一：
        a) grok 无挑战通过（xAI 风控认可，最强信号）
        b) chatgpt 无挑战 200（住宅 IP 级别）
        c) 通过 >= 3 个服务且包含至少 1 个高权重(>=3)

      tier A (可用)  能连上，但都走挑战页/未达 S 标准：
        - 通过 >= 1 个服务，或
        - 有 challenge（IP 未被硬封）

      tier B (一般)  全部失败（连不上）

      tier X (差)    被明确地区封锁（451）
    """
    score = 0
    passed, challenged, blocked = [], [], []
    for svc, spec in SERVICES.items():
        d = detail.get(svc) or {}
        v = d.get("verdict")
        w = spec["weight"]
        if v == "ok":
            score += w
            passed.append(svc)
        elif v == "challenge":
            score += w * 0.3
            challenged.append(svc)
        elif v == "other":
            score += w * 0.2
        elif v in ("geoblocked", "http_451"):
            score -= w
            blocked.append(svc)

    passed_set = set(passed)
    high_weight_passed = [s for s in passed if SERVICES[s]["weight"] >= 3]

    # ── 分档 ──
    is_s = (
        "grok" in passed_set                      # a) Grok 无挑战（最强信号）
        or "chatgpt" in passed_set                # b) ChatGPT 直接 200（住宅 IP）
        or (len(passed) >= 3 and high_weight_passed)   # c) 广度过关且有高权重
    )

    if is_s:
        tier = "S"
    elif passed or challenged:
        tier = "A"
    elif blocked:
        tier = "X"
    else:
        tier = "B"

    # 判定理由（便于人工核查）
    if "grok" in passed_set:
        why = "grok_no_challenge"
    elif "chatgpt" in passed_set:
        why = "chatgpt_direct_200"
    elif is_s:
        why = f"broad_pass({len(passed)})"
    elif passed:
        why = f"partial_pass({','.join(passed[:3])})"
    elif challenged:
        why = f"challenge_only({','.join(challenged[:3])})"
    elif blocked:
        why = f"blocked({','.join(blocked[:3])})"
    else:
        why = "all_failed"

    return round(score, 1), tier, {
        "passed": passed, "challenged": challenged, "blocked": blocked,
        "why": why, "high_weight_passed": high_weight_passed,
    }


def extract_names(text: str) -> list[str]:
    m = re.search(r"(?m)^proxies:\s*$", text)
    if not m:
        return []
    rest = text[m.end():]
    end = re.search(r"(?m)^proxy-groups:\s*$", rest)
    body = rest[: end.start()] if end else rest
    names = []
    for ch in re.split(r"(?m)^  - name: ", body)[1:]:
        n = ch.split("\n", 1)[0].strip().strip('"').replace('\\"', '"')
        if n:
            names.append(n)
    return names


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", type=Path, default=DIST_CLEAN / "clash.yaml")
    ap.add_argument("--mode", choices=("full", "incremental"), default="incremental")
    ap.add_argument("--limit", type=int, default=150)
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--pause", type=float, default=0.05)
    ap.add_argument("--deadline-s", type=int, default=1200,
                    help="总时间预算（秒），超时则优雅停止并保存已测结果；0=不限")
    ap.add_argument("--out-clash", type=Path,
                    help="同时生成仅 tier S 的 clash.yaml")
    ap.add_argument("--min-tier", choices=("S", "A"), default="S",
                    help="生成过滤订阅时保留的最低档")
    args = ap.parse_args()

    if not args.input.exists():
        print(f"missing {args.input}")
        return 1

    text = args.input.read_text(encoding="utf-8", errors="ignore")
    names = extract_names(text)
    print(f"[q] nodes: {len(names)}")
    if not names:
        return 1

    db = load_json(DIST_CLEAN / "alive.json", {"nodes": {}})
    now = datetime.now(timezone.utc).isoformat()
    q_by_name = db.get("quality_by_name") or {}

    if args.mode == "full":
        todo = names
    else:
        todo = [n for n in names if not (q_by_name.get(n) or {}).get("checked_at")]

    # ── 时间预算保护 ──
    # 实测：并发探测下约 6-7 秒/节点（7 个服务并行）
    # 用保守估计 12s/节点（含慢节点），避免高估导致截断过多
    est_per_node = 12.0
    if args.deadline_s and args.deadline_s > 0:
        budget_nodes = int(args.deadline_s / est_per_node)
        if budget_nodes < len(todo):
            print(f"[q] time budget: {args.deadline_s}s / ~{est_per_node}s per node "
                  f"→ cap {budget_nodes} nodes")
            todo = todo[:budget_nodes]

    if args.limit and len(todo) > args.limit:
        print(f"[q] limit {len(todo)} -> {args.limit}")
        todo = todo[: args.limit]

    print(f"[q] probing {len(todo)} (mode={args.mode})")
    if not todo:
        print("[q] nothing to do")
        return 0

    tmp = ROOT / ".mihomo-q"
    if tmp.exists():
        shutil.rmtree(tmp, ignore_errors=True)
    tmp.mkdir()

    cfg = text
    cfg = re.sub(r"(?m)^external-controller:.*$", f"external-controller: {CONTROLLER}", cfg)
    if "external-controller:" not in cfg:
        cfg = f"external-controller: {CONTROLLER}\n" + cfg
    cfg = re.sub(r"(?m)^log-level:.*$", "log-level: error", cfg)
    cfg = re.sub(r"(?m)^mixed-port:.*$", f"mixed-port: {MIXED_PORT}", cfg)
    if "mixed-port:" not in cfg:
        cfg = f"mixed-port: {MIXED_PORT}\n" + cfg
    cfg = re.sub(r"(?ms)^rules:.*$", "rules:\n  - MATCH,PROXY\n", cfg)
    if not re.search(r"(?m)^rules:", cfg):
        cfg += "\nrules:\n  - MATCH,PROXY\n"
    (tmp / "config.yaml").write_text(cfg, encoding="utf-8")

    logf = open(tmp / "log.txt", "w", encoding="utf-8")
    proc = subprocess.Popen([find_mihomo(), "-d", str(tmp), "-f", str(tmp / "config.yaml")],
                            stdout=logf, stderr=subprocess.STDOUT)
    try:
        wait_api(proc, 90)
        opener = build_opener(ProxyHandler({
            "http": f"http://127.0.0.1:{MIXED_PORT}",
            "https": f"http://127.0.0.1:{MIXED_PORT}",
        }))
        counts = {"S": 0, "A": 0, "B": 0, "X": 0, "select_failed": 0}
        t0 = time.time()
        deadline = (t0 + args.deadline_s) if args.deadline_s else None

        # ── 性能优化：两阶段 ──
        # 阶段1：串行切换节点（select API 是全局状态，不能并发）
        # 阶段2：对同一节点的多个服务并发探测（7 个请求并行）
        #   → 单节点耗时从 7×T 降到 ~T，理论提速 7 倍
        done = 0
        timed_out = False

        for name in todo:
            # 时间预算：超了就优雅退出（已测结果仍会保存）
            if deadline and time.time() > deadline:
                print(f"[q] ⏰ time budget reached ({args.deadline_s}s), "
                      f"stopping after {done}/{len(todo)}")
                timed_out = True
                break

            if not select_proxy(name):
                q_by_name[name] = {"tier": "B", "score": 0,
                                   "reason": "select_failed", "checked_at": now}
                counts["select_failed"] += 1
                done += 1
                continue

            # 并发探测该节点的所有服务
            detail = {}
            try:
                with ThreadPoolExecutor(max_workers=len(SERVICES)) as ex:
                    futs = {ex.submit(probe_one, opener, svc, spec, args.timeout): svc
                            for svc, spec in SERVICES.items()}
                    for fut in as_completed(futs):
                        svc = futs[fut]
                        try:
                            detail[svc] = fut.result()
                        except Exception as e:
                            detail[svc] = {"code": None, "verdict": "error",
                                           "reason": type(e).__name__}
            except Exception as e:
                print(f"  ! probe error for {name}: {e}")

            sc, tier, summary = score_and_tier(detail)
            q_by_name[name] = {
                "tier": tier, "score": sc, "checked_at": now,
                "summary": summary, "detail": detail,
                "elapsed_s": round(time.time() - t0, 1),
            }
            counts[tier] = counts.get(tier, 0) + 1
            done += 1
            if done % 10 == 0 or done == len(todo):
                rate = done / max(time.time() - t0, 0.1)
                eta = (len(todo) - done) / rate if rate > 0 else 0
                print(f"  … {done}/{len(todo)}  S={counts['S']} A={counts['A']} "
                      f"B={counts['B']} X={counts['X']}  "
                      f"({time.time()-t0:.0f}s, {rate:.2f} node/s, ETA {eta:.0f}s)")
            if args.pause:
                time.sleep(args.pause)

        if timed_out:
            print(f"[q] partial run: {done}/{len(todo)} probed")

        db["quality_by_name"] = q_by_name
        db["quality_updated_at"] = now
        db["quality_counts"] = counts
        write_json(DIST_CLEAN / "alive.json", db)

        s_nodes = sorted((n for n, v in q_by_name.items() if v.get("tier") == "S"),
                         key=lambda n: -q_by_name[n].get("score", 0))
        a_nodes = sorted((n for n, v in q_by_name.items() if v.get("tier") == "A"),
                         key=lambda n: -q_by_name[n].get("score", 0))
        write_json(DIST_CLEAN / "quality_tiers.json", {
            "updated_at": now,
            "counts": counts,
            "criteria": {
                "S": "Grok 无挑战通过 / ChatGPT 直接200 / 通过>=3个且含高权重",
                "A": "能连上（含挑战页），但未达 S 标准",
                "B": "全部失败（连不上）",
                "X": "被明确地区封锁（451）",
                "rationale": "Grok 不跳挑战页 = xAI 风控认可该 IP，是最强质量信号",
            },
            "services": {k: {"url": v["url"], "weight": v["weight"], "note": v["note"]}
                         for k, v in SERVICES.items()},
            "tier_S": s_nodes,
            "tier_A": a_nodes,
        })

        # 生成过滤后的订阅
        if args.out_clash:
            keep = set(s_nodes) if args.min_tier == "S" else set(s_nodes) | set(a_nodes)
            blocks = re.split(r"(?m)^  - name: ", text)
            head = blocks[0].rstrip()
            kept, dropped = [], 0
            for ch in blocks[1:]:
                nm = ch.split("\n", 1)[0].strip().strip('"').replace('\\"', '"')
                if nm in keep:
                    kept.append("  - name: " + ch.rstrip())
                else:
                    dropped += 1
            out = (head + "\n"
                   + f"# Quality-filtered subscription (tier >= {args.min_tier})\n"
                   + f"# updated: {now}\n"
                   + f"# kept {len(kept)} / dropped {dropped}\n"
                   + "\n".join(kept) + "\n")
            args.out_clash.parent.mkdir(parents=True, exist_ok=True)
            args.out_clash.write_text(out, encoding="utf-8")
            print(f"[q] wrote {args.out_clash} : {len(kept)} nodes (dropped {dropped})")

        report = {"at": now, "mode": args.mode, "probed": len(todo),
                  "counts": counts, "total_known": len(q_by_name)}
        write_json(DIST_CLEAN / "quality_report.json", report)
        print(json.dumps(report, ensure_ascii=False))
        return 0
    finally:
        try: logf.close()
        except Exception: pass
        proc.terminate()
        try: proc.wait(timeout=8)
        except Exception: proc.kill()


if __name__ == "__main__":
    raise SystemExit(main())
