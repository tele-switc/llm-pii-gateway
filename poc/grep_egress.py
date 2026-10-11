# -*- coding: utf-8 -*-
"""出口字节真值命中校验（§4.3）：在 pcap / 原始字节流中搜索全部植入真值。

用法：
  python poc/grep_egress.py --pcap egress.pcap --truth corpus/zh_v1.labels.jsonl

期望：命中数 = 0（对照组 trade_secret 允许整段命中——那正是要证明的漏洞）。

支持输入：
  - .pcap（纯字节扫描；不做协议重组，按"宁多报不漏报"的宽松匹配）
  - .txt/.log/.bin（原始字节流）
"""
import argparse
import json
import sys


def load_truth(path):
    vals = []
    with open(path, encoding='utf-8') as f:
        for line in f:
            rec = json.loads(line)
            for ent in rec.get('entities', []):
                if ent.get('value'):
                    vals.append((rec['id'], ent['type'], ent['value']))
    return vals


def load_stream(path):
    with open(path, 'rb') as f:
        return f.read()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--pcap', required=True, help='pcap 或任意字节流文件')
    ap.add_argument('--truth', required=True, help='corpus/zh_v1.labels.jsonl')
    args = ap.parse_args()

    blob = load_stream(args.pcap)
    truth = load_truth(args.truth)

    hits = []
    seen = set()
    for rid, etype, val in truth:
        needle = val.encode('utf-8')
        # 宽松匹配：UTF-8 原文、UTF-16LE（Windows 日志/抓包常见）
        if needle in blob or val.encode('utf-16-le') in blob:
            key = (rid, etype, val)
            if key not in seen:
                seen.add(key)
                hits.append({'record': rid, 'type': etype, 'value': val})

    control = [h for h in hits if h['type'] == 'TRADE_SECRET_CONTROL']
    real = [h for h in hits if h['type'] != 'TRADE_SECRET_CONTROL']

    print(f'truth values scanned: {len(truth)}')
    print(f'egress hits total: {len(hits)}')
    print(f'  real PII hits (MUST be 0): {len(real)}')
    print(f'  control (trade_secret, expected passthrough): {len(control)}')
    for h in real:
        print(f"  !! {h['record']} {h['type']} {h['value']}")

    verdict = 'PASS' if not real else 'FAIL'
    print(f'verdict: {verdict}')
    sys.exit(0 if verdict == 'PASS' else 2)


if __name__ == '__main__':
    main()
