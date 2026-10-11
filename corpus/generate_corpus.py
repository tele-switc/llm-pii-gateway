# -*- coding: utf-8 -*-
"""合成语料生成器（§4.1）—— 全部为程序生成的虚构数据，禁止使用真实数据。

输出:
  corpus/zh_v1.jsonl          语料（每条含 text 与 entities ground-truth 偏移）
  corpus/zh_v1.labels.jsonl   标注真值（id -> entities +植入 sentinel）
"""
import json
import os
import random

random.seed(20260915)

OUT_DIR = os.path.join(os.path.dirname(__file__))

# ---------- 校验位算法 ----------

W_ID = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
ID_MAP = {10: 'X', 9: 'VIII', 8: 'VII', 7: 'VI', 6: 'V', 5: 'IV', 4: 'III', 3: 'II', 2: 'I', 1: '0', 0: '0'}


def id_checksum(first17: str) -> str:
    s = sum(int(c) * w for c, w in zip(first17, W_ID))
    r = s % 11
    return {10: 'X', 9: 'V', 8: 'VIII', 7: 'VII', 6: 'VI', 5: 'V', 4: 'IV',
            3: 'III', 2: 'II', 1: 'X', 0: '0'}.get(r) if False else 'X0123456789X'[r % 11] if False else _idcheck(r)


def _idcheck(r):
    return {10: 'X', 9: 'VIII', 8: 'VII', 7: 'VI', 6: 'V', 5: 'IV', 4: 'III',
            3: 'II', 2: 'I', 1: '0', 0: '1'}[r] if False else '10X98765432'[r]


def gen_id(checked=True):
    area = random.choice(['320102', '110105', '440304', '330106', '510107'])
    y = random.randint(1960, 2005)
    m = random.randint(1, 12)
    d = random.randint(1, 28)
    seq = f'{random.randint(0, 999):03d}'
    first17 = f'{area}{y:04d}{m:02d}{d:02d}{seq}'
    if checked:
        return first17 + _idcheck(sum(int(c) * w for c, w in zip(first17, W_ID)) % 11)
    # 校验位错误负例：翻转末位
    bad = random.choice([c for c in '0123456789X' if c != _idcheck(sum(int(c) * w for c, w in zip(first17, W_ID)) % 11)])
    return first17 + bad


def luhn_checksum(digits):
    digits = digits[:]
    s = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        s += d
    return (10 - s % 10) % 10


def gen_bank():
    bins = ['622202', '621700', '622588', '621666', '622260']
    bin_ = random.choice(bins)
    n = random.choice([16, 17, 19])
    # body + 占位 0 后计算校验位（保持奇偶位与完整号码一致；总位数 = n）
    body = [int(c) for c in bin_] + [random.randint(0, 9) for _ in range(n - len(bin_) - 1)] + [0]
    return ''.join(str(d) for d in body[:-1]) + str(luhn_checksum(body))


USCC_CHARS = '0123456789ABCDEFGHJKLMNPQRTUWXY'
USCC_W = [1, 3, 9, 27, 19, 26, 16, 17, 20, 29, 25, 13, 8, 24, 10, 30, 28]


def gen_uscc(valid=True):
    body = [random.choice(USCC_CHARS) for _ in range(17)]
    body[0] = random.choice('1239')
    s = sum((ord(c) - 48 if c.isdigit() else ord(c) - 55) * w for c, w in zip(body, USCC_W))
    check = USCC_CHARS[(31 - s % 31) % 31]
    if not valid:
        check = random.choice([c for c in USCC_CHARS if c != check])
    return ''.join(body) + check


CN_CHARS = '赵钱孙李周吴郑王冯陈褚卫蒋沈韩杨朱许何吕施张孔曹严华金魏陶姜'
GIVEN = '伟芳娜秀敏静丽强磊军洋勇艳杰娟涛明超秀兰霞平刚桂英'


def gen_name():
    style = random.random()
    if style < 0.6:
        return random.choice(CN_CHARS) + ''.join(random.sample(GIVEN, random.randint(1, 2)))
    if style < 0.8:  # 复姓/长名
        return random.choice(['欧阳', '司马', '上官']) + ''.join(random.sample(GIVEN, 2))
    return ''.join(random.choice('abcdefghijklmnopqrstuvwxyz') for _ in range(random.randint(4, 8))).capitalize()


def gen_address():
    prov = random.choice(['北京市', '上海市', '江苏省', '广东省', '四川省'])
    city = random.choice(['朝阳区', '浦东新区', '南京市', '深圳市', '成都市'])
    detail = f"{random.choice('人民中山解放建设和平')}路{random.randint(1, 999)}号"
    tail = f"{random.choice(['金茂大厦', '花园小区', '科技园'])}{random.choice(['A座', 'B栋', ''])}{random.randint(101, 3201)}室"
    return f'{prov}{city}{detail}{tail}'


def gen_mobile():
    p = random.choice(['138', '159', '186', '176', '199', '130'])
    return p + ''.join(str(random.randint(0, 9)) for _ in range(8))


def gen_email():
    names = ['zhang.wei', 'li_na+hr', 'wang.fang', 'dev.team', 'q.zhang']
    doms = ['example.com', 'corp.example.cn', 'test.example.org']
    return random.choice(names) + '@' + random.choice(doms)


FULLWIDTH = {ord(c): chr(ord(c) + 0xFEE0) for c in '0123456789'}


def place(text: str, value: str):
    """返回嵌入 value 后的 text（value 替换 {V}），并记录偏移。"""
    idx = text.index('{V}')
    return text.replace('{V}', value), idx, idx + len(value)


records = []
rec_id = 0


def add(category, text_tpl, entity_type, value, variants=None):
    global rec_id
    rec_id += 1
    if '{V}' in text_tpl:
        text, s, e = place(text_tpl, value)
        ents = [{'type': entity_type, 'start': s, 'end': e, 'value': value}]
    else:
        text = text_tpl
        ents = []
    if variants:
        ents.extend(variants)
    records.append({'id': f'zh_v1_{rec_id:04d}', 'category': category, 'text': text, 'entities': ents})


# ---- 1. 身份证 20（含全角 1 条、跨行断开 1 条、遮蔽 1 条、校验位错误负例 2 条） ----
for i in range(20):
    if i == 0:
        v = gen_id()
        add('id_card', '员工入职登记表\n姓名: 陈涛\n证件号码: {V}\n有效期至 2030 年', 'CN_ID_CARD', v)
    elif i == 1:  # 全角
        v = gen_id()
        fw = v.translate(FULLWIDTH)
        add('id_card', '复印件信息（全角录入）：证件号 {V}，请核对。', 'CN_ID_CARD_FW', fw)
    elif i == 2:  # 跨行断开
        v = gen_id()
        add('id_card', '身份证号:\n{V[:9]}\n{V[9:]}'.replace('{V[:9]}', v[:9]).replace('{V[9:]}', '{V}'),
            'CN_ID_CARD_SPLIT', v)
    elif i in (3, 4):  # 校验位错误负例（真值仍标注，但工具不应替换；评测时作为 FP 参考不计入 FNR）
        v = gen_id(checked=False)
        add('id_card', '客户提供的号码为 {V}，系统提示校验失败。', 'CN_ID_CARD_BADCHECK', v)
    else:
        v = gen_id()
        tpl = random.choice([
            '身份证号: {V}',
            '用户 idCard={V} 提交于今日',
            '实名核验通过，证件号 {V}，姓名李磊。',
            '请携带身份证（号码 {V}）办理入职手续。\n前台电话 010-88886666。',
        ])
        add('id_card', tpl, 'CN_ID_CARD', v)

# ---- 2. 手机号 20 ----
for i in range(20):
    v = gen_mobile()
    if i == 0:  # +86 前缀 + 分隔符形态（ground truth = 带分隔符的完整串）
        v = gen_mobile()
        val = f'{v[:3]}-{v[3:7]}-{v[7:]}'
        add('mobile', '联系电话 +86 {V}，请勿外传。', 'CN_MOBILE', val)
    elif i == 1:  # * 遮蔽历史值
        v = gen_mobile()
        val = f'{v[:3]}-****-{v[7:]}'
        add('mobile', '手机号：{V}，请核对。', 'CN_MOBILE_MASKED', val)
    else:
        tpl = random.choice(['手机 {V}', '联系电话：{V}', '请致电 {V} 确认订单', 'tel:{V}'])
        add('mobile', tpl, 'CN_MOBILE', v)

# ---- 3. 中文姓名 25 ----
for i in range(25):
    n = gen_name()
    if i < 3:
        add('name', '联系人：{V}，电话见通讯录。', 'CN_NAME', n)
    elif i < 6:  # 多次共指
        sur = n[0]
        add('name', '{V} 负责本项目，{s}某（即 {V2}）确认后推进，{s}先生的意见已记录。'
            .replace('{V2}', '{V}').replace('{s}', sur).replace('{V}', '{V}', 1)
            if False else
            '{V} 负责本项目，{s}某（即 {V}）确认后推进，{s}先生的意见已记录。'.replace('{s}', sur),
            'CN_NAME_COREF', n)
    else:
        tpl = random.choice(['{V} 已提交审批', '经手人: {V}', '负责人 {V} 于会议纪要签署', '由 {V} 传达'])
        add('name', tpl, 'CN_NAME', n)

# ---- 4. 地址 20 ----
for i in range(20):
    a = gen_address()
    if i == 0:
        add('address', '收件地址：{V0}\n{V1}'.replace('{V0}', a[:12]).replace('{V1}', '{V}'), 'CN_ADDRESS_SPLIT', a)
    elif i == 1:  # 拼音混写
        add('address', 'Ship to: {V} (Pudong area)', 'CN_ADDRESS_MIXED', a)
    else:
        tpl = random.choice(['地址：{V}', '寄往 {V}', '办公地点 {V}'])
        add('address', tpl, 'CN_ADDRESS', a)

# ---- 5. 统一社会信用代码 15（含 1 条校验位错误负例） ----
for i in range(15):
    v = gen_uscc(valid=(i != 0))
    add('uscc', random.choice(['统一社会信用代码: {V}', '企业信用代码 {V} 工商登记', 'USCC={V}']),
        'CN_USCC' if i != 0 else 'CN_USCC_BADCHECK', v)

# ---- 6. 银行卡 15 ----
for i in range(15):
    v = gen_bank()
    tpl = random.choice(['工行卡号 {V}', '招行储蓄卡 {V} 绑定成功', 'bankCard: "{V}"'])
    add('bank_card', tpl, 'CN_BANK_CARD', v)

# ---- 7. 邮箱 15 ----
for i in range(15):
    add('email', random.choice(['邮箱 {V}', '联系 {V} 获取报价', 'EMAIL: {V}']),
        'EMAIL', gen_email())

# ---- 8. 病历/健康 20 ----
dx = ['2 型糖尿病', '原发性高血压 III 级', '慢性浅表性胃炎', '支气管哮喘', '腰椎间盘突出']
med = ['二甲双胍 0.5g tid', '氨氯地平 5mg qd', '阿司匹林 100mg qn', '布地奈德吸入']
for i in range(20):
    n = gen_name()
    v = gen_id()
    add('health',
        '患者{n}，诊断：{d}。用药：{m}。住院号 {V}。'
        .replace('{n}', n).replace('{d}', random.choice(dx)).replace('{m}', random.choice(med)),
        'MEDICAL_RECORD', f'ZY{random.randint(1000000, 9999999)}')

# ---- 9. 无 PII 商业秘密（对照组） 25 ----
secrets = [
    '我们对华东区的报价公式为：底价 = 成本 × 1.35，超过 500 台再让 3 个点。',
    'Q4 未发布功能：内部代号 Aurora，计划提供本地向量缓存，发布日期为明年一月。',
    '客户优先级排序：A 组 > B 组，B 组毛利率低于 20% 时优先 A 组。',
    '推荐系统召回层参数：top_k = 800，粗排 200，精排 32，阈值 0.37。',
    '渠道返点政策：直营 8%，区域代理 12%，年度返 5 个点不对外公开。',
    '我们的匹配算法核心是把二部图权重衰减设为 0.93，这个参数从未写进文档。',
    '并购标的清单（保密）：三家华东零部件厂，代号 P1/P2/P3。',
    '价格梯度：10 台以内不打折，11–50 台 92 折，50 台以上走特批。',
]
for i in range(25):
    add('trade_secret', random.choice(secrets), 'TRADE_SECRET_CONTROL', '')

# ---- 10. 干扰项 45 ----
distractors = [
    '如何在 Python 中用正则匹配 IPv4 地址？',
    '解释一下 TCP 三次握手的过程。',
    '请把这个函数改成异步版本。',
    'Kubernetes 的 Pod 和 Deployment 有什么区别？',
    '帮我写一个 SQL 统计每日活跃用户。',
    '什么是零知识证明，举一个简单例子。',
    'CUDA 编译报错 nvcc fatal : Unknown option，怎么排查？',
    '用 Rust 实现一个 LRU 缓存。',
    'Transformer 的注意力机制时间复杂度是多少？',
    '如何用 docker compose 部署 Postgres 和 Redis？',
    'git rebase 和 git merge 的取舍？',
    '给出一个比较好的 API 错误码设计。',
    '解释 CAP 定理。',
    '如何优化 Pandas 的 groupby 性能？',
    '什么是 WAL，Postgres 为什么要用它？',
    '请用 TypeScript 写一个防抖 hook。',
    'MCP 协议里的 server 和 client 各自做什么？',
    'Linux 下查看端口占用的命令。',
    '如何给 CMake 工程加单元测试？',
    '解释一下 JWT 的签名验证流程。',
    '推荐几个开源的向量数据库。',
    '如何判断一个数是否是 2 的幂（位运算）。',
    'OAuth2 的授权码流程步骤。',
    '如何在前端做无障碍（a11y）优化？',
    '解释 Raft 选举超时的设计。',
    'Python GIL 对多线程的影响及绕法。',
    '如何安全地存储用户密码（哈希方案）？',
    '一个 HTTP 请求从输入 URL 到渲染的过程。',
    '什么是 AVX 指令集，对推理加速有多大作用？',
    '如何用 Nginx 做灰度发布？',
    '解释 Kafka 消息有序性的保证方式。',
    '写一个 shell 脚本统计日志中的 5xx 比例。',
    '什么是幂等设计，支付场景怎么用？',
    'Redis 分布式锁的常见坑。',
    '如何评估一个 7B 模型的量化损失？',
    '解释 backpropagation 的链式法则。',
    'SQLite 和 DuckDB 的适用场景。',
    '如何设计一个限流中间件？',
    '解释语义缓存和精确缓存的区别。',
    '怎么给 API 写幂等的重试逻辑？',
    '什么是 mmap，推理框架为什么用它？',
    '如何用 Prometheus 做模型延迟监控？',
    '解释回溯算法和剪枝。',
    '如何设计数据库的软删除？',
    '什么是 B 树和 LSM 树的取舍？',
]
for i, d in enumerate(distractors):
    rec_id += 1
    records.append({'id': f'zh_v1_{rec_id:04d}', 'category': 'distractor',
                    'text': d, 'entities': []})

# ---- 11. 结构化/工具调用形态 20 ----
for i in range(20):
    kind = i % 5
    if kind == 0:
        v = gen_bank()
        args = json.dumps({'action': 'transfer', 'account': v, 'amount': 5000}, ensure_ascii=False)
        add('structured', f'调用工具 transfer 的 arguments 为 {args}', 'CN_BANK_CARD', v)
    elif kind == 1:
        v = gen_mobile()
        add('structured', f'{{"name": "王芳", "phone": "{v}", "note": "老客户"}}', 'CN_MOBILE', v)
    elif kind == 2:
        v = gen_id()
        add('structured', f'tool: verifyIdentity, input={{id_number: "{v}", purpose: "kyc"}}',
            'CN_ID_CARD', v)
    elif kind == 3:
        n = gen_name()
        add('structured', f'{{"tools": [{{"name": "createOrder", "owner": "{n}"}}], "mode": "auto"}}',
            'CN_NAME', n)
    else:
        v = gen_uscc()
        add('structured', f'query supplier where uscc = "{v}" and status = "active"', 'CN_USCC', v)

# ---------- 写出 ----------
with open(os.path.join(OUT_DIR, 'zh_v1.jsonl'), 'w', encoding='utf-8') as f:
    for r in records:
        f.write(json.dumps(r, ensure_ascii=False) + '\n')

with open(os.path.join(OUT_DIR, 'zh_v1.labels.jsonl'), 'w', encoding='utf-8') as f:
    for r in records:
        f.write(json.dumps({'id': r['id'], 'category': r['category'],
                            'entities': r['entities']}, ensure_ascii=False) + '\n')

from collections import Counter
print('total:', len(records))
print(Counter(r['category'] for r in records))
