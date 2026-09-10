# JA3 / HTTP-2 指纹实现说明

`rust_click` 作为 jump_svc 的 sidecar sender，用 **真实设备采集的 TLS/HTTP-2 指纹** 发送点击请求。本文说明数据来源、运行时行为、如何自检，以及已知限制。

## 1. 为什么要 JA3 + HTTP/2 一起做

- **JA3** 只描述 TLS ClientHello（cipher / extension / curve / point format 的顺序与集合）。
- **HTTP/2 指纹**（Akamai 格式：`SETTINGS|WINDOW_UPDATE|PRIORITY|伪头顺序`）描述 TLS 之上的帧结构，JA3 完全覆盖不到。
- 目标站一旦协商到 h2，只对齐 JA3 依然会在帧层露馅，所以两者必须一起复刻。

一个关键事实：**Chrome 110+ 每个连接都会随机打乱 ClientHello 的扩展顺序**（extension permutation）。因此：

- 同一台设备每次连接的 **JA3 都不同**；
- **JA4 稳定**（JA4 对 cipher/extension 排序后取哈希）。

这就是本项目用 **JA4 作为分组建模键**、并在发送时开启 `permute_extensions` 的原因——复刻的是"这台设备的行为分布"，而不是某一串固定 JA3。

## 2. 数据来源与生成

采集数据：`ja3_info.sql`（MySQL dump，10000 行真实设备抓包，字段含完整 ClientHello `tls.raw`、`tls.ja3`、`h2.akamai_fingerprint`、`h2.headers`、UA/机型/Chrome 版本）。

```bash
python3 tools/gen_profiles.py <ja3_info.sql> data/collected_profiles.json
```

生成器会：

1. 从 base64url 的 `tls.raw` 解析出完整 ClientHello（cipher、扩展及顺序、curves、签名算法、ALPN、TLS 版本），并过滤 GREASE；
2. 计算 **JA4**，按 JA4 归并；
3. 每组取出现次数最多的 JA3 作为代表，同时保留 cipher/curve/sigalg 列表、Akamai h2 指纹、header 顺序与 `sec-ch-ua` 等默认头；
4. 输出 `data/collected_profiles.json`（随二进制 `include_str!` 内嵌，运行时无外部文件依赖）。

当前采集结果：**10000 行 → 22 个 JA4 分组**，其中主指纹 `c001` 占 **92%**（Chrome 150 Android WebView，曲线 `4588-29-23-24`）。

## 3. 运行时行为

```
POST /send ──▶ 解析 SendRequest ──▶ 按 ua 选指纹 ──▶ 取 (proxy, fingerprint) 池化 client
                                         │
                                         ├─ 命中采集库：用 profile 构造 TlsConfig + Http2Config
                                         └─ 未命中：回退 wreq-util 社区 emulation（Chrome/Safari/Firefox）
```

- **选择优先级**：同 Chrome 大版本采集指纹 → 最接近大版本的采集指纹 → 社区指纹（Safari/Firefox/旧 Chrome）→ 主采集指纹。
- 也可在 `SendRequest` 里显式指定 `fingerprint: "<profile id>"`（jump_svc 可选项，当前不发）。
- 一条重定向链复用同一个 client，保持同一 TLS 身份；client 池 key 为 `(proxy, fingerprint)`，沿用原有 `RUST_CLIENT_POOL_SIZE` / `RUST_MAX_REUSED` 语义。

采集指纹到 BoringSSL 配置的映射：

| 采集字段 | wreq/BoringSSL 参数 |
|---|---|
| `tls.ciphers` | `cipher_list`（按序映射到 OpenSSL cipher 名） |
| `tls.curves` | `curves`（`4588→X25519MLKEM768`、`29→X25519`、`23/24/25→P-256/384/521`、`256/257→FFDHE`） |
| `tls.sigalgs` | `sigalgs_list` |
| `tls.extensions` | `permute_extensions`、`grease_enabled`、`alps_protos` + `alps_use_new_codepoint`（17513/17613）、`enable_ech_grease`、`pre_shared_key` |
| `h2` | `Http2Config`（SETTINGS / 连接窗口 / 伪头顺序 / HEADERS 优先级） |
| `headers` / `header_order` | `default_headers` / `headers_order` |

两个容易踩的实现细节：

- **ALPS codepoint**：Chrome 已从 `0x4469`(17513) 迁到 `0x44CD`(17613)。采集库里同时存在两种，必须按 profile 的扩展集合切 `alps_use_new_codepoint`，否则扩展集合对不上。
- **HTTP/2 连接窗口**：Akamai 指纹记录的是 WINDOW_UPDATE 的**增量**，而 hyper2 的 `initial_connection_window_size` 是**绝对值**（初始 65535），所以要 `+65535`。

## 4. 自检

```bash
# 打印采集指纹库
cargo run --release -- --list

# 对每个采集 profile 实发一次，打印服务端观测到的 ja3/ja4/akamai
cargo run --release -- --verify
cargo run --release -- --verify https://tls.peet.ws/api/all c001
```

因为扩展顺序每次都会变，自检用 **JA4** 和 **归一化 JA3**（cipher/extension 排序后比较）判断是否命中。

### 实测结果（`tls.peet.ws/api/all`）

主采集指纹 `c001`（占采集量 92%）：

| 观测项 | 采集值 | 实测发送值 | 结果 |
|---|---|---|---|
| JA3 cipher 列表（含顺序） | `4865-4866-4867-...-47-53` | 完全一致 | ✅ |
| JA3 curves | `4588-29-23-24` | 完全一致 | ✅ |
| JA3 extension 集合 | 16 个 | 完全一致（含 17613 新 ALPS codepoint） | ✅ |
| JA4_a / JA4_b | `t13d1516h2` / `8daaf6152771` | 完全一致 | ✅ |
| JA4_c | `d85c08a3ce5e` | `d8a2da3f94cd` | ❌ 仅因 ML-DSA 缺失（见限制 1） |
| HTTP/2 Akamai 指纹 | `1:65536;2:0;4:6291456;6:262144\|15663105\|0\|m,a,s,p` | 逐字节一致 | ✅ |

按采集权重统计，**95.6% 的采集流量可以做到 JA3 集合/顺序完全一致**。

## 5. 已知限制

1. **ML-DSA 签名算法无法复刻**。采集数据中 Chrome 150 的 `signature_algorithms` 含 `mldsa44/65/87`（`0x0904/0x0905/0x0906`），而当前 BoringSSL（boring2 4.15.15）只有 ML-KEM、没有 ML-DSA，因此这些条目会被丢弃。**这只影响 JA4_c；JA3（含 cipher/extension/curve 顺序）完全不受影响。** SHA-224（`0x0301/0x0303`）与 Ed448（`0x0808`）同样不支持——注意 BoringSSL 对未知 sigalg 名会**直接报错**，所以映射表必须严格（`sigalg_name` 只输出 BoringSSL name 表里存在的名字）。
2. **X448（曲线 30）与 FFDHE 4096/6144/8192（258/259/260）** 未在该 BoringSSL 中暴露，映射时丢弃；本次采集数据的主指纹只用 `4588/29/23/24`，不受影响。
3. **扩展 41（pre_shared_key）无法在新建连接上复现**。它只在会话恢复时出现；采集到含 41 的少数 profile（如 c003/c013/c018/c020）在全新连接上观测不到该扩展，属预期。
4. **扩展 21（padding）由 BoringSSL 按 ClientHello 长度自适应添加**，与采集端不完全同步；这是真实 Chrome 的行为，不必强行对齐。
5. JA3 原始串**不会**与采集库里保存的代表值逐字节相同——这是 `permute_extensions` 的预期行为，也是真实 Chrome 的行为。比对请用 JA4 / 归一化 JA3。
6. 少数采集 profile 并非 Chrome/BoringSSL 形状（更老或非 Chromium 客户端），其扩展集合无法由 BoringSSL 复刻；它们权重极低（合计 <1%）。
7. 社区回退用的是 `wreq-util` 内置 profile（最高 Chrome 137），当请求 UA 是更老的 Chrome 时使用；若 UA 是 Safari/Firefox 则直接走对应社区 profile。

## 6. 构建注意事项

`wreq` 依赖 BoringSSL，需要 `cmake` + C++ 编译器 + `libclang`（bindgen）。Dockerfile 已在 builder 阶段安装；本地构建需保证 `cmake` 在 PATH 中；首次编译 BoringSSL 需要数分钟。
