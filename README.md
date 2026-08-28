# Crypto Vault

Crypto Vault 是一款**纯浏览器端运行**的现代化 AEAD 密码学工具套件。不需要将数据上传到服务器，即可在浏览器内安全完成文本、普通小文件以及**多 GB 超大文件**的高性能加密、解密与完整性校验。

---

## 🌟 核心特性

### 1. 银行级密码学与双算法支持
- **原生极速与跨平台兼顾**：大文件优先使用浏览器硬件加速的 **AES-256-GCM**（单文件仅导入一次 CryptoKey 降低开销）；同时内置 **ChaCha20-Poly1305**（优先按需加载 libsodium WASM，不可用时平滑回退至 `@noble/ciphers`）。
- **专业级口令与密钥管理**：支持 CSPRNG 生成的 256 位随机密钥（兼容 Base64 / Base64URL / Hex 格式）；对于人类记忆的文本口令，加密时自动生成独立随机盐，通过 **Argon2id**（64 MiB 内存、3 轮迭代、4 并行度）进行高强度抗爆破派生。
- **全方位防篡改（AAD）**：文件名、MIME 类型、分块索引与容器头均绑定至 AEAD 附加认证数据（AAD），任何分块的插入、删除、重排或篡改都会立刻触发认证失败。

### 2.  V2 流式引擎：应对数 GB 大文件
- **恒定内存占用，不卡死页面**：64 MiB 及以上的文件自动启用 **CRYPTA V2 STREAM** 机制。通过 16 MiB 分块流水线实现“边读、边加密/解密、边写盘”，彻底告别会导致浏览器崩溃的整文件载入。
- **原生文件系统直写**：桌面端结合 File System Access API 实现直接写入目标文件；移动端或无保存选择器时，自动调度至 Dedicated Worker 并借助 OPFS（虚拟文件系统）进行极速读写。
- **并发调度与实时监控**：智能匹配移动端 2 路、桌面端最多 3 路 WebCrypto 并发吞吐，界面实时显示读取、加密与写盘速度，且支持随时安全取消。

### 3. 多算法哈希摘要与全格式校验清单
- **单遍读取，全算法并发**：支持 MD5、SHA-1、SHA-256、SHA-512、SHA3、BLAKE2b 与 BLAKE3。同时勾选多种算法时，只需按 8 MiB 分块读取一次文件即可同步算出所有哈希，结合多 Worker 线程池批量处理大批文件。
- **广泛的清单格式兼容**：支持导出多算法 JSON 清单（`CRYPTA-INTEGRITY` v2），导入时不仅向下兼容 v1 清单，还无缝识别 Linux 标准 GNU 格式（`md5sum` / `sha256sum` / `b2sum`）与 BSD 标签格式，自动按清单匹配校验算法。

### 4. 零知识端到端加密私聊与媒体互传
- **富媒体流式传输**：支持大体积图片与音视频传输，通过 256 KiB 独立 E2EE 分片结合 WebSocket 背压机制发送，不设应用层文件大小上限。
- **浏览器本地轻量转码**：大于 2 MiB 的图片在本地 Worker 中无损优化；大于 12 MiB 的视频优先通过 WebCodecs 在本地转为高兼容性的 H.264/AAC MP4，并在编码同时流式回写分发。所有明文数据仅停留在浏览器内存中，无任何第三方云服务。

---

## 🔑 文本口令与密钥说明

- **关于口令安全性**：密码不会进行简单的截断或 SHA-256 运算，每次加密均会生成新随机盐并记录在密文头部中，解密时只需输入原口令即可自动复原参数。虽然 Argon2id 能极大提高离线破解成本，但对于极高价值的敏感数据，依然推荐直接使用随机生成的 256 位密钥。
- **运行环境提示**：Web Crypto、OPFS 和文件保存接口需要运行在安全上下文（`https://` 或 `localhost`）下。

---

## 🛠️ 本地运行与构建

```bash
# 安装依赖并启动本地开发服务器
npm install
npm run dev

# 生产环境打包与预览
npm run build
npm run preview
```

---

## 📦 容器格式规范

### CRYPTA V1（适合文本与小文件）
基于 MessagePack 的自描述容器，元数据与正文整体打包加密：
```text
magic       "CRYPTA"
version     1
header      { algorithm, keyDerivation }  # 明文头，作为 AAD 参与认证
nonce       96-bit 随机 Nonce
ciphertext  AEAD({ metadata, data })       # 文件元数据与正文合并加密
```

### CRYPTA V2 STREAM（面向 GB 级大文件）
主密钥结合 128-bit 随机盐通过 `HKDF-SHA-256` 派生独立文件子密钥，正文流式分块写入，杜绝堆内存积压：
```text
magic       "CRYPTA2S"
header      { version=2, algorithm, chunkSize, fileSalt, keyDerivation }
meta        AEAD({ name, mime, size, createdAt, chunks })
chunk #1    length + AEAD(16 MiB 数据块)
chunk #2    length + AEAD(16 MiB 数据块)
...
chunk #N    length + AEAD(末尾数据块)
```
- **Nonce 策略**：记录 0 专用于元数据保护，数据块从序号 1 递增，序号直接编码进 96-bit Nonce 与 AAD。
- **截断与防注入**：受保护的元数据中固化了文件总大小与分块总量，解析器在到达尾部时会自动拒绝任何未经认证的尾随残留数据。