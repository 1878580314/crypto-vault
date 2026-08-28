/**
 * 加密私聊协议层 v3（BLAKE3）端到端测试。
 * 运行：node chat-protocol.test.ts（Node ≥ 23.6 原生 type-stripping）
 */
import assert from 'node:assert/strict';
import {
  createSession,
  createInsecureSession,
  establishSession,
  helloMac,
  verifyHelloMac,
  sealFrame,
  openFrame,
  MAX_SEQ_GAP,
  roomCodeOf,
  parseRoomCode,
  destroySession,
  publicKeyText,
  peerPublicKeyFromText,
  type ChatSession,
} from './src/chat.ts';

async function handshake(roomCode: string): Promise<{ alice: ChatSession; bob: ChatSession }> {
  const alice = await createSession(roomCode);
  const bob = await createSession(roomCode);
  const aliceMac = await helloMac(alice);
  const bobMac = await helloMac(bob);
  assert.equal(await verifyHelloMac(bob, alice.publicKey, aliceMac), true, 'bob 须认可 alice 公钥 MAC');
  assert.equal(await verifyHelloMac(alice, bob.publicKey, bobMac), true, 'alice 须认可 bob 公钥 MAC');
  await establishSession(alice, bob.publicKey);
  await establishSession(bob, alice.publicKey);
  return { alice, bob };
}

const equalBytes = (a: Uint8Array, b: Uint8Array) =>
  a.length === b.length && a.every((v, i) => v === b[i]);

const tests: Array<{ name: string; fn: () => Promise<void> }> = [
  {
    name: 'PSK MAC：正常校验通过，篡改公钥 / 错误 PSK 均拒绝',
    fn: async () => {
      const alice = await createSession();
      const bob = await createSession(roomCodeOf(alice));
      const mac = await helloMac(alice);
      assert.equal(await verifyHelloMac(bob, alice.publicKey, mac), true);
      const evil = (await createSession(roomCodeOf(alice))).publicKey;
      assert.equal(await verifyHelloMac(bob, evil, mac), false, '被替换的公钥必须校验失败');
      const stranger = await createSession(); // 不同 PSK
      assert.equal(await verifyHelloMac(stranger, alice.publicKey, mac), false, '不同 PSK 必须校验失败');
      assert.ok(mac !== null && mac.length <= 86, `MAC 长度 ${mac?.length} 须在中继白名单内`);
    },
  },
  {
    name: '会话建立：双方推导出相同视觉安全徽章种子（BLAKE3 派生）',
    fn: async () => {
      const { alice, bob } = await handshake(roomCodeOf(await createSession()));
      assert.equal(alice.safetyBadgeSeed, bob.safetyBadgeSeed, '视觉安全徽章种子必须一致');
      assert.match(alice.safetyBadgeSeed!, /^[0-9a-f]{64}$/u, '视觉安全徽章种子必须是小写 64 位十六进制');
    },
  },
  {
    name: '文本帧往返：seq 返回并递增，载荷无损',
    fn: async () => {
      const { alice, bob } = await handshake(roomCodeOf(await createSession()));
      const first = await sealFrame(alice, { k: 'text', t: '你好，BLAKE3。' });
      assert.equal(first.seq, 0);
      const second = await sealFrame(alice, { k: 'text', t: '第二条' });
      assert.equal(second.seq, 1);
      assert.deepEqual((await openFrame(bob, first.frame)).payload, { k: 'text', t: '你好，BLAKE3。' });
      assert.deepEqual((await openFrame(bob, second.frame)).payload, { k: 'text', t: '第二条' });
      const reply = await sealFrame(bob, { k: 'text', t: '收到' });
      assert.deepEqual((await openFrame(alice, reply.frame)).payload, { k: 'text', t: '收到' });
    },
  },
  {
    name: '图片帧与已读回执往返',
    fn: async () => {
      const { alice, bob } = await handshake(roomCodeOf(await createSession()));
      const image = await sealFrame(alice, { k: 'image', mime: 'image/png', name: 'a.png', d: new Uint8Array([1, 2, 3, 255]) });
      const opened = await openFrame(bob, image.frame);
      assert.equal(opened.payload.k, 'image');
      if (opened.payload.k === 'image') {
        assert.equal(opened.payload.mime, 'image/png');
        assert.deepEqual(opened.payload.d, new Uint8Array([1, 2, 3, 255]));
      }
      const receipt = await sealFrame(bob, { k: 'read', upTo: bob.rx!.acked });
      assert.deepEqual((await openFrame(alice, receipt.frame)).payload, { k: 'read', upTo: 1 });
    },
  },
  {
    name: '分片媒体帧：起始、数据块与结束元数据均经过认证',
    fn: async () => {
      const { alice, bob } = await handshake(roomCodeOf(await createSession()));
      const start = await sealFrame(alice, {
        k: 'media-start',
        id: 'media-1',
        media: 'video',
        mime: 'video/mp4',
        name: 'clip.mp4',
        originalSize: 8,
        compressed: true,
      });
      const chunk = await sealFrame(alice, {
        k: 'media-chunk',
        id: 'media-1',
        index: 0,
        offset: 1024,
        d: new Uint8Array([1, 2, 3, 4]),
      });
      const end = await sealFrame(alice, { k: 'media-end', id: 'media-1', size: 4, chunks: 1 });

      assert.equal((await openFrame(bob, start.frame)).payload.k, 'media-start');
      const openedChunk = (await openFrame(bob, chunk.frame)).payload;
      assert.equal(openedChunk.k, 'media-chunk');
      if (openedChunk.k === 'media-chunk') {
        assert.equal(openedChunk.offset, 1024, '随机写媒体分片必须保留文件偏移');
        assert.deepEqual(openedChunk.d, new Uint8Array([1, 2, 3, 4]));
      }
      assert.deepEqual((await openFrame(bob, end.frame)).payload, { k: 'media-end', id: 'media-1', size: 4, chunks: 1 });
    },
  },
  {
    name: '重放帧被拒绝',
    fn: async () => {
      const { alice, bob } = await handshake(roomCodeOf(await createSession()));
      const frame = (await sealFrame(alice, { k: 'text', t: 'once' })).frame;
      await openFrame(bob, frame);
      await assert.rejects(() => openFrame(bob, frame), /重放/u, '同一帧二次投递必须被拒');
    },
  },
  {
    name: '丢帧跳跃：自动对齐棘轮并报告缺口，回退帧仍拒绝',
    fn: async () => {
      const { alice, bob } = await handshake(roomCodeOf(await createSession()));
      const f0 = await sealFrame(alice, { k: 'text', t: '1' });
      const f1 = await sealFrame(alice, { k: 'text', t: '2' });
      const f2 = await sealFrame(alice, { k: 'text', t: '3' });
      // f0 在传输中丢失，先收到 f1：应跳过缺口正常解出
      const skipped = await openFrame(bob, f1.frame);
      assert.equal(skipped.gap, 1, '须报告跳过 1 帧');
      assert.deepEqual(skipped.payload, { k: 'text', t: '2' });
      // 补发的 f0（回退）按重放拒绝
      await assert.rejects(() => openFrame(bob, f0.frame), /重放/u, '回退帧必须被拒');
      // f2 继续正常接收
      const next = await openFrame(bob, f2.frame);
      assert.equal(next.gap, 0);
      assert.deepEqual(next.payload, { k: 'text', t: '3' });
    },
  },
  {
    name: '已读回执基准 acked：跳过丢失帧后不虚报已读',
    fn: async () => {
      const { alice, bob } = await handshake(roomCodeOf(await createSession()));
      await sealFrame(alice, { k: 'text', t: '丢失' });
      const f1 = await sealFrame(alice, { k: 'text', t: '送达' });
      await openFrame(bob, f1.frame); // 跳过 seq 0
      assert.equal(bob.rx!.nextSeq, 2, 'nextSeq 已对齐到 2');
      assert.equal(bob.rx!.acked, 0, 'acked 不得推进（seq 0 从未按序收到）');
      const f2 = await sealFrame(alice, { k: 'text', t: '再送达' });
      await openFrame(bob, f2.frame);
      assert.equal(bob.rx!.acked, 3, '恢复按序接收后 acked 直追 nextSeq');
    },
  },
  {
    name: '会话重协商：对方换新密钥对后凭新 hello 恢复',
    fn: async () => {
      const room = roomCodeOf(await createSession());
      const { alice, bob } = await handshake(room);
      const oldSeed = alice.safetyBadgeSeed;
      // bob 页面重载：全新密钥对
      const bobNew = await createSession(room);
      assert.equal(await verifyHelloMac(alice, bobNew.publicKey, await helloMac(bobNew)), true, '新公钥 MAC 须通过');
      await establishSession(bobNew, alice.publicKey);
      await establishSession(alice, bobNew.publicKey); // alice 凭新 hello 重协商
      assert.notEqual(alice.safetyBadgeSeed, oldSeed, '视觉安全徽章种子应随新会话更新');
      assert.equal(alice.safetyBadgeSeed, bobNew.safetyBadgeSeed, '重协商后双方视觉安全徽章种子一致');
      assert.equal(alice.rx!.nextSeq, 0, '接收链序号重置');
      const msg = await sealFrame(bobNew, { k: 'text', t: '重连成功' });
      assert.deepEqual((await openFrame(alice, msg.frame)).payload, { k: 'text', t: '重连成功' });
    },
  },
  {
    name: '密文被篡改时解密失败',
    fn: async () => {
      const { alice, bob } = await handshake(roomCodeOf(await createSession()));
      const { frame } = await sealFrame(alice, { k: 'text', t: 'payload' });
      const tampered = frame.slice();
      tampered[tampered.length - 1] ^= 0x01;
      await assert.rejects(() => openFrame(bob, tampered), undefined, '篡改帧不得解出明文');
    },
  },
  {
    name: '未来帧认证失败后不推进棘轮，合法当前帧仍可解密',
    fn: async () => {
      const { alice, bob } = await handshake(roomCodeOf(await createSession()));
      const current = await sealFrame(alice, { k: 'text', t: '当前帧' });
      const forgedFuture = current.frame.slice();
      new DataView(forgedFuture.buffer, forgedFuture.byteOffset, forgedFuture.byteLength).setUint32(0, 2, false);
      const beforeChain = bob.rx!.chain.slice();

      await assert.rejects(() => openFrame(bob, forgedFuture), '伪造未来帧必须认证失败');
      assert.equal(bob.rx!.nextSeq, 0, '认证失败不得推进 nextSeq');
      assert.equal(bob.rx!.acked, 0, '认证失败不得推进 acked');
      assert.deepEqual(bob.rx!.chain, beforeChain, '认证失败不得推进接收棘轮');
      assert.deepEqual((await openFrame(bob, current.frame)).payload, { k: 'text', t: '当前帧' });
    },
  },
  {
    name: '超大序号快速拒绝且接收状态保持不变',
    fn: async () => {
      const { alice, bob } = await handshake(roomCodeOf(await createSession()));
      const giant = new Uint8Array(4 + 24 + 16);
      new DataView(giant.buffer).setUint32(0, 0xffffffff, false);
      const beforeChain = bob.rx!.chain.slice();

      await assert.rejects(() => openFrame(bob, giant), /序号跳跃过大/u);
      assert.equal(bob.rx!.nextSeq, 0, '超大序号不得推进 nextSeq');
      assert.equal(bob.rx!.acked, 0, '超大序号不得推进 acked');
      assert.deepEqual(bob.rx!.chain, beforeChain, '超大序号不得派生或提交棘轮');
      // 保证拒绝后仍可正常接收一条合法帧。
      assert.deepEqual((await openFrame(bob, (await sealFrame(alice, { k: 'text', t: 'after reject' })).frame)).payload, {
        k: 'text',
        t: 'after reject',
      });
    },
  },
  {
    name: '认证载荷结构无效时不推进状态',
    fn: async () => {
      const { alice, bob } = await handshake(roomCodeOf(await createSession()));
      const current = await sealFrame(alice, { k: 'text', t: 'current' });
      const malformed = await sealFrame(alice, { k: 'unknown' } as never);
      const beforeChain = bob.rx!.chain.slice();

      await assert.rejects(() => openFrame(bob, malformed.frame), /载荷类型无效/u);
      assert.equal(bob.rx!.nextSeq, 0, '载荷结构失败不得推进 nextSeq');
      assert.equal(bob.rx!.acked, 0, '载荷结构失败不得推进 acked');
      assert.deepEqual(bob.rx!.chain, beforeChain, '载荷结构失败不得推进接收棘轮');
      assert.deepEqual((await openFrame(bob, current.frame)).payload, { k: 'text', t: 'current' });
    },
  },
  {
    name: '允许的最大丢帧缺口仍能认证并对齐棘轮',
    fn: async () => {
      const { alice, bob } = await handshake(roomCodeOf(await createSession()));
      let boundary: Awaited<ReturnType<typeof sealFrame>> | undefined;
      for (let i = 0; i <= MAX_SEQ_GAP; i += 1) {
        boundary = await sealFrame(alice, { k: 'text', t: `boundary-${i}` });
      }

      const opened = await openFrame(bob, boundary!.frame);
      assert.equal(opened.gap, MAX_SEQ_GAP, '最大允许缺口应被接受');
      assert.deepEqual(opened.payload, { k: 'text', t: `boundary-${MAX_SEQ_GAP}` });
      assert.equal(bob.rx!.nextSeq, MAX_SEQ_GAP + 1, '接收序号应对齐到边界后一条');
      assert.equal(bob.rx!.acked, 0, '跳过的帧不能虚报已读');

      const next = await sealFrame(alice, { k: 'text', t: 'after boundary' });
      const nextOpened = await openFrame(bob, next.frame);
      assert.equal(nextOpened.gap, 0);
      assert.equal(bob.rx!.acked, MAX_SEQ_GAP + 2, '边界对齐后按序帧应推进 acked');
    },
  },
  {
    name: '降级模式（无 PSK）：MAC 为 null，会话仍可建立',
    fn: async () => {
      const room = (await createSession()).roomId;
      const alice = await createInsecureSession(room);
      const bob = await createInsecureSession(room);
      assert.equal(await helloMac(alice), null);
      assert.equal(await verifyHelloMac(bob, alice.publicKey, null), true);
      await establishSession(alice, bob.publicKey);
      await establishSession(bob, alice.publicKey);
      assert.equal(alice.safetyBadgeSeed, bob.safetyBadgeSeed);
      assert.deepEqual(
        (await openFrame(bob, (await sealFrame(alice, { k: 'text', t: 'insecure' })).frame)).payload,
        { k: 'text', t: 'insecure' },
      );
    },
  },
  {
    name: '房间码往返与 PSK 长度校验',
    fn: async () => {
      const session = await createSession();
      const code = roomCodeOf(session);
      const parsed = parseRoomCode(code);
      assert.equal(parsed.room, session.roomId);
      assert.equal(parsed.psk!.length, 32, 'PSK 必须是 256 位');
      await assert.rejects(() => createSession(`${session.roomId}.YWJjZA`), /预共享密钥长度/u, '非 32 字节 PSK 必须被拒');
      assert.equal(peerPublicKeyFromText(publicKeyText(session)).length, 32);
      assert.ok(equalBytes(peerPublicKeyFromText(publicKeyText(session)), session.publicKey));
    },
  },
  {
    name: 'destroySession 后一切密钥材料清零',
    fn: async () => {
      const { alice, bob } = await handshake(roomCodeOf(await createSession()));
      await sealFrame(alice, { k: 'text', t: 'bye' });
      destroySession(alice);
      assert.equal(alice.sessionKey, null);
      assert.equal(alice.tx, null);
      assert.equal(alice.rx, null);
      assert.equal(alice.psk, null);
      assert.equal(alice.safetyBadgeSeed, null);
      destroySession(bob);
    },
  },
];

let passed = 0;
for (const test of tests) {
  try {
    await test.fn();
    passed += 1;
    console.log(`  ✓ ${test.name}`);
  } catch (error) {
    console.error(`  ✗ ${test.name}`);
    throw error;
  }
}
console.log(`\n${passed}/${tests.length} 通过 -- 协议层 v3（BLAKE3 + 重协商 + 丢帧对齐）就绪`);
