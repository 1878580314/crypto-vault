import {
  Check,
  ChevronDown,
  Copy,
  Download,
  Fingerprint,
  KeyRound,
  PackageOpen,
  RefreshCw,
  Send,
  ShieldCheck,
  UserRound,
} from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import { toast } from 'sonner';
import { keyToBase64Url, parseKey } from './crypto';
import {
  generateRecipientIdentity,
  inspectRecipientPublicKey,
  openSealedRawKey,
  protectRecipientIdentity,
  sealRawKeyForRecipient,
  type RecipientIdentity,
} from './keyExchange';

interface KeyExchangeProps {
  operation: 'encrypt' | 'decrypt';
  currentKey: string;
  keyMode: 'raw' | 'passphrase';
  initiallyExpanded?: boolean;
  onRequireRawKey: () => void;
  onUseRecoveredKey: (key: string) => void;
}

function downloadText(filename: string, value: string) {
  const blob = new Blob([value], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

async function copy(value: string, label: string) {
  try {
    await navigator.clipboard.writeText(value);
    toast.success(`${label}已复制`);
  } catch {
    toast.error(`无法复制${label}，请检查浏览器剪贴板权限`);
  }
}

export default function KeyExchange({
  operation,
  currentKey,
  keyMode,
  initiallyExpanded = false,
  onRequireRawKey,
  onUseRecoveredKey,
}: KeyExchangeProps) {
  const [expanded, setExpanded] = useState(initiallyExpanded);
  const [identity, setIdentity] = useState<RecipientIdentity | null>(null);
  const [identityPassphrase, setIdentityPassphrase] = useState('');
  const [identityPassphraseConfirm, setIdentityPassphraseConfirm] = useState('');
  const [recipientPublicKey, setRecipientPublicKey] = useState('');
  const [packageText, setPackageText] = useState('');
  const [packageFingerprint, setPackageFingerprint] = useState('');
  const [incomingIdentity, setIncomingIdentity] = useState('');
  const [incomingIdentityPassphrase, setIncomingIdentityPassphrase] = useState('');
  const [incomingPackage, setIncomingPackage] = useState('');
  const [openedFingerprint, setOpenedFingerprint] = useState('');
  const [busy, setBusy] = useState(false);

  const recipientFp = useMemo(() => {
    if (!recipientPublicKey.trim()) return '';
    try {
      return inspectRecipientPublicKey(recipientPublicKey).fingerprint;
    } catch {
      return '';
    }
  }, [recipientPublicKey]);

  useEffect(() => {
    setPackageText('');
    setPackageFingerprint('');
  }, [currentKey]);

  useEffect(() => {
    if (expanded && operation === 'encrypt' && keyMode !== 'raw') onRequireRawKey();
  }, [expanded, keyMode, onRequireRawKey, operation]);

  const toggleExpanded = () => {
    const next = !expanded;
    if (next && operation === 'encrypt' && keyMode !== 'raw') {
      onRequireRawKey();
      toast.info('安全分发使用独立 256 位密钥，已切换到原始密钥模式');
    }
    setExpanded(next);
  };

  const generateIdentity = async () => {
    setBusy(true);
    try {
      const next = await generateRecipientIdentity();
      setIdentity(next);
      setIdentityPassphrase('');
      setIdentityPassphraseConfirm('');
      toast.success('X25519 接收身份已生成');
    } catch (error) {
      toast.error(error instanceof Error ? error.message : '无法生成接收身份。');
    } finally {
      setBusy(false);
    }
  };

  const downloadIdentityBackup = async () => {
    if (!identity) return;
    if (!identityPassphrase || identityPassphrase !== identityPassphraseConfirm) {
      toast.error('请确认两次身份备份口令完全一致');
      return;
    }
    setBusy(true);
    try {
      const protectedIdentity = await protectRecipientIdentity(identity.privateKey, identityPassphrase);
      downloadText('crypta-identity.txt', protectedIdentity);
      toast.success('加密身份文件已下载');
    } catch (error) {
      toast.error(error instanceof Error ? error.message : '无法创建身份备份。');
    } finally {
      setBusy(false);
    }
  };

  const createPackage = async () => {
    setBusy(true);
    let rawKey: Uint8Array | undefined;
    try {
      rawKey = parseKey(currentKey);
      const result = await sealRawKeyForRecipient(rawKey, recipientPublicKey);
      setPackageText(result.packageText);
      setPackageFingerprint(result.recipientFingerprint);
      toast.success('当前解密密钥已封装给目标接收者');
    } catch (error) {
      toast.error(error instanceof Error ? error.message : '无法创建密钥包。');
    } finally {
      rawKey?.fill(0);
      setBusy(false);
    }
  };

  const openPackage = async () => {
    setBusy(true);
    let rawKey: Uint8Array | undefined;
    try {
      const identityMaterial = incomingIdentity.trim() || identity?.privateKey || '';
      if (!identityMaterial) throw new Error('请先生成当前会话身份，或粘贴加密身份文件。');
      const result = await openSealedRawKey(incomingPackage, identityMaterial, incomingIdentityPassphrase);
      rawKey = result.rawKey;
      setOpenedFingerprint(result.recipientFingerprint);
      onUseRecoveredKey(keyToBase64Url(rawKey));
      toast.success('密钥包已打开，解密密钥已载入');
    } catch (error) {
      toast.error(error instanceof Error ? error.message : '无法打开密钥包。');
    } finally {
      rawKey?.fill(0);
      setBusy(false);
    }
  };

  return (
    <div className={`key-distribution ${expanded ? 'expanded' : ''}`}>
      <button
        type="button"
        className="key-distribution-toggle"
        onClick={toggleExpanded}
        aria-expanded={expanded}
      >
        <span className="key-distribution-icon">
          {operation === 'encrypt' ? <Send size={16} /> : <PackageOpen size={16} />}
        </span>
        <span className="key-distribution-label">
          <strong>{operation === 'encrypt' ? '安全分发密钥' : '使用安全密钥包'}</strong>
          <small>{operation === 'encrypt' ? '用接收者公钥封装当前密钥' : '用接收身份打开收到的密钥包'}</small>
        </span>
        <span className="key-distribution-optional">可选</span>
        <ChevronDown className="key-distribution-chevron" size={16} />
      </button>

      {expanded && (
        <div className="key-distribution-body">
          {operation === 'encrypt' ? (
            <>
              <div className="exchange-session-key">
                <ShieldCheck size={15} />
                <span>该功能使用当前 256 位原始密钥。密文格式不变，接收者只需额外收到一个 CRYPTA KEY 密钥包。</span>
              </div>
              <label className="exchange-field">
                <span>接收者 X25519 公钥</span>
                <textarea
                  value={recipientPublicKey}
                  onChange={(event) => {
                    setRecipientPublicKey(event.target.value);
                    setPackageText('');
                    setPackageFingerprint('');
                  }}
                  placeholder="crypta:pub:v1:…"
                  spellCheck={false}
                />
              </label>
              {recipientFp ? (
                <div className="exchange-fingerprint">
                  <Fingerprint size={14} /><span>接收者指纹</span><strong>{recipientFp}</strong>
                </div>
              ) : recipientPublicKey.trim() ? (
                <div className="distribution-invalid">公钥格式无效</div>
              ) : null}
              <button
                type="button"
                className="exchange-primary"
                onClick={() => void createPackage()}
                disabled={busy || keyMode !== 'raw' || !recipientFp}
              >
                {busy ? <RefreshCw className="spin" size={16} /> : <Send size={16} />}
                创建 CRYPTA KEY 密钥包
              </button>
              {packageText && (
                <div className="exchange-output-stack">
                  <div className="exchange-fingerprint">
                    <Check size={14} /><span>已封装给</span><strong>{packageFingerprint}</strong>
                  </div>
                  <label className="exchange-field">
                    <span>与密文一起发送</span>
                    <textarea value={packageText} readOnly spellCheck={false} />
                  </label>
                  <div className="exchange-actions">
                    <button type="button" onClick={() => void copy(packageText, '密钥包')}><Copy size={15} /> 复制</button>
                    <button type="button" onClick={() => downloadText('crypta-key-package.txt', packageText)}><Download size={15} /> 下载</button>
                  </div>
                </div>
              )}
              <div className="exchange-security-note compact">
                <ShieldCheck size={15} />
                <div><strong>先核对公钥指纹</strong><span>首次交换公钥时通过可信渠道确认指纹，避免把密钥封装给被替换的公钥。</span></div>
              </div>
            </>
          ) : (
            <>
              <div className="distribution-section-head">
                <span className="exchange-icon"><UserRound size={17} /></span>
                <div><strong>我的接收身份</strong><span>只分享公钥；私钥留在自己手中。</span></div>
                <button type="button" className="exchange-primary compact-button" onClick={() => void generateIdentity()} disabled={busy}>
                  {busy ? <RefreshCw className="spin" size={15} /> : <KeyRound size={15} />}
                  {identity ? '重新生成' : '生成身份'}
                </button>
              </div>
              {identity && (
                <div className="exchange-output-stack distribution-identity">
                  <div className="exchange-fingerprint"><Fingerprint size={14} /><span>我的公钥指纹</span><strong>{identity.fingerprint}</strong></div>
                  <label className="exchange-field">
                    <span>分享给发送者的公钥</span>
                    <div className="exchange-value-row">
                      <input value={identity.publicKey} readOnly />
                      <button type="button" onClick={() => void copy(identity.publicKey, '公钥')} aria-label="复制公钥"><Copy size={16} /></button>
                      <button type="button" onClick={() => downloadText('crypta-public-key.txt', identity.publicKey)} aria-label="下载公钥"><Download size={16} /></button>
                    </div>
                  </label>
                  <div className="exchange-session-key"><ShieldCheck size={15} /><span>私钥只保存在当前标签页内存；如需长期使用，请创建加密身份备份。</span></div>
                  <div className="exchange-backup-grid">
                    <label className="exchange-field">
                      <span>身份备份口令</span>
                      <input value={identityPassphrase} onChange={(event) => setIdentityPassphrase(event.target.value)} type="password" autoComplete="new-password" placeholder="加密身份私钥" />
                    </label>
                    <label className="exchange-field">
                      <span>确认口令</span>
                      <input value={identityPassphraseConfirm} onChange={(event) => setIdentityPassphraseConfirm(event.target.value)} type="password" autoComplete="new-password" placeholder="再次输入" />
                    </label>
                  </div>
                  <button
                    type="button"
                    className="exchange-secondary-wide"
                    onClick={() => void downloadIdentityBackup()}
                    disabled={busy || !identityPassphrase || identityPassphrase !== identityPassphraseConfirm}
                  >
                    <Download size={15} /> 下载加密身份文件
                  </button>
                </div>
              )}

              <div className="distribution-divider" />

              <div className="distribution-section-head plain">
                <span className="exchange-icon"><PackageOpen size={17} /></span>
                <div><strong>打开收到的密钥包</strong><span>成功后会直接填入上方 256 位解密密钥。</span></div>
              </div>
              <label className="exchange-field">
                <span>CRYPTA KEY 密钥包</span>
                <textarea value={incomingPackage} onChange={(event) => setIncomingPackage(event.target.value)} placeholder="crypta:key:v1:…" spellCheck={false} />
              </label>
              <label className="exchange-field">
                <span>加密身份文件</span>
                <textarea
                  value={incomingIdentity}
                  onChange={(event) => setIncomingIdentity(event.target.value)}
                  placeholder={identity ? '当前会话身份可直接使用；或粘贴 crypta:identity:v1:…' : 'crypta:identity:v1:…'}
                  spellCheck={false}
                />
              </label>
              <label className="exchange-field">
                <span>身份备份口令</span>
                <input
                  value={incomingIdentityPassphrase}
                  onChange={(event) => setIncomingIdentityPassphrase(event.target.value)}
                  type="password"
                  autoComplete="current-password"
                  placeholder={identity && !incomingIdentity.trim() ? '当前会话身份无需口令' : '输入身份文件备份口令'}
                />
              </label>
              <button
                type="button"
                className="exchange-primary"
                onClick={() => void openPackage()}
                disabled={busy || !incomingPackage.trim() || (!incomingIdentity.trim() && !identity)}
              >
                {busy ? <RefreshCw className="spin" size={16} /> : <PackageOpen size={16} />}
                打开并载入解密密钥
              </button>
              {openedFingerprint && (
                <div className="exchange-recovered distribution-recovered">
                  <span className="success-icon"><Check size={15} /></span>
                  <div><strong>256 位解密密钥已载入</strong><span>身份指纹 {openedFingerprint}</span></div>
                </div>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}
