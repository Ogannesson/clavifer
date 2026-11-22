import { useMemo, useRef, useState, type DragEvent, type KeyboardEvent } from 'react';
import { decryptKey, encryptedKey, UnsupportedKeyEncryption } from '../../../packages/core/pkcs8';
import { fault } from './api';
import { asValue, derText, isDer, isPkcs12, pkcs12Text, unescapedKey, unsupportedText } from './values';

/** Reads a file the Owner chose or dropped as text; a PKCS#12 bundle or a binary DER key is refused with
 * how to convert it. */
export async function readText(file: File) {
  const bytes = new Uint8Array(await file.arrayBuffer());
  if (isPkcs12(file.name, bytes)) throw new Error(pkcs12Text);
  if (isDer(bytes)) throw new Error(derText);
  return new TextDecoder().decode(bytes);
}
const dropped = (e: DragEvent) => {
  e.preventDefault();
  return e.dataTransfer.files[0];
};

/** A button that opens the file chooser and hands over the file chosen. */
export function FileButton({ label, onFile }: { label: string; onFile: (file: File) => void }) {
  const input = useRef<HTMLInputElement>(null);
  return (
    <>
      <button type="button" className="btn btn--ghost btn--small" onClick={() => input.current?.click()}>
        {label}
      </button>
      <input
        ref={input}
        type="file"
        hidden
        onChange={(e) => {
          const file = e.currentTarget.files?.[0];
          // Cleared, so choosing the same file again is a change too.
          e.currentTarget.value = '';
          if (file) onFile(file);
        }}
      />
    </>
  );
}

/** The value of a credential field, on the credential form and on a setup's approval card alike.
 * A password box as long as the value is one line: a password input drops line breaks, so a paste with
 * them is taken whole into the component and the box only says how many lines it holds, as is a private
 * key pasted as a JSON file writes it, once its escapes are decoded (unescapedKey). A file is read
 * by the button or dropped onto the field. An encrypted PKCS#8 key gets a passphrase box beside it and
 * is replaced by the plain key once decrypted in the page; the passphrase is neither kept nor sent. */
export function ValueInput({
  name,
  value,
  onChange,
  label,
  required = true,
}: {
  name: string;
  value: string;
  onChange: (value: string) => void;
  label: string;
  required?: boolean;
}) {
  const [passphrase, setPassphrase] = useState('');
  const [problem, setProblem] = useState('');
  const [opening, setOpening] = useState(false);
  // The last pasted key whose escapes, as a JSON file writes them, were decoded; the note under the field
  // stands while it is the value, which a JSON file filled in on the setup card also replaces.
  const [unescaped, setUnescaped] = useState('');
  const set = (next: string) => {
    setProblem('');
    setPassphrase('');
    onChange(next);
  };
  // What the value holds when it is a private key with a passphrase, worked out again only when it changes.
  const key = useMemo(() => {
    try {
      return { encrypted: encryptedKey(value) };
    } catch (e) {
      return {
        refused: e instanceof UnsupportedKeyEncryption ? unsupportedText(e) : fault('key_decryption_failed').message,
      };
    }
  }, [value]);
  const lines = value.replace(/\r?\n$/, '').split(/\r\n|\r|\n/).length;
  const multiline = /[\r\n]/.test(value);
  const load = (file: File | undefined) => {
    if (file)
      readText(file).then(
        (text) => set(asValue(text)),
        (e: Error) => setProblem(e.message),
      );
  };
  const open = async () => {
    if (!key.encrypted) return;
    setOpening(true);
    try {
      set(await decryptKey(key.encrypted, passphrase));
    } catch {
      setProblem(fault('key_decryption_failed').message);
    } finally {
      setOpening(false);
    }
  };
  return (
    <div className="value-input" onDragOver={(e) => e.preventDefault()} onDrop={(e) => load(dropped(e))}>
      <div className="value-line">
        {multiline ? (
          <>
            <input readOnly value={`已载入多行值（${lines} 行）`} aria-label={label} />
            <input type="hidden" name={name} value={value} />
            <button type="button" className="btn btn--quiet btn--small" onClick={() => set('')}>
              清除
            </button>
          </>
        ) : (
          <input
            name={name}
            type="password"
            autoComplete="off"
            required={required}
            aria-label={label}
            value={value}
            onChange={(e) => set(e.target.value)}
            onPaste={(e) => {
              // One line, with or without a break after it, is left to the box, which drops breaks; a key
              // out of a JSON file, its breaks written \n, gets them back.
              const text = e.clipboardData.getData('text');
              const decoded = unescapedKey(asValue(text));
              if (!decoded && !/[\r\n]/.test(asValue(text))) return;
              e.preventDefault();
              set(decoded ?? text);
              setUnescaped(decoded ?? '');
            }}
          />
        )}
        <FileButton label="从文件读取" onFile={load} />
      </div>
      {key.encrypted ? (
        <div className="value-line">
          <input
            type="password"
            autoComplete="off"
            placeholder="私钥的口令"
            aria-label={`${label}：私钥的口令`}
            value={passphrase}
            onChange={(e) => setPassphrase(e.target.value)}
            onKeyDown={(e: KeyboardEvent) => {
              // Enter here opens the key; it must not submit the form around it.
              if (e.key !== 'Enter') return;
              e.preventDefault();
              void open();
            }}
          />
          <button
            type="button"
            className="btn btn--small"
            disabled={opening || !passphrase}
            onClick={() => void open()}
          >
            {opening ? '正在解开…' : '解开私钥'}
          </button>
        </div>
      ) : null}
      {key.encrypted && !problem ? (
        <p className="field-hint">
          这是带口令加密的私钥。口令只在本页使用，解开后保存不加密的私钥，口令不保存、不上传。
        </p>
      ) : null}
      {unescaped && unescaped === value ? (
        <p className="field-hint">粘贴的私钥是 JSON 文件里的写法，其中字面的 \n 已换成换行。</p>
      ) : null}
      {key.refused || problem ? <p className="value-problem">{problem || key.refused}</p> : null}
    </div>
  );
}
/** Whether a value is a private key still under a passphrase, which the service cannot sign with. */
export function lockedKey(value: string) {
  try {
    return !!encryptedKey(value);
  } catch {
    return true;
  }
}
