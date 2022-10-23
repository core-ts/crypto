import { clear, del, get, set } from 'idb-keyval';

export const STORAGE = {
  SERVER_SHAREKEY: 'shKey',
  CLIENT_KEY_PAIR: 'keyPair',
  SESSION_ID: 'sessionId',
};

export class Idb {
  clientId: string;
  tokenPrefix: string;
  expirationPrefix: string;
  constructor(clientId: string, tokenPrefix?: string, expirationPrefix?: string) {
    this.clientId = clientId;
    this.tokenPrefix = (tokenPrefix && tokenPrefix.length > 0 ? tokenPrefix : 'adal.access.token.key');
    this.expirationPrefix = (expirationPrefix && expirationPrefix.length > 0 ? expirationPrefix : 'adal.expiration.key');
    this.setSharedKey = this.setSharedKey.bind(this);
    this.setSessionId = this.setSessionId.bind(this);
    this.getSessionId = this.getSessionId.bind(this);
    this.getSharedKey = this.getSharedKey.bind(this);
    this.getClientKeyPair = this.getClientKeyPair.bind(this);
    this.getToken = this.getToken.bind(this);
    this.getTokenExpiration = this.getTokenExpiration.bind(this);
    this.removeStorage = this.removeStorage.bind(this);
  }
  setSharedKey(message: string): Promise<void> {
    return set(STORAGE.SERVER_SHAREKEY, message);
  }
  setSessionId(sessionId: string): Promise<void> {
    return set(STORAGE.SESSION_ID, sessionId);
  }
  setClientKeyPair(key: string): Promise<void> {
    return set(STORAGE.CLIENT_KEY_PAIR, key);
  }
  getSessionId(): Promise<{token: string, email: string, roles: string[]}|undefined> {
    return get(STORAGE.SESSION_ID);
  }
  getSharedKey(): Promise<string|undefined> {
    return get(STORAGE.SERVER_SHAREKEY);
  }
  getClientKeyPair(): Promise<string|undefined> {
    return get(STORAGE.CLIENT_KEY_PAIR);
  }
  getToken(): string | null {
    return sessionStorage.getItem(
      `${this.tokenPrefix}${this.clientId}`,
    );
  }
  getTokenExpiration(): string | null {
    return sessionStorage.getItem(
      `${this.expirationPrefix}${this.clientId}`,
    );
  }

  async removeStorage() {
    await del(STORAGE.SERVER_SHAREKEY);
    await del(STORAGE.SESSION_ID);
    await del(STORAGE.CLIENT_KEY_PAIR);
    sessionStorage.clear();
    clear();
  }
}

type KeyType = 'AESKey' | 'PublicKey' | 'PrivateKey' | 'PKPem' | 'SaltKey';
type Format = 'pkcs8' | 'raw' | 'spki';
export function genKey32Bytes() {
  const ran = window.crypto.getRandomValues(new Uint8Array(32));
  const ranStr: string = String.fromCharCode.apply(null, Array.from(ran));
  return window.btoa(ranStr).substring(0, 32);
}
interface CryptoKeyPair {
  privateKey?: CryptoKey;
  publicKey?: CryptoKey;
}
export function generateKey(): Promise<CryptoKeyPair> {
  return window.crypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['encrypt', 'decrypt'],
  );
}
export async function importKey(type: KeyType, key: string): Promise<CryptoKey> {
  let format: Format = 'spki';
  let keyData: BufferSource = new ArrayBuffer(0);
  let algorithm: AlgorithmIdentifier | RsaHashedImportParams | EcKeyImportParams | HmacImportParams | AesKeyAlgorithm = '';
  let extractable = false;
  let keyUsages: KeyUsage[] = [];
  switch (type) {
    case 'PublicKey':
      format = 'spki';
      keyData = convertPemToBinary(key);
      algorithm = {
        name: 'RSA-OAEP',
        hash: 'SHA-256',
      };
      extractable = true;
      keyUsages = ['encrypt'];
      break;
    case 'PrivateKey':
      format = 'pkcs8';
      keyData = convertPemToBinary(key);
      algorithm = {
        name: 'RSA-OAEP',
        hash: 'SHA-256',
      };
      extractable = true;
      keyUsages = ['decrypt'];
      break;
    case 'PKPem':
      format = 'spki';
      keyData = str2ab(window.atob(key));
      algorithm = {
        name: 'RSA-OAEP',
        hash: 'SHA-256',
      };
      extractable = true;
      keyUsages = ['encrypt'];
      break;
    case 'AESKey':
      format = 'raw';
      keyData = str2ab(key);
      algorithm = {
        name: 'AES-CBC',
      };
      extractable = true;
      keyUsages = ['encrypt', 'decrypt'];
      break;
    case 'SaltKey':
      format = 'raw';
      keyData = str2ab(key);
      algorithm = {
        name: 'HMAC',
        hash: { name: 'SHA-256' },
      };
      extractable = false;
      keyUsages = ['sign', 'verify'];
      break;
    default:
      return Promise.reject('key doesn\'t exist');

  }
  return await window.crypto.subtle.importKey(
    format,
    keyData,
    algorithm,
    extractable,
    keyUsages,
  );
}
export async function hashHMAC(keyText: string, data: string, type: KeyType): Promise<string> {
  const key = await importKey(type, keyText);
  const signature = await window.crypto.subtle.sign('HMAC', key, str2ab(data));
  return arrayBufferToHex(signature);
}
export async function encryptAES(key: CryptoKey, message: string): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(16));
  const ivStr = String.fromCharCode.apply(null, Array.from(iv));
  const encrypted = await window.crypto.subtle.encrypt(
    {
      name: 'AES-CBC',
      iv,
    },
    key,
    str2ab(message),
  );
  return `${ivStr}${arrayBufferToString(encrypted)}`;
}
export async function decryptAES(key: CryptoKey, ciphertext: string, iv: string): Promise<string> {
  const decrypted = await window.crypto.subtle.decrypt(
    {
      name: 'AES-CBC',
      iv: str2ab(iv),
    },
    key,
    str2ab(ciphertext),
  );
  return new TextDecoder().decode(decrypted);
}
export async function exportPublicKey(key: CryptoKey): Promise<string> {
  const exported = await window.crypto.subtle.exportKey('spki', key);
  const exportedAsString = ab2str(exported);
  const exportedAsBase64 = window.btoa(exportedAsString);
  const pemExported = `-----BEGIN PUBLIC KEY-----\n${exportedAsBase64}\n-----END PUBLIC KEY-----`;

  return pemExported;
}
export async function exportPrivateKey(key: CryptoKey): Promise<string> {
  const exported = await window.crypto.subtle.exportKey('pkcs8', key);
  const exportedAsString = ab2str(exported);
  const exportedAsBase64 = window.btoa(exportedAsString);
  const pemExported = `-----BEGIN PRIVATE KEY-----\n${exportedAsBase64}\n-----END PRIVATE KEY-----`;

  return pemExported;
}
export async function encrypt(pk: any, data: string): Promise<ArrayBuffer> {
  const encrypted = await window.crypto.subtle.encrypt(
    {
      name: pk.algorithm.name || 'RSA-OAEP',
    },
    pk,
    str2ab(data),
  );
  return encrypted;
}
export async function decrypt(privateKey: CryptoKey, data: string, algorithm?: string): Promise<ArrayBuffer> {
  try {
    const res = await window.crypto.subtle.decrypt(
      {
        name: privateKey.algorithm.name,
      },
      privateKey,
      str2ab(data),
    );
    return res;
  } catch (e) {
    console.log(e);
    throw e;
  }
}

export function convertPemToBinary(pem: string): ArrayBuffer {
  const lines = pem.split('\n');
  let encoded = '';
  // tslint:disable-next-line:prefer-for-of
  for (let i = 0; i < lines.length; i++) {
    if (
      lines[i].trim().length > 0 &&
      lines[i].indexOf('-----BEGIN PRIVATE KEY-----') < 0 &&
      lines[i].indexOf('-----BEGIN PUBLIC KEY-----') < 0 &&
      lines[i].indexOf('-----END PRIVATE KEY-----') < 0 &&
      lines[i].indexOf('-----END PUBLIC KEY-----') < 0
    ) {
      encoded += lines[i].trim();
    }
  }
  const byteStr = window.atob(encoded);
  return str2ab(byteStr);
}

export function str2ab(message: string): ArrayBuffer {
  const buffer = new ArrayBuffer(message.length);
  const bufferView = new Uint8Array(buffer);
  const len = message.length;
  for (let i = 0, strLen = len; i < strLen; i++) {
    bufferView[i] = message.charCodeAt(i);
  }
  return buffer;
}

export function arrayBufferToHex(buffer: any): string {
  let s = '';
  const h = '0123456789abcdef';
  new Uint8Array(buffer).forEach((v) => {
    // tslint:disable-next-line
    s += h[v >> 4] + h[v & 15];
  });
  return s;
}

export function arrayBufferToString(buffer: any): string {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return binary;
}

export function ab2str(buf: any): string {
  // @ts-ignore
  return String.fromCharCode.apply(null, new Uint8Array(buf));
}


export interface ShareKey {
  shareKey: string;
  salt: string;
}

export interface ExchangeKeyPair {
  token: ArrayBuffer;
  dataAESEncrypted: string;
  adalToken: string;
}

export interface CryptoConfig {
  encryption: boolean;
  encryptionShareKey: string;
  encryptionPK: string;
}

const atob = window.atob;
const btoa = window.btoa;

export class CryptoService {
  constructor(
    private idb: Idb,
    protected encryptionShareKey: string,
    protected encryptionPk: string,
    protected encryption?: boolean,
  ) {
    this.generateKey = this.generateKey.bind(this);
    this.getSharedKey = this.getSharedKey.bind(this);
    this.getKeyPair = this.getKeyPair.bind(this);
    this.exchangeKeypair = this.exchangeKeypair.bind(this);
    this.encryptAESMessage = this.encryptAESMessage.bind(this);
    this.decryptAESJSONMessage = this.decryptAESJSONMessage.bind(this);
  }
  async generateKey() {
    const keyPair = await generateKey();
    const key = await importKey('AESKey', atob(this.encryptionShareKey));
    const pemPrivateKeyExport = await exportPrivateKey(keyPair.privateKey as any);
    const pemPublicKeyExport = await exportPublicKey(keyPair.publicKey as any);
    const keyMSG = JSON.stringify({ pemPrivateKeyExport, pemPublicKeyExport });
    const encrypted = await encryptAES(key, keyMSG);
    await this.idb.setClientKeyPair(btoa(encrypted));
  }
  async getSharedKey(): Promise<ShareKey | null> {
    const msg: string | undefined = await this.idb.getSharedKey();
    if (msg) {
      const privateKey = await this.getKeyPair();
      const decrypted = privateKey && await decrypt(privateKey.privateKey as any, msg);
      return JSON.parse(ab2str(decrypted));
    } else {
      return null;
    }
  }
  async getKeyPair(): Promise<CryptoKeyPair | undefined> {
    let msgKeyPair = await this.idb.getClientKeyPair();
    if (msgKeyPair) {
      msgKeyPair = atob(msgKeyPair);
      const key = await importKey('AESKey', atob(this.encryptionShareKey));
      const ivRes = msgKeyPair.substring(0, 16);
      const msg = msgKeyPair.substring(16, msgKeyPair.length);
      const realkeyPair = await decryptAES(key, msg, ivRes);
      const pemKey = JSON.parse(realkeyPair);
      const privateKey = await importKey('PrivateKey', pemKey.pemPrivateKeyExport);
      const publicKey = await importKey('PublicKey', pemKey.pemPublicKeyExport);
      return { privateKey, publicKey };
    } else {
      return undefined;
    }
  }
  async exchangeKeypair(userName: string): Promise<ExchangeKeyPair> {
    const ADALToken = this.idb.getToken();
    if (!ADALToken) {
      throw new Error('Ldap');
    }
    const clientSalt = genKey32Bytes();
    const clientShKey = genKey32Bytes();
    const myKeyPair: any = await this.getKeyPair();

    const pk = await exportPublicKey(myKeyPair.publicKey);
    const aesKey = await importKey('AESKey', clientShKey);
    const aesEncrypted = await encryptAES(aesKey, pk);
    const hash = await hashHMAC(clientSalt, aesEncrypted, 'SaltKey');
    const reqData = `${hash}${aesEncrypted}`;
    const base64 = btoa(reqData);
    const serverPKObj = await importKey('PKPem', this.encryptionPk);

    const token = await encrypt(
      serverPKObj,
      JSON.stringify({
        userName,
        shareKey: clientShKey,
        salt: clientSalt,
      }),
    );

    return {
      token,
      dataAESEncrypted: base64,
      adalToken: ADALToken,
    };
  }
  async encryptAESMessage(dataJSON: string): Promise<string> {
    const security: ShareKey | null = await this.getSharedKey();
    if (this.encryption && security) {
      const aesKey = await importKey('AESKey', security.shareKey);
      const aesEncrypted = await encryptAES(aesKey, dataJSON);
      const hash = await hashHMAC(security.salt, aesEncrypted, 'SaltKey');
      const reqData = `${hash}${aesEncrypted}`;
      const base64 = btoa(reqData);
      return base64;
    } else {
      return dataJSON;
    }
  }
  async decryptAESJSONMessage(messageEncrypted: any,
    option?: {
      decodeUri: boolean;
    },
  ) {
    const security: ShareKey | null = await this.getSharedKey();
    if (this.encryption && security) {
      messageEncrypted = window.atob(messageEncrypted);

      const output = messageEncrypted.substring(64, messageEncrypted.length);
      const ivRes = output.substring(0, 16);
      const msg = output.substring(16, output.length);
      const aesKey = await importKey('AESKey', security.shareKey);
      let decrypted = await decryptAES(aesKey, msg, ivRes);

      if (option && option.decodeUri) {
        decrypted = decodeURIComponent(decrypted);
      }

      return JSON.parse(decrypted);
    } else {
      const result = JSON.parse(messageEncrypted);
      return result;
    }
  }
}
