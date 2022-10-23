"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
  function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
  return new (P || (P = Promise))(function (resolve, reject) {
    function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
    function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
    function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
    step((generator = generator.apply(thisArg, _arguments || [])).next());
  });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
  var _ = { label: 0, sent: function () { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
  return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function () { return this; }), g;
  function verb(n) { return function (v) { return step([n, v]); }; }
  function step(op) {
    if (f) throw new TypeError("Generator is already executing.");
    while (_) try {
      if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
      if (y = 0, t) op = [op[0] & 2, t.value];
      switch (op[0]) {
        case 0: case 1: t = op; break;
        case 4: _.label++; return { value: op[1], done: false };
        case 5: _.label++; y = op[1]; op = [0]; continue;
        case 7: op = _.ops.pop(); _.trys.pop(); continue;
        default:
          if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
          if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
          if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
          if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
          if (t[2]) _.ops.pop();
          _.trys.pop(); continue;
      }
      op = body.call(thisArg, _);
    } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
    if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
  }
};
Object.defineProperty(exports, "__esModule", { value: true });
var idb_keyval_1 = require("idb-keyval");
exports.STORAGE = {
  SERVER_SHAREKEY: 'shKey',
  CLIENT_KEY_PAIR: 'keyPair',
  SESSION_ID: 'sessionId',
};
var Idb = /** @class */ (function () {
  function Idb(clientId, tokenPrefix, expirationPrefix) {
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
  Idb.prototype.setSharedKey = function (message) {
    return idb_keyval_1.set(exports.STORAGE.SERVER_SHAREKEY, message);
  };
  Idb.prototype.setSessionId = function (sessionId) {
    return idb_keyval_1.set(exports.STORAGE.SESSION_ID, sessionId);
  };
  Idb.prototype.setClientKeyPair = function (key) {
    return idb_keyval_1.set(exports.STORAGE.CLIENT_KEY_PAIR, key);
  };
  Idb.prototype.getSessionId = function () {
    return idb_keyval_1.get(exports.STORAGE.SESSION_ID);
  };
  Idb.prototype.getSharedKey = function () {
    return idb_keyval_1.get(exports.STORAGE.SERVER_SHAREKEY);
  };
  Idb.prototype.getClientKeyPair = function () {
    return idb_keyval_1.get(exports.STORAGE.CLIENT_KEY_PAIR);
  };
  Idb.prototype.getToken = function () {
    return sessionStorage.getItem("" + this.tokenPrefix + this.clientId);
  };
  Idb.prototype.getTokenExpiration = function () {
    return sessionStorage.getItem("" + this.expirationPrefix + this.clientId);
  };
  Idb.prototype.removeStorage = function () {
    return __awaiter(this, void 0, void 0, function () {
      return __generator(this, function (_a) {
        switch (_a.label) {
          case 0: return [4 /*yield*/, idb_keyval_1.del(exports.STORAGE.SERVER_SHAREKEY)];
          case 1:
            _a.sent();
            return [4 /*yield*/, idb_keyval_1.del(exports.STORAGE.SESSION_ID)];
          case 2:
            _a.sent();
            return [4 /*yield*/, idb_keyval_1.del(exports.STORAGE.CLIENT_KEY_PAIR)];
          case 3:
            _a.sent();
            sessionStorage.clear();
            idb_keyval_1.clear();
            return [2 /*return*/];
        }
      });
    });
  };
  return Idb;
}());
exports.Idb = Idb;
function genKey32Bytes() {
  var ran = window.crypto.getRandomValues(new Uint8Array(32));
  var ranStr = String.fromCharCode.apply(null, Array.from(ran));
  return window.btoa(ranStr).substring(0, 32);
}
exports.genKey32Bytes = genKey32Bytes;
function generateKey() {
  return window.crypto.subtle.generateKey({
    name: 'RSA-OAEP',
    modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: 'SHA-256',
  }, true, ['encrypt', 'decrypt']);
}
exports.generateKey = generateKey;
function importKey(type, key) {
  return __awaiter(this, void 0, void 0, function () {
    var format, keyData, algorithm, extractable, keyUsages;
    return __generator(this, function (_a) {
      switch (_a.label) {
        case 0:
          format = 'spki';
          keyData = new ArrayBuffer(0);
          algorithm = '';
          extractable = false;
          keyUsages = [];
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
              return [2 /*return*/, Promise.reject("key doesn't exist")];
          }
          return [4 /*yield*/, window.crypto.subtle.importKey(format, keyData, algorithm, extractable, keyUsages)];
        case 1: return [2 /*return*/, _a.sent()];
      }
    });
  });
}
exports.importKey = importKey;
function hashHMAC(keyText, data, type) {
  return __awaiter(this, void 0, void 0, function () {
    var key, signature;
    return __generator(this, function (_a) {
      switch (_a.label) {
        case 0: return [4 /*yield*/, importKey(type, keyText)];
        case 1:
          key = _a.sent();
          return [4 /*yield*/, window.crypto.subtle.sign('HMAC', key, str2ab(data))];
        case 2:
          signature = _a.sent();
          return [2 /*return*/, arrayBufferToHex(signature)];
      }
    });
  });
}
exports.hashHMAC = hashHMAC;
function encryptAES(key, message) {
  return __awaiter(this, void 0, void 0, function () {
    var iv, ivStr, encrypted;
    return __generator(this, function (_a) {
      switch (_a.label) {
        case 0:
          iv = crypto.getRandomValues(new Uint8Array(16));
          ivStr = String.fromCharCode.apply(null, Array.from(iv));
          return [4 /*yield*/, window.crypto.subtle.encrypt({
            name: 'AES-CBC',
            iv: iv,
          }, key, str2ab(message))];
        case 1:
          encrypted = _a.sent();
          return [2 /*return*/, "" + ivStr + arrayBufferToString(encrypted)];
      }
    });
  });
}
exports.encryptAES = encryptAES;
function decryptAES(key, ciphertext, iv) {
  return __awaiter(this, void 0, void 0, function () {
    var decrypted;
    return __generator(this, function (_a) {
      switch (_a.label) {
        case 0: return [4 /*yield*/, window.crypto.subtle.decrypt({
          name: 'AES-CBC',
          iv: str2ab(iv),
        }, key, str2ab(ciphertext))];
        case 1:
          decrypted = _a.sent();
          return [2 /*return*/, new TextDecoder().decode(decrypted)];
      }
    });
  });
}
exports.decryptAES = decryptAES;
function exportPublicKey(key) {
  return __awaiter(this, void 0, void 0, function () {
    var exported, exportedAsString, exportedAsBase64, pemExported;
    return __generator(this, function (_a) {
      switch (_a.label) {
        case 0: return [4 /*yield*/, window.crypto.subtle.exportKey('spki', key)];
        case 1:
          exported = _a.sent();
          exportedAsString = ab2str(exported);
          exportedAsBase64 = window.btoa(exportedAsString);
          pemExported = "-----BEGIN PUBLIC KEY-----\n" + exportedAsBase64 + "\n-----END PUBLIC KEY-----";
          return [2 /*return*/, pemExported];
      }
    });
  });
}
exports.exportPublicKey = exportPublicKey;
function exportPrivateKey(key) {
  return __awaiter(this, void 0, void 0, function () {
    var exported, exportedAsString, exportedAsBase64, pemExported;
    return __generator(this, function (_a) {
      switch (_a.label) {
        case 0: return [4 /*yield*/, window.crypto.subtle.exportKey('pkcs8', key)];
        case 1:
          exported = _a.sent();
          exportedAsString = ab2str(exported);
          exportedAsBase64 = window.btoa(exportedAsString);
          pemExported = "-----BEGIN PRIVATE KEY-----\n" + exportedAsBase64 + "\n-----END PRIVATE KEY-----";
          return [2 /*return*/, pemExported];
      }
    });
  });
}
exports.exportPrivateKey = exportPrivateKey;
function encrypt(pk, data) {
  return __awaiter(this, void 0, void 0, function () {
    var encrypted;
    return __generator(this, function (_a) {
      switch (_a.label) {
        case 0: return [4 /*yield*/, window.crypto.subtle.encrypt({
          name: pk.algorithm.name || 'RSA-OAEP',
        }, pk, str2ab(data))];
        case 1:
          encrypted = _a.sent();
          return [2 /*return*/, encrypted];
      }
    });
  });
}
exports.encrypt = encrypt;
function decrypt(privateKey, data, algorithm) {
  return __awaiter(this, void 0, void 0, function () {
    var res, e_1;
    return __generator(this, function (_a) {
      switch (_a.label) {
        case 0:
          _a.trys.push([0, 2, , 3]);
          return [4 /*yield*/, window.crypto.subtle.decrypt({
            name: privateKey.algorithm.name,
          }, privateKey, str2ab(data))];
        case 1:
          res = _a.sent();
          return [2 /*return*/, res];
        case 2:
          e_1 = _a.sent();
          console.log(e_1);
          throw e_1;
        case 3: return [2 /*return*/];
      }
    });
  });
}
exports.decrypt = decrypt;
function convertPemToBinary(pem) {
  var lines = pem.split('\n');
  var encoded = '';
  for (var i = 0; i < lines.length; i++) {
    if (lines[i].trim().length > 0 &&
      lines[i].indexOf('-----BEGIN PRIVATE KEY-----') < 0 &&
      lines[i].indexOf('-----BEGIN PUBLIC KEY-----') < 0 &&
      lines[i].indexOf('-----END PRIVATE KEY-----') < 0 &&
      lines[i].indexOf('-----END PUBLIC KEY-----') < 0) {
      encoded += lines[i].trim();
    }
  }
  var byteStr = window.atob(encoded);
  return str2ab(byteStr);
}
exports.convertPemToBinary = convertPemToBinary;
function str2ab(message) {
  var buffer = new ArrayBuffer(message.length);
  var bufferView = new Uint8Array(buffer);
  var len = message.length;
  for (var i = 0, strLen = len; i < strLen; i++) {
    bufferView[i] = message.charCodeAt(i);
  }
  return buffer;
}
exports.str2ab = str2ab;
function arrayBufferToHex(buffer) {
  var s = '';
  var h = '0123456789abcdef';
  new Uint8Array(buffer).forEach(function (v) {
    s += h[v >> 4] + h[v & 15];
  });
  return s;
}
exports.arrayBufferToHex = arrayBufferToHex;
function arrayBufferToString(buffer) {
  var binary = '';
  var bytes = new Uint8Array(buffer);
  var len = bytes.byteLength;
  for (var i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return binary;
}
exports.arrayBufferToString = arrayBufferToString;
function ab2str(buf) {
  //@ts-ignore
  return String.fromCharCode.apply(null, new Uint8Array(buf));
}
exports.ab2str = ab2str;
var atob = window.atob;
var btoa = window.btoa;
var CryptoService = /** @class */ (function () {
  function CryptoService(idb, encryptionShareKey, encryptionPk, encryption) {
    this.idb = idb;
    this.encryptionShareKey = encryptionShareKey;
    this.encryptionPk = encryptionPk;
    this.encryption = encryption;
    this.generateKey = this.generateKey.bind(this);
    this.getSharedKey = this.getSharedKey.bind(this);
    this.getKeyPair = this.getKeyPair.bind(this);
    this.exchangeKeypair = this.exchangeKeypair.bind(this);
    this.encryptAESMessage = this.encryptAESMessage.bind(this);
    this.decryptAESJSONMessage = this.decryptAESJSONMessage.bind(this);
  }
  CryptoService.prototype.generateKey = function () {
    return __awaiter(this, void 0, void 0, function () {
      var keyPair, key, pemPrivateKeyExport, pemPublicKeyExport, keyMSG, encrypted;
      return __generator(this, function (_a) {
        switch (_a.label) {
          case 0: return [4 /*yield*/, generateKey()];
          case 1:
            keyPair = _a.sent();
            return [4 /*yield*/, importKey('AESKey', atob(this.encryptionShareKey))];
          case 2:
            key = _a.sent();
            return [4 /*yield*/, exportPrivateKey(keyPair.privateKey)];
          case 3:
            pemPrivateKeyExport = _a.sent();
            return [4 /*yield*/, exportPublicKey(keyPair.publicKey)];
          case 4:
            pemPublicKeyExport = _a.sent();
            keyMSG = JSON.stringify({ pemPrivateKeyExport: pemPrivateKeyExport, pemPublicKeyExport: pemPublicKeyExport });
            return [4 /*yield*/, encryptAES(key, keyMSG)];
          case 5:
            encrypted = _a.sent();
            return [4 /*yield*/, this.idb.setClientKeyPair(btoa(encrypted))];
          case 6:
            _a.sent();
            return [2 /*return*/];
        }
      });
    });
  };
  CryptoService.prototype.getSharedKey = function () {
    return __awaiter(this, void 0, void 0, function () {
      var msg, privateKey, decrypted, _a;
      return __generator(this, function (_b) {
        switch (_b.label) {
          case 0: return [4 /*yield*/, this.idb.getSharedKey()];
          case 1:
            msg = _b.sent();
            if (!msg) return [3 /*break*/, 5];
            return [4 /*yield*/, this.getKeyPair()];
          case 2:
            privateKey = _b.sent();
            _a = privateKey;
            if (!_a) return [3 /*break*/, 4];
            return [4 /*yield*/, decrypt(privateKey.privateKey, msg)];
          case 3:
            _a = (_b.sent());
            _b.label = 4;
          case 4:
            decrypted = _a;
            return [2 /*return*/, JSON.parse(ab2str(decrypted))];
          case 5: return [2 /*return*/, null];
        }
      });
    });
  };
  CryptoService.prototype.getKeyPair = function () {
    return __awaiter(this, void 0, void 0, function () {
      var msgKeyPair, key, ivRes, msg, realkeyPair, pemKey, privateKey, publicKey;
      return __generator(this, function (_a) {
        switch (_a.label) {
          case 0: return [4 /*yield*/, this.idb.getClientKeyPair()];
          case 1:
            msgKeyPair = _a.sent();
            if (!msgKeyPair) return [3 /*break*/, 6];
            msgKeyPair = atob(msgKeyPair);
            return [4 /*yield*/, importKey('AESKey', atob(this.encryptionShareKey))];
          case 2:
            key = _a.sent();
            ivRes = msgKeyPair.substring(0, 16);
            msg = msgKeyPair.substring(16, msgKeyPair.length);
            return [4 /*yield*/, decryptAES(key, msg, ivRes)];
          case 3:
            realkeyPair = _a.sent();
            pemKey = JSON.parse(realkeyPair);
            return [4 /*yield*/, importKey('PrivateKey', pemKey.pemPrivateKeyExport)];
          case 4:
            privateKey = _a.sent();
            return [4 /*yield*/, importKey('PublicKey', pemKey.pemPublicKeyExport)];
          case 5:
            publicKey = _a.sent();
            return [2 /*return*/, { privateKey: privateKey, publicKey: publicKey }];
          case 6: return [2 /*return*/, undefined];
        }
      });
    });
  };
  CryptoService.prototype.exchangeKeypair = function (userName) {
    return __awaiter(this, void 0, void 0, function () {
      var ADALToken, clientSalt, clientShKey, myKeyPair, pk, aesKey, aesEncrypted, hash, reqData, base64, serverPKObj, token;
      return __generator(this, function (_a) {
        switch (_a.label) {
          case 0:
            ADALToken = this.idb.getToken();
            if (!ADALToken) {
              throw new Error('Ldap');
            }
            clientSalt = genKey32Bytes();
            clientShKey = genKey32Bytes();
            return [4 /*yield*/, this.getKeyPair()];
          case 1:
            myKeyPair = _a.sent();
            return [4 /*yield*/, exportPublicKey(myKeyPair.publicKey)];
          case 2:
            pk = _a.sent();
            return [4 /*yield*/, importKey('AESKey', clientShKey)];
          case 3:
            aesKey = _a.sent();
            return [4 /*yield*/, encryptAES(aesKey, pk)];
          case 4:
            aesEncrypted = _a.sent();
            return [4 /*yield*/, hashHMAC(clientSalt, aesEncrypted, 'SaltKey')];
          case 5:
            hash = _a.sent();
            reqData = "" + hash + aesEncrypted;
            base64 = btoa(reqData);
            return [4 /*yield*/, importKey('PKPem', this.encryptionPk)];
          case 6:
            serverPKObj = _a.sent();
            return [4 /*yield*/, encrypt(serverPKObj, JSON.stringify({
              userName: userName,
              shareKey: clientShKey,
              salt: clientSalt,
            }))];
          case 7:
            token = _a.sent();
            return [2 /*return*/, {
              token: token,
              dataAESEncrypted: base64,
              adalToken: ADALToken,
            }];
        }
      });
    });
  };
  CryptoService.prototype.encryptAESMessage = function (dataJSON) {
    return __awaiter(this, void 0, void 0, function () {
      var security, aesKey, aesEncrypted, hash, reqData, base64;
      return __generator(this, function (_a) {
        switch (_a.label) {
          case 0: return [4 /*yield*/, this.getSharedKey()];
          case 1:
            security = _a.sent();
            if (!(this.encryption && security)) return [3 /*break*/, 5];
            return [4 /*yield*/, importKey('AESKey', security.shareKey)];
          case 2:
            aesKey = _a.sent();
            return [4 /*yield*/, encryptAES(aesKey, dataJSON)];
          case 3:
            aesEncrypted = _a.sent();
            return [4 /*yield*/, hashHMAC(security.salt, aesEncrypted, 'SaltKey')];
          case 4:
            hash = _a.sent();
            reqData = "" + hash + aesEncrypted;
            base64 = btoa(reqData);
            return [2 /*return*/, base64];
          case 5: return [2 /*return*/, dataJSON];
        }
      });
    });
  };
  CryptoService.prototype.decryptAESJSONMessage = function (messageEncrypted, option) {
    return __awaiter(this, void 0, void 0, function () {
      var security, output, ivRes, msg, aesKey, decrypted, result;
      return __generator(this, function (_a) {
        switch (_a.label) {
          case 0: return [4 /*yield*/, this.getSharedKey()];
          case 1:
            security = _a.sent();
            if (!(this.encryption && security)) return [3 /*break*/, 4];
            messageEncrypted = window.atob(messageEncrypted);
            output = messageEncrypted.substring(64, messageEncrypted.length);
            ivRes = output.substring(0, 16);
            msg = output.substring(16, output.length);
            return [4 /*yield*/, importKey('AESKey', security.shareKey)];
          case 2:
            aesKey = _a.sent();
            return [4 /*yield*/, decryptAES(aesKey, msg, ivRes)];
          case 3:
            decrypted = _a.sent();
            if (option && option.decodeUri) {
              decrypted = decodeURIComponent(decrypted);
            }
            return [2 /*return*/, JSON.parse(decrypted)];
          case 4:
            result = JSON.parse(messageEncrypted);
            return [2 /*return*/, result];
        }
      });
    });
  };
  return CryptoService;
}());
exports.CryptoService = CryptoService;
