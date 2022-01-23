"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var CryptoJS = require("crypto-js");
var RC4Encrypter = (function () {
  function RC4Encrypter(secret) {
    this.secret = secret;
    this.decrypt = this.decrypt.bind(this);
    this.encrypt = this.encrypt.bind(this);
  }
  RC4Encrypter.prototype.encrypt = function (plainText) {
    var cipherText = CryptoJS.RC4.encrypt(plainText, CryptoJS.enc.Utf8.parse(this.secret)).ciphertext;
    return cipherText.toString(CryptoJS.enc.Base64);
  };
  RC4Encrypter.prototype.decrypt = function (cipherText) {
    var encryptedMessage = {
      ciphertext: CryptoJS.enc.Base64.parse(cipherText)
    };
    try {
      var plainText = CryptoJS.RC4.decrypt(encryptedMessage, CryptoJS.enc.Utf8.parse(this.secret));
      return plainText.toString(CryptoJS.enc.Utf8);
    } catch (e) {
      return undefined;
    }
  };
  return RC4Encrypter;
}());
exports.RC4Encrypter = RC4Encrypter;
