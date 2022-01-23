import * as CryptoJS from 'crypto-js';

export class RC4Encrypter {
  constructor(public secret: string) {
    this.decrypt = this.decrypt.bind(this);
    this.encrypt = this.encrypt.bind(this);
  }
  encrypt(plainText: string): string {
    const cipherText = CryptoJS.RC4.encrypt(plainText, CryptoJS.enc.Utf8.parse(this.secret)).ciphertext;
    return cipherText.toString(CryptoJS.enc.Base64);
  }
  decrypt(cipherText: string): string|undefined {
    const encryptedMessage: any = {
      ciphertext: CryptoJS.enc.Base64.parse(cipherText)
    };
    try {
      const plainText = CryptoJS.RC4.decrypt(encryptedMessage, CryptoJS.enc.Utf8.parse(this.secret));
      return plainText.toString(CryptoJS.enc.Utf8);
    } catch (e) {
      return undefined;
    }
  }
}
