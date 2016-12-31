# encoding: utf-8
from __future__ import division, absolute_import, with_statement, print_function
import base64
import hashlib
import six


def url_encode(s):
    if six.PY2:
        import urllib
        return urllib.quote(s)
    else:
        import urllib.parse
        return urllib.parse.quote(s)


def url_decode(s):
    if six.PY2:
        import urllib
        return urllib.unquote(s)
    else:
        import urllib.parse
        return urllib.parse.unquote(s)


def md5(s):
    return hashlib.md5(s.encode("utf-8")).hexdigest()


def sha1(s):
    return hashlib.sha1(s.encode("utf-8")).hexdigest()


def sha256(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def sha512(s):
    return hashlib.sha512(s.encode("utf-8")).hexdigest()


def md5_file(file_path):
    return hashlib.md5(open(file_path, 'rb').read()).hexdigest()


def sha1_file(file_path):
    return hashlib.sha1(open(file_path, 'rb').read()).hexdigest()


def sha256_file(file_path):
    return hashlib.sha256(open(file_path, 'rb').read()).hexdigest()


def sha512_file(file_path):
    return hashlib.sha512(open(file_path, 'rb').read()).hexdigest()


def crc32(s):
    import zlib
    return zlib.crc32(s)


def base64_encode(s):
    return base64.b64encode(s) if six.PY2 else base64.b64encode(s if isinstance(s, bytes) else s.encode()).decode()


def base64_decode(s):
    return base64.b64decode(s) if six.PY2 else base64.b64decode(s if isinstance(s, bytes) else s.encode()).decode()


def aes_encrypt(text, key):
    def pad(s):
        return s + (bs - len(s) % bs) * chr(bs - len(s) % bs)

    from Crypto.Cipher import AES
    from Crypto import Random
    bs = 16
    raw = pad(text)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return base64.b64encode(iv + cipher.encrypt(raw))


def aes_decrypt(text, key):
    def unpad(s):
        return s[:-ord(s[len(s) - 1:])]

    from Crypto.Cipher import AES
    enc = base64.b64decode(text)
    iv = enc[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(enc[16:])).decode()


def rsa_generate_key(public_key_file, private_key_file, bit=2048):
    from Crypto.PublicKey import RSA
    key = RSA.generate(bit)
    public_key = key.publickey().exportKey()
    private_key = key.exportKey()
    with open(public_key_file, "w") as f:
        f.write(public_key)
    with open(private_key_file, "w") as f:
        f.write(private_key)


def __rsa_load_key(key_file):
    from Crypto.PublicKey import RSA
    with open(key_file) as f:
        return RSA.importKey(f.read())


def rsa_encrypt(text, key_file):
    key = __rsa_load_key(key_file)
    enc = key.encrypt(text, None)[0]
    return base64.encodestring(enc)


def rsa_decrypt(cipher, key_file):
    text = base64.decodestring(cipher)
    key = __rsa_load_key(key_file)
    return key.decrypt(text)
