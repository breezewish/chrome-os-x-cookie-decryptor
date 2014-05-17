chrome-os-x-cookie-decryptor
============================

Decrypt cookie values from Chrome OS X database.

Require [NSS](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS) library.

Get Chrome Encrypt-Password in KeyChain:
```
security find-generic-password -ga "Chrome"
```