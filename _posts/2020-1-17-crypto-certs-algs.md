---
layout: single
title: Windows CryptoAPI and digital certificate analysis
---

This post aims to give a better understanding of how Microsofts CryptoAPI functions as a means of providing security to the system, this post will also have focus on Windows digital certificates and some of the security issues and flaws that today's researchers have found.

Windows utilizes the Microsoft CryptoAPI (which is apart of the Win32 API), which enables developers to have the ability to add cryptography-based security to their applications. Secure communications over nonsecure networks involve the three main areas of concern, "privacy, authentication, and integrity", The Microsoft CryptoAPI is a set of functions and tools which can be used to improve the various areas of concern. Previously Microsoft it was available as the "CryptoAPI SDK" in the early days of Windows. The CryptoAPI acts as a layer between the user and the complex algorithms that are used for protecting data. An application will make calls to various special functions that are known as Cryptographic Service Providers (CSPs), and these are the modules that do all of the encryption/decryption work.

There are four basic types of cryptography, Symmetric Cryptography, Hashing, Public-Key Cryptography, and Digital signatures.

----

**Cryptographic keys**

To encrypt and decrypt data you need a session key, a session key is an object which has a short lifespan, they will never leave the CSP. A user will have cryptographic session keys that are created and destroyed. If a user decides to export a session key, they are created as key "blobs", which are chunks of binary data which represent the encrypted key. 

Each CSP has a key database where it stores its persistent cryptographic keys, 

**wincrypt.h**

Wincrypt.h is a library which is used for security and Identity purposes, it contains various functions which allow for certificate management and 

```c++
BOOL CryptAcquireCertificatePrivateKey(
  PCCERT_CONTEXT                  pCert,
  DWORD                           dwFlags,
  void                            *pvParameters,
  HCRYPTPROV_OR_NCRYPT_KEY_HANDLE *phCryptProvOrNCryptKey,
  DWORD                           *pdwKeySpec,
  BOOL                            *pfCallerFreeProvOrNCryptKey
);
```

**Crypt32.dll**

**Tools**
