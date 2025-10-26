// Auto-generated; CWE-327; number of APIs 109
import cpp

predicate isTargetApi(Function target, string qn) {
  target.getQualifiedName().matches("MD5%") and qn = "MD5" or
  target.getQualifiedName().matches("MD5_Init%") and qn = "MD5_Init" or
  target.getQualifiedName().matches("MD5_Update%") and qn = "MD5_Update" or
  target.getQualifiedName().matches("MD5_Final%") and qn = "MD5_Final" or
  target.getQualifiedName().matches("EVP_md5%") and qn = "EVP_md5" or
  target.getQualifiedName().matches("EVP_get_digestbyname%") and qn = "EVP_get_digestbyname" or
  target.getQualifiedName().matches("SHA1%") and qn = "SHA1" or
  target.getQualifiedName().matches("SHA1_Init%") and qn = "SHA1_Init" or
  target.getQualifiedName().matches("SHA1_Update%") and qn = "SHA1_Update" or
  target.getQualifiedName().matches("SHA1_Final%") and qn = "SHA1_Final" or
  target.getQualifiedName().matches("EVP_sha1%") and qn = "EVP_sha1" or
  target.getQualifiedName().matches("SHA224%") and qn = "SHA224" or
  target.getQualifiedName().matches("EVP_sha224%") and qn = "EVP_sha224" or
  target.getQualifiedName().matches("SHA256%") and qn = "SHA256" or
  target.getQualifiedName().matches("SHA256_Init%") and qn = "SHA256_Init" or
  target.getQualifiedName().matches("SHA256_Update%") and qn = "SHA256_Update" or
  target.getQualifiedName().matches("SHA256_Final%") and qn = "SHA256_Final" or
  target.getQualifiedName().matches("EVP_sha256%") and qn = "EVP_sha256" or
  target.getQualifiedName().matches("SHA384%") and qn = "SHA384" or
  target.getQualifiedName().matches("EVP_sha384%") and qn = "EVP_sha384" or
  target.getQualifiedName().matches("SHA512%") and qn = "SHA512" or
  target.getQualifiedName().matches("EVP_sha512%") and qn = "EVP_sha512" or
  target.getQualifiedName().matches("SHA3_224%") and qn = "SHA3_224" or
  target.getQualifiedName().matches("EVP_sha3_224%") and qn = "EVP_sha3_224" or
  target.getQualifiedName().matches("SHA3_256%") and qn = "SHA3_256" or
  target.getQualifiedName().matches("EVP_sha3_256%") and qn = "EVP_sha3_256" or
  target.getQualifiedName().matches("SHA3_384%") and qn = "SHA3_384" or
  target.getQualifiedName().matches("EVP_sha3_384%") and qn = "EVP_sha3_384" or
  target.getQualifiedName().matches("SHA3_512%") and qn = "SHA3_512" or
  target.getQualifiedName().matches("EVP_sha3_512%") and qn = "EVP_sha3_512" or
  target.getQualifiedName().matches("EVP_get_cipherbyname%") and qn = "EVP_get_cipherbyname" or
  target.getQualifiedName().matches("EVP_des_ecb%") and qn = "EVP_des_ecb" or
  target.getQualifiedName().matches("EVP_des_cbc%") and qn = "EVP_des_cbc" or
  target.getQualifiedName().matches("DES_set_key%") and qn = "DES_set_key" or
  target.getQualifiedName().matches("DES_ecb_encrypt%") and qn = "DES_ecb_encrypt" or
  target.getQualifiedName().matches("DES_ncbc_encrypt%") and qn = "DES_ncbc_encrypt" or
  target.getQualifiedName().matches("DES_cblock%") and qn = "DES_cblock" or
  target.getQualifiedName().matches("EVP_rc4%") and qn = "EVP_rc4" or
  target.getQualifiedName().matches("RC4%") and qn = "RC4" or
  target.getQualifiedName().matches("RC4_set_key%") and qn = "RC4_set_key" or
  target.getQualifiedName().matches("EVP_bf_cbc%") and qn = "EVP_bf_cbc" or
  target.getQualifiedName().matches("Blowfish%") and qn = "Blowfish" or
  target.getQualifiedName().matches("bf_encrypt%") and qn = "bf_encrypt" or
  target.getQualifiedName().matches("bf_cfb64_encrypt%") and qn = "bf_cfb64_encrypt" or
  target.getQualifiedName().matches("mbedtls_md5%") and qn = "mbedtls_md5" or
  target.getQualifiedName().matches("mbedtls_md5_starts_ret%") and qn = "mbedtls_md5_starts_ret" or
  target.getQualifiedName().matches("mbedtls_md5_update_ret%") and qn = "mbedtls_md5_update_ret" or
  target.getQualifiedName().matches("mbedtls_md5_finish_ret%") and qn = "mbedtls_md5_finish_ret" or
  target.getQualifiedName().matches("mbedtls_sha1%") and qn = "mbedtls_sha1" or
  target.getQualifiedName().matches("mbedtls_des_crypt_ecb%") and qn = "mbedtls_des_crypt_ecb" or
  target.getQualifiedName().matches("mbedtls_des_crypt_cbc%") and qn = "mbedtls_des_crypt_cbc" or
  target.getQualifiedName().matches("gcry_md_open%") and qn = "gcry_md_open" or
  target.getQualifiedName().matches("gcry_md_write%") and qn = "gcry_md_write" or
  target.getQualifiedName().matches("gcry_md_read%") and qn = "gcry_md_read" or
  target.getQualifiedName().matches("gcry_cipher_open%") and qn = "gcry_cipher_open" or
  target.getQualifiedName().matches("gcry_cipher_setkey%") and qn = "gcry_cipher_setkey" or
  target.getQualifiedName().matches("gcry_cipher_decrypt%") and qn = "gcry_cipher_decrypt" or
  target.getQualifiedName().matches("PK11_CreateDigestContext%") and qn = "PK11_CreateDigestContext" or
  target.getQualifiedName().matches("CryptCreateHash%") and qn = "CryptCreateHash" or
  target.getQualifiedName().matches("BCryptCreateHash%") and qn = "BCryptCreateHash" or
  target.getQualifiedName().matches("NCryptCreatePersistedKey%") and qn = "NCryptCreatePersistedKey" or
  target.getQualifiedName().matches("CryptAcquireContext%") and qn = "CryptAcquireContext" or
  target.getQualifiedName().matches("CryptGenKey%") and qn = "CryptGenKey" or
  target.getQualifiedName().matches("HMAC_Init_ex%") and qn = "HMAC_Init_ex" or
  target.getQualifiedName().matches("HMAC%") and qn = "HMAC" or
  target.getQualifiedName().matches("EVP_DigestInit%") and qn = "EVP_DigestInit" or
  target.getQualifiedName().matches("EVP_DigestInit_ex%") and qn = "EVP_DigestInit_ex" or
  target.getQualifiedName().matches("EVP_DigestUpdate%") and qn = "EVP_DigestUpdate" or
  target.getQualifiedName().matches("EVP_DigestFinal%") and qn = "EVP_DigestFinal" or
  target.getQualifiedName().matches("EVP_CipherInit_ex%") and qn = "EVP_CipherInit_ex" or
  target.getQualifiedName().matches("EVP_BytesToKey%") and qn = "EVP_BytesToKey" or
  target.getQualifiedName().matches("PKCS5_PBKDF2_HMAC%") and qn = "PKCS5_PBKDF2_HMAC" or
  target.getQualifiedName().matches("PKCS5_PBKDF2_HMAC_SHA1%") and qn = "PKCS5_PBKDF2_HMAC_SHA1" or
  target.getQualifiedName().matches("SSL_CTX_set_cipher_list%") and qn = "SSL_CTX_set_cipher_list" or
  target.getQualifiedName().matches("SSL_set_cipher_list%") and qn = "SSL_set_cipher_list" or
  target.getQualifiedName().matches("SSL_CIPHER_get_name%") and qn = "SSL_CIPHER_get_name" or
  target.getQualifiedName().matches("RSA_sign%") and qn = "RSA_sign" or
  target.getQualifiedName().matches("EVP_SignInit%") and qn = "EVP_SignInit" or
  target.getQualifiedName().matches("EVP_SignInit_ex%") and qn = "EVP_SignInit_ex" or
  target.getQualifiedName().matches("EVP_VerifyInit%") and qn = "EVP_VerifyInit" or
  target.getQualifiedName().matches("create_hash%") and qn = "create_hash" or
  target.getQualifiedName().matches("CryptoPP%::MD5%") and qn = "CryptoPP::MD5" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "CryptoPP") and
    memberFunc.getName() = "MD5" and
    qn = "CryptoPP::MD5"
  ) or
  target.getQualifiedName().matches("CryptoPP%::SHA1%") and qn = "CryptoPP::SHA1" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "CryptoPP") and
    memberFunc.getName() = "SHA1" and
    qn = "CryptoPP::SHA1"
  ) or
  target.getQualifiedName().matches("CryptoPP%::DES_EDE3_Encryptor%") and qn = "CryptoPP::DES_EDE3_Encryptor" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "CryptoPP") and
    memberFunc.getName() = "DES_EDE3_Encryptor" and
    qn = "CryptoPP::DES_EDE3_Encryptor"
  ) or
  target.getQualifiedName().matches("CryptoPP%::DES_EDE3_Decryptor%") and qn = "CryptoPP::DES_EDE3_Decryptor" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "CryptoPP") and
    memberFunc.getName() = "DES_EDE3_Decryptor" and
    qn = "CryptoPP::DES_EDE3_Decryptor"
  ) or
  target.getQualifiedName().matches("CryptoPP%::RC4%") and qn = "CryptoPP::RC4" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "CryptoPP") and
    memberFunc.getName() = "RC4" and
    qn = "CryptoPP::RC4"
  ) or
  target.getQualifiedName().matches("Botan%::MD5%") and qn = "Botan::MD5" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "Botan") and
    memberFunc.getName() = "MD5" and
    qn = "Botan::MD5"
  ) or
  target.getQualifiedName().matches("Botan%::SHA1%") and qn = "Botan::SHA1" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "Botan") and
    memberFunc.getName() = "SHA1" and
    qn = "Botan::SHA1"
  ) or
  target.getQualifiedName().matches("Botan%::DES%") and qn = "Botan::DES" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "Botan") and
    memberFunc.getName() = "DES" and
    qn = "Botan::DES"
  ) or
  target.getQualifiedName().matches("Botan%::RC4%") and qn = "Botan::RC4" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "Botan") and
    memberFunc.getName() = "RC4" and
    qn = "Botan::RC4"
  ) or
  target.getQualifiedName().matches("OpenSSL_md5%") and qn = "OpenSSL_md5" or
  target.getQualifiedName().matches("openssl%::md5%") and qn = "openssl::md5" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "openssl") and
    memberFunc.getName() = "md5" and
    qn = "openssl::md5"
  ) or
  target.getQualifiedName().matches("md5%") and qn = "md5" or
  target.getQualifiedName().matches("md4%") and qn = "md4" or
  target.getQualifiedName().matches("MD2%") and qn = "MD2" or
  target.getQualifiedName().matches("EVP_md2%") and qn = "EVP_md2" or
  target.getQualifiedName().matches("rc4_new%") and qn = "rc4_new" or
  target.getQualifiedName().matches("rc4_init%") and qn = "rc4_init" or
  target.getQualifiedName().matches("ssl_ctx_set_cipher_list%") and qn = "ssl_ctx_set_cipher_list" or
  target.getQualifiedName().matches("curl_easy_setopt%") and qn = "curl_easy_setopt" or
  target.getQualifiedName().matches("gnutls_hash_init%") and qn = "gnutls_hash_init" or
  target.getQualifiedName().matches("gnutls_cipher_init%") and qn = "gnutls_cipher_init" or
  target.getQualifiedName().matches("EVP_aes_128_ecb%") and qn = "EVP_aes_128_ecb" or
  target.getQualifiedName().matches("EVP_aes_128_cbc%") and qn = "EVP_aes_128_cbc" or
  target.getQualifiedName().matches("EVP_aes_256_ecb%") and qn = "EVP_aes_256_ecb" or
  target.getQualifiedName().matches("EVP_aes_256_cbc%") and qn = "EVP_aes_256_cbc" or
  target.getQualifiedName().matches("EVP_aes_128_gcm%") and qn = "EVP_aes_128_gcm" or
  target.getQualifiedName().matches("EVP_aes_256_gcm%") and qn = "EVP_aes_256_gcm" or
  target.getQualifiedName().matches("cipher_init%") and qn = "cipher_init"
}

predicate isInSourceCode(FunctionCall call) {
  call.getLocation().getFile().getRelativePath() != ""
}

from FunctionCall call, Function targetFunc, Function enclosingFunc, string qn
where
  targetFunc = call.getTarget() and
  isTargetApi(targetFunc, qn) and
  enclosingFunc = call.getEnclosingFunction() and
  isInSourceCode(call)
select 
"Path: " + call.getLocation().getFile(),
"call function: " + call.getLocation().getStartLine()+":"+call.getLocation().getStartColumn()+
"-"+call.getLocation().getEndLine()+":"+call.getLocation().getEndColumn(),
"call in function: " + enclosingFunc.getName() + "@" +
enclosingFunc.getLocation().getStartLine() + "-" +
enclosingFunc.getBlock().getLocation().getEndLine(),
"callee=" + qn,
"basic block: " + call.getBasicBlock().getStart().getLocation().getStartLine() + ":" +call.getBasicBlock().getStart().getLocation().getStartColumn()+
"-"+ call.getBasicBlock().getEnd().getLocation().getEndLine() + ":" + call.getBasicBlock().getEnd().getLocation().getEndColumn()
