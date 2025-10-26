// Auto-generated; CWE-326; number of APIs 291
import cpp

predicate isTargetApi(Function target, string qn) {
  target.getQualifiedName().matches("EVP_md5%") and qn = "EVP_md5" or
  target.getQualifiedName().matches("EVP_sha1%") and qn = "EVP_sha1" or
  target.getQualifiedName().matches("EVP_sha224%") and qn = "EVP_sha224" or
  target.getQualifiedName().matches("EVP_sha256%") and qn = "EVP_sha256" or
  target.getQualifiedName().matches("EVP_sha384%") and qn = "EVP_sha384" or
  target.getQualifiedName().matches("EVP_sha512%") and qn = "EVP_sha512" or
  target.getQualifiedName().matches("EVP_sha3_224%") and qn = "EVP_sha3_224" or
  target.getQualifiedName().matches("EVP_sha3_256%") and qn = "EVP_sha3_256" or
  target.getQualifiedName().matches("EVP_sha3_384%") and qn = "EVP_sha3_384" or
  target.getQualifiedName().matches("EVP_sha3_512%") and qn = "EVP_sha3_512" or
  target.getQualifiedName().matches("EVP_get_digestbyname%") and qn = "EVP_get_digestbyname" or
  target.getQualifiedName().matches("EVP_MD_CTX_new%") and qn = "EVP_MD_CTX_new" or
  target.getQualifiedName().matches("EVP_DigestInit_ex%") and qn = "EVP_DigestInit_ex" or
  target.getQualifiedName().matches("EVP_DigestUpdate%") and qn = "EVP_DigestUpdate" or
  target.getQualifiedName().matches("EVP_DigestFinal_ex%") and qn = "EVP_DigestFinal_ex" or
  target.getQualifiedName().matches("HMAC%") and qn = "HMAC" or
  target.getQualifiedName().matches("HMAC_Init_ex%") and qn = "HMAC_Init_ex" or
  target.getQualifiedName().matches("HMAC_Update%") and qn = "HMAC_Update" or
  target.getQualifiedName().matches("HMAC_Final%") and qn = "HMAC_Final" or
  target.getQualifiedName().matches("PKCS5_PBKDF1%") and qn = "PKCS5_PBKDF1" or
  target.getQualifiedName().matches("PKCS5_PBKDF2_HMAC%") and qn = "PKCS5_PBKDF2_HMAC" or
  target.getQualifiedName().matches("PKCS5_PBKDF2_HMAC_SHA1%") and qn = "PKCS5_PBKDF2_HMAC_SHA1" or
  target.getQualifiedName().matches("EVP_EncryptInit_ex%") and qn = "EVP_EncryptInit_ex" or
  target.getQualifiedName().matches("EVP_EncryptUpdate%") and qn = "EVP_EncryptUpdate" or
  target.getQualifiedName().matches("EVP_EncryptFinal_ex%") and qn = "EVP_EncryptFinal_ex" or
  target.getQualifiedName().matches("EVP_DecryptInit_ex%") and qn = "EVP_DecryptInit_ex" or
  target.getQualifiedName().matches("EVP_DecryptUpdate%") and qn = "EVP_DecryptUpdate" or
  target.getQualifiedName().matches("EVP_DecryptFinal_ex%") and qn = "EVP_DecryptFinal_ex" or
  target.getQualifiedName().matches("EVP_aes_128_cbc%") and qn = "EVP_aes_128_cbc" or
  target.getQualifiedName().matches("EVP_aes_256_cbc%") and qn = "EVP_aes_256_cbc" or
  target.getQualifiedName().matches("EVP_aes_128_gcm%") and qn = "EVP_aes_128_gcm" or
  target.getQualifiedName().matches("EVP_aes_256_gcm%") and qn = "EVP_aes_256_gcm" or
  target.getQualifiedName().matches("EVP_aes_128_ctr%") and qn = "EVP_aes_128_ctr" or
  target.getQualifiedName().matches("EVP_aes_256_ctr%") and qn = "EVP_aes_256_ctr" or
  target.getQualifiedName().matches("EVP_des_cbc%") and qn = "EVP_des_cbc" or
  target.getQualifiedName().matches("EVP_des_ede3_cbc%") and qn = "EVP_des_ede3_cbc" or
  target.getQualifiedName().matches("EVP_rc4%") and qn = "EVP_rc4" or
  target.getQualifiedName().matches("EVP_rc2_cbc%") and qn = "EVP_rc2_cbc" or
  target.getQualifiedName().matches("EVP_bf_cbc%") and qn = "EVP_bf_cbc" or
  target.getQualifiedName().matches("EVP_cast5_cbc%") and qn = "EVP_cast5_cbc" or
  target.getQualifiedName().matches("EVP_chacha20_poly1305%") and qn = "EVP_chacha20_poly1305" or
  target.getQualifiedName().matches("EVP_aead_chacha20_poly1305%") and qn = "EVP_aead_chacha20_poly1305" or
  target.getQualifiedName().matches("EVP_aead_aes_256_gcm%") and qn = "EVP_aead_aes_256_gcm" or
  target.getQualifiedName().matches("EVP_CIPHER_CTX_new%") and qn = "EVP_CIPHER_CTX_new" or
  target.getQualifiedName().matches("EVP_CIPHER_CTX_free%") and qn = "EVP_CIPHER_CTX_free" or
  target.getQualifiedName().matches("RAND_bytes%") and qn = "RAND_bytes" or
  target.getQualifiedName().matches("RAND_priv_bytes%") and qn = "RAND_priv_bytes" or
  target.getQualifiedName().matches("RAND_poll%") and qn = "RAND_poll" or
  target.getQualifiedName().matches("getrandom%") and qn = "getrandom" or
  target.getQualifiedName().matches("arc4random_buf%") and qn = "arc4random_buf" or
  target.getQualifiedName().matches("CryptGenRandom%") and qn = "CryptGenRandom" or
  target.getQualifiedName().matches("BCryptGenRandom%") and qn = "BCryptGenRandom" or
  target.getQualifiedName().matches("RSA_generate_key_ex%") and qn = "RSA_generate_key_ex" or
  target.getQualifiedName().matches("RSA_new%") and qn = "RSA_new" or
  target.getQualifiedName().matches("RSA_free%") and qn = "RSA_free" or
  target.getQualifiedName().matches("RSA_public_encrypt%") and qn = "RSA_public_encrypt" or
  target.getQualifiedName().matches("RSA_private_decrypt%") and qn = "RSA_private_decrypt" or
  target.getQualifiedName().matches("RSA_sign%") and qn = "RSA_sign" or
  target.getQualifiedName().matches("RSA_verify%") and qn = "RSA_verify" or
  target.getQualifiedName().matches("DSA_generate_parameters_ex%") and qn = "DSA_generate_parameters_ex" or
  target.getQualifiedName().matches("DH_generate_parameters_ex%") and qn = "DH_generate_parameters_ex" or
  target.getQualifiedName().matches("EVP_PKEY_new%") and qn = "EVP_PKEY_new" or
  target.getQualifiedName().matches("EVP_PKEY_assign_RSA%") and qn = "EVP_PKEY_assign_RSA" or
  target.getQualifiedName().matches("EVP_PKEY_free%") and qn = "EVP_PKEY_free" or
  target.getQualifiedName().matches("EVP_PKEY_encrypt%") and qn = "EVP_PKEY_encrypt" or
  target.getQualifiedName().matches("EVP_PKEY_decrypt%") and qn = "EVP_PKEY_decrypt" or
  target.getQualifiedName().matches("EVP_DigestSignInit%") and qn = "EVP_DigestSignInit" or
  target.getQualifiedName().matches("EVP_DigestSignUpdate%") and qn = "EVP_DigestSignUpdate" or
  target.getQualifiedName().matches("EVP_DigestSignFinal%") and qn = "EVP_DigestSignFinal" or
  target.getQualifiedName().matches("EVP_DigestVerifyInit%") and qn = "EVP_DigestVerifyInit" or
  target.getQualifiedName().matches("EVP_DigestVerifyUpdate%") and qn = "EVP_DigestVerifyUpdate" or
  target.getQualifiedName().matches("EVP_DigestVerifyFinal%") and qn = "EVP_DigestVerifyFinal" or
  target.getQualifiedName().matches("BN_new%") and qn = "BN_new" or
  target.getQualifiedName().matches("BN_free%") and qn = "BN_free" or
  target.getQualifiedName().matches("BN_rand%") and qn = "BN_rand" or
  target.getQualifiedName().matches("BN_generate_prime_ex%") and qn = "BN_generate_prime_ex" or
  target.getQualifiedName().matches("CryptCreateHash%") and qn = "CryptCreateHash" or
  target.getQualifiedName().matches("CryptHashData%") and qn = "CryptHashData" or
  target.getQualifiedName().matches("BCryptCreateHash%") and qn = "BCryptCreateHash" or
  target.getQualifiedName().matches("BCryptHashData%") and qn = "BCryptHashData" or
  target.getQualifiedName().matches("BCryptDeriveKeyPBKDF2%") and qn = "BCryptDeriveKeyPBKDF2" or
  target.getQualifiedName().matches("CryptDeriveKey%") and qn = "CryptDeriveKey" or
  target.getQualifiedName().matches("scrypt%") and qn = "scrypt" or
  target.getQualifiedName().matches("EVP_PBE_scrypt%") and qn = "EVP_PBE_scrypt" or
  target.getQualifiedName().matches("bcrypt_hashpw%") and qn = "bcrypt_hashpw" or
  target.getQualifiedName().matches("argon2_hash%") and qn = "argon2_hash" or
  target.getQualifiedName().matches("argon2_verify%") and qn = "argon2_verify" or
  target.getQualifiedName().matches("crypto_hash_sha256%") and qn = "crypto_hash_sha256" or
  target.getQualifiedName().matches("crypto_hash_sha512%") and qn = "crypto_hash_sha512" or
  target.getQualifiedName().matches("crypto_generichash%") and qn = "crypto_generichash" or
  target.getQualifiedName().matches("crypto_aead_chacha20poly1305_encrypt%") and qn = "crypto_aead_chacha20poly1305_encrypt" or
  target.getQualifiedName().matches("crypto_aead_chacha20poly1305_decrypt%") and qn = "crypto_aead_chacha20poly1305_decrypt" or
  target.getQualifiedName().matches("crypto_aead_aes256gcm_encrypt%") and qn = "crypto_aead_aes256gcm_encrypt" or
  target.getQualifiedName().matches("crypto_aead_aes256gcm_decrypt%") and qn = "crypto_aead_aes256gcm_decrypt" or
  target.getQualifiedName().matches("mbedtls_md5%") and qn = "mbedtls_md5" or
  target.getQualifiedName().matches("mbedtls_sha1%") and qn = "mbedtls_sha1" or
  target.getQualifiedName().matches("mbedtls_sha256%") and qn = "mbedtls_sha256" or
  target.getQualifiedName().matches("mbedtls_sha512%") and qn = "mbedtls_sha512" or
  target.getQualifiedName().matches("mbedtls_md_init%") and qn = "mbedtls_md_init" or
  target.getQualifiedName().matches("mbedtls_md_setup%") and qn = "mbedtls_md_setup" or
  target.getQualifiedName().matches("mbedtls_md_update%") and qn = "mbedtls_md_update" or
  target.getQualifiedName().matches("mbedtls_md_finish%") and qn = "mbedtls_md_finish" or
  target.getQualifiedName().matches("mbedtls_aes_setkey_enc%") and qn = "mbedtls_aes_setkey_enc" or
  target.getQualifiedName().matches("mbedtls_aes_crypt_cbc%") and qn = "mbedtls_aes_crypt_cbc" or
  target.getQualifiedName().matches("mbedtls_aes_crypt_ctr%") and qn = "mbedtls_aes_crypt_ctr" or
  target.getQualifiedName().matches("mbedtls_aes_crypt_gcm%") and qn = "mbedtls_aes_crypt_gcm" or
  target.getQualifiedName().matches("mbedtls_cipher_setup%") and qn = "mbedtls_cipher_setup" or
  target.getQualifiedName().matches("mbedtls_cipher_setkey%") and qn = "mbedtls_cipher_setkey" or
  target.getQualifiedName().matches("mbedtls_cipher_crypt%") and qn = "mbedtls_cipher_crypt" or
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
  target.getQualifiedName().matches("CryptoPP%::SHA256%") and qn = "CryptoPP::SHA256" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "CryptoPP") and
    memberFunc.getName() = "SHA256" and
    qn = "CryptoPP::SHA256"
  ) or
  target.getQualifiedName().matches("CryptoPP%::SHA512%") and qn = "CryptoPP::SHA512" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "CryptoPP") and
    memberFunc.getName() = "SHA512" and
    qn = "CryptoPP::SHA512"
  ) or
  target.getQualifiedName().matches("CryptoPP%::HMAC%") and qn = "CryptoPP::HMAC" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "CryptoPP") and
    memberFunc.getName() = "HMAC" and
    qn = "CryptoPP::HMAC"
  ) or
  target.getQualifiedName().matches("CryptoPP%::HMAC_SHA1%") and qn = "CryptoPP::HMAC_SHA1" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "CryptoPP") and
    memberFunc.getName() = "HMAC_SHA1" and
    qn = "CryptoPP::HMAC_SHA1"
  ) or
  target.getQualifiedName().matches("CryptoPP%::HMAC_SHA256%") and qn = "CryptoPP::HMAC_SHA256" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "CryptoPP") and
    memberFunc.getName() = "HMAC_SHA256" and
    qn = "CryptoPP::HMAC_SHA256"
  ) or
  target.getQualifiedName().matches("CryptoPP%::Weak%::MD5%") and qn = "CryptoPP::Weak::MD5" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("CryptoPP", "Weak") and
    memberFunc.getName() = "MD5" and
    qn = "CryptoPP::Weak::MD5"
  ) or
  target.getQualifiedName().matches("CryptoPP%::AES%") and qn = "CryptoPP::AES" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "CryptoPP") and
    memberFunc.getName() = "AES" and
    qn = "CryptoPP::AES"
  ) or
  target.getQualifiedName().matches("CryptoPP%::AES%::Encryption%") and qn = "CryptoPP::AES::Encryption" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("CryptoPP", "AES") and
    memberFunc.getName() = "Encryption" and
    qn = "CryptoPP::AES::Encryption"
  ) or
  target.getQualifiedName().matches("CryptoPP%::AES%::Decryption%") and qn = "CryptoPP::AES::Decryption" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("CryptoPP", "AES") and
    memberFunc.getName() = "Decryption" and
    qn = "CryptoPP::AES::Decryption"
  ) or
  target.getQualifiedName().matches("CryptoPP%::ECB_Mode%") and qn = "CryptoPP::ECB_Mode" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "CryptoPP") and
    memberFunc.getName() = "ECB_Mode" and
    qn = "CryptoPP::ECB_Mode"
  ) or
  target.getQualifiedName().matches("CryptoPP%::CBC_Mode%") and qn = "CryptoPP::CBC_Mode" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "CryptoPP") and
    memberFunc.getName() = "CBC_Mode" and
    qn = "CryptoPP::CBC_Mode"
  ) or
  target.getQualifiedName().matches("CryptoPP%::CTR_Mode%") and qn = "CryptoPP::CTR_Mode" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "CryptoPP") and
    memberFunc.getName() = "CTR_Mode" and
    qn = "CryptoPP::CTR_Mode"
  ) or
  target.getQualifiedName().matches("CryptoPP%::GCM_Mode%") and qn = "CryptoPP::GCM_Mode" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "CryptoPP") and
    memberFunc.getName() = "GCM_Mode" and
    qn = "CryptoPP::GCM_Mode"
  ) or
  target.getQualifiedName().matches("CryptoPP%::RC4%") and qn = "CryptoPP::RC4" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "CryptoPP") and
    memberFunc.getName() = "RC4" and
    qn = "CryptoPP::RC4"
  ) or
  target.getQualifiedName().matches("CryptoPP%::TripleDES%") and qn = "CryptoPP::TripleDES" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "CryptoPP") and
    memberFunc.getName() = "TripleDES" and
    qn = "CryptoPP::TripleDES"
  ) or
  target.getQualifiedName().matches("CryptoPP%::DES%") and qn = "CryptoPP::DES" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "CryptoPP") and
    memberFunc.getName() = "DES" and
    qn = "CryptoPP::DES"
  ) or
  target.getQualifiedName().matches("Botan%::MD5%") and qn = "Botan::MD5" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "Botan") and
    memberFunc.getName() = "MD5" and
    qn = "Botan::MD5"
  ) or
  target.getQualifiedName().matches("Botan%::SHA_1%") and qn = "Botan::SHA_1" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "Botan") and
    memberFunc.getName() = "SHA_1" and
    qn = "Botan::SHA_1"
  ) or
  target.getQualifiedName().matches("Botan%::SHA_256%") and qn = "Botan::SHA_256" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "Botan") and
    memberFunc.getName() = "SHA_256" and
    qn = "Botan::SHA_256"
  ) or
  target.getQualifiedName().matches("Botan%::SHA_512%") and qn = "Botan::SHA_512" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "Botan") and
    memberFunc.getName() = "SHA_512" and
    qn = "Botan::SHA_512"
  ) or
  target.getQualifiedName().matches("Botan%::HMAC%") and qn = "Botan::HMAC" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "Botan") and
    memberFunc.getName() = "HMAC" and
    qn = "Botan::HMAC"
  ) or
  target.getQualifiedName().matches("Botan%::PBKDF2%") and qn = "Botan::PBKDF2" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "Botan") and
    memberFunc.getName() = "PBKDF2" and
    qn = "Botan::PBKDF2"
  ) or
  target.getQualifiedName().matches("Botan%::Scrypt%") and qn = "Botan::Scrypt" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "Botan") and
    memberFunc.getName() = "Scrypt" and
    qn = "Botan::Scrypt"
  ) or
  target.getQualifiedName().matches("Botan%::argon2%") and qn = "Botan::argon2" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "Botan") and
    memberFunc.getName() = "argon2" and
    qn = "Botan::argon2"
  ) or
  target.getQualifiedName().matches("Botan%::AES_128%") and qn = "Botan::AES_128" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "Botan") and
    memberFunc.getName() = "AES_128" and
    qn = "Botan::AES_128"
  ) or
  target.getQualifiedName().matches("Botan%::AES_256%") and qn = "Botan::AES_256" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "Botan") and
    memberFunc.getName() = "AES_256" and
    qn = "Botan::AES_256"
  ) or
  target.getQualifiedName().matches("Botan%::AES_128/GCM%") and qn = "Botan::AES_128/GCM" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "Botan") and
    memberFunc.getName() = "AES_128/GCM" and
    qn = "Botan::AES_128/GCM"
  ) or
  target.getQualifiedName().matches("Botan%::AES_256/GCM%") and qn = "Botan::AES_256/GCM" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "Botan") and
    memberFunc.getName() = "AES_256/GCM" and
    qn = "Botan::AES_256/GCM"
  ) or
  target.getQualifiedName().matches("Botan%::ChaCha20Poly1305%") and qn = "Botan::ChaCha20Poly1305" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "Botan") and
    memberFunc.getName() = "ChaCha20Poly1305" and
    qn = "Botan::ChaCha20Poly1305"
  ) or
  target.getQualifiedName().matches("WolfSSL_MD5_Init%") and qn = "WolfSSL_MD5_Init" or
  target.getQualifiedName().matches("WolfSSL_SHA_Init%") and qn = "WolfSSL_SHA_Init" or
  target.getQualifiedName().matches("wolfSSL_MD5_Update%") and qn = "wolfSSL_MD5_Update" or
  target.getQualifiedName().matches("wolfSSL_SHA1_Update%") and qn = "wolfSSL_SHA1_Update" or
  target.getQualifiedName().matches("wolfSSL_SHA256_Update%") and qn = "wolfSSL_SHA256_Update" or
  target.getQualifiedName().matches("QCryptographicHash%::Md5%") and qn = "QCryptographicHash::Md5" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QCryptographicHash") and
    memberFunc.getName() = "Md5" and
    qn = "QCryptographicHash::Md5"
  ) or
  target.getQualifiedName().matches("QCryptographicHash%::Sha1%") and qn = "QCryptographicHash::Sha1" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QCryptographicHash") and
    memberFunc.getName() = "Sha1" and
    qn = "QCryptographicHash::Sha1"
  ) or
  target.getQualifiedName().matches("QCryptographicHash%::Sha256%") and qn = "QCryptographicHash::Sha256" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QCryptographicHash") and
    memberFunc.getName() = "Sha256" and
    qn = "QCryptographicHash::Sha256"
  ) or
  target.getQualifiedName().matches("QCA%::MD5%") and qn = "QCA::MD5" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QCA") and
    memberFunc.getName() = "MD5" and
    qn = "QCA::MD5"
  ) or
  target.getQualifiedName().matches("QCA%::SHA1%") and qn = "QCA::SHA1" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QCA") and
    memberFunc.getName() = "SHA1" and
    qn = "QCA::SHA1"
  ) or
  target.getQualifiedName().matches("QCA%::SHA256%") and qn = "QCA::SHA256" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QCA") and
    memberFunc.getName() = "SHA256" and
    qn = "QCA::SHA256"
  ) or
  target.getQualifiedName().matches("Windows%::Security%::Cryptography%::Core%::HashAlgorithmNames%::md5%") and qn = "Windows::Security::Cryptography::Core::HashAlgorithmNames::md5" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Windows::Security::Cryptography::Core", "HashAlgorithmNames") and
    memberFunc.getName() = "md5" and
    qn = "Windows::Security::Cryptography::Core::HashAlgorithmNames::md5"
  ) or
  target.getQualifiedName().matches("Windows%::Security%::Cryptography%::Core%::HashAlgorithmNames%::sha1%") and qn = "Windows::Security::Cryptography::Core::HashAlgorithmNames::sha1" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Windows::Security::Cryptography::Core", "HashAlgorithmNames") and
    memberFunc.getName() = "sha1" and
    qn = "Windows::Security::Cryptography::Core::HashAlgorithmNames::sha1"
  ) or
  target.getQualifiedName().matches("OpenSSL_add_all_digests%") and qn = "OpenSSL_add_all_digests" or
  target.getQualifiedName().matches("OpenSSL_add_all_ciphers%") and qn = "OpenSSL_add_all_ciphers" or
  target.getQualifiedName().matches("EVP_get_cipherbyname%") and qn = "EVP_get_cipherbyname" or
  target.getQualifiedName().matches("EVP_set_cipherbyname%") and qn = "EVP_set_cipherbyname" or
  target.getQualifiedName().matches("EVP_set_digestbyname%") and qn = "EVP_set_digestbyname" or
  target.getQualifiedName().matches("PKCS7_sign%") and qn = "PKCS7_sign" or
  target.getQualifiedName().matches("PKCS7_verify%") and qn = "PKCS7_verify" or
  target.getQualifiedName().matches("CMS_sign%") and qn = "CMS_sign" or
  target.getQualifiedName().matches("CMS_verify%") and qn = "CMS_verify" or
  target.getQualifiedName().matches("SSL_CTX_set_cipher_list%") and qn = "SSL_CTX_set_cipher_list" or
  target.getQualifiedName().matches("SSL_set_cipher_list%") and qn = "SSL_set_cipher_list" or
  target.getQualifiedName().matches("SSL_CTX_set_min_proto_version%") and qn = "SSL_CTX_set_min_proto_version" or
  target.getQualifiedName().matches("mbedtls_ssl_conf_min_version%") and qn = "mbedtls_ssl_conf_min_version" or
  target.getQualifiedName().matches("mbedtls_ssl_conf_ciphersuites%") and qn = "mbedtls_ssl_conf_ciphersuites" or
  target.getQualifiedName().matches("NSS_PK11_CreateDigest%") and qn = "NSS_PK11_CreateDigest" or
  target.getQualifiedName().matches("NSS_PK11_Digest%") and qn = "NSS_PK11_Digest" or
  target.getQualifiedName().matches("NSS_PK11_Sign%") and qn = "NSS_PK11_Sign" or
  target.getQualifiedName().matches("NSS_PK11_Verify%") and qn = "NSS_PK11_Verify" or
  target.getQualifiedName().matches("EVP_PKEY_new_raw_private_key%") and qn = "EVP_PKEY_new_raw_private_key" or
  target.getQualifiedName().matches("EVP_PKEY_new_raw_public_key%") and qn = "EVP_PKEY_new_raw_public_key" or
  target.getQualifiedName().matches("EVP_PKEY_set1_RSA%") and qn = "EVP_PKEY_set1_RSA" or
  target.getQualifiedName().matches("EVP_MAC_init%") and qn = "EVP_MAC_init" or
  target.getQualifiedName().matches("EVP_MAC_update%") and qn = "EVP_MAC_update" or
  target.getQualifiedName().matches("EVP_MAC_final%") and qn = "EVP_MAC_final" or
  target.getQualifiedName().matches("EVP_MAC_CTX_new%") and qn = "EVP_MAC_CTX_new" or
  target.getQualifiedName().matches("EVP_MAC_CTX_free%") and qn = "EVP_MAC_CTX_free" or
  target.getQualifiedName().matches("EVP_aead_aes_128_gcm%") and qn = "EVP_aead_aes_128_gcm" or
  target.getQualifiedName().matches("crypto_box_easy%") and qn = "crypto_box_easy" or
  target.getQualifiedName().matches("crypto_box_open_easy%") and qn = "crypto_box_open_easy" or
  target.getQualifiedName().matches("sodium_init%") and qn = "sodium_init" or
  target.getQualifiedName().matches("sodium_mlock%") and qn = "sodium_mlock" or
  target.getQualifiedName().matches("sodium_munlock%") and qn = "sodium_munlock" or
  target.getQualifiedName().matches("PKCS12_create%") and qn = "PKCS12_create" or
  target.getQualifiedName().matches("PKCS12_parse%") and qn = "PKCS12_parse" or
  target.getQualifiedName().matches("X509_get_pubkey%") and qn = "X509_get_pubkey" or
  target.getQualifiedName().matches("X509_sign%") and qn = "X509_sign" or
  target.getQualifiedName().matches("X509_verify%") and qn = "X509_verify" or
  target.getQualifiedName().matches("EVP_CIPHER_block_size%") and qn = "EVP_CIPHER_block_size" or
  target.getQualifiedName().matches("EVP_CIPHER_key_length%") and qn = "EVP_CIPHER_key_length" or
  target.getQualifiedName().matches("EVP_CIPHER_iv_length%") and qn = "EVP_CIPHER_iv_length" or
  target.getQualifiedName().matches("EVP_MD_block_size%") and qn = "EVP_MD_block_size" or
  target.getQualifiedName().matches("EVP_MD_size%") and qn = "EVP_MD_size" or
  target.getQualifiedName().matches("mbedtls_entropy_init%") and qn = "mbedtls_entropy_init" or
  target.getQualifiedName().matches("mbedtls_ctr_drbg_seed%") and qn = "mbedtls_ctr_drbg_seed" or
  target.getQualifiedName().matches("mbedtls_ctr_drbg_random%") and qn = "mbedtls_ctr_drbg_random" or
  target.getQualifiedName().matches("getentropy%") and qn = "getentropy" or
  target.getQualifiedName().matches("arc4random%") and qn = "arc4random" or
  target.getQualifiedName().matches("arc4random_uniform%") and qn = "arc4random_uniform" or
  target.getQualifiedName().matches("RAND_status%") and qn = "RAND_status" or
  target.getQualifiedName().matches("RtlGenRandom%") and qn = "RtlGenRandom" or
  target.getQualifiedName().matches("BCryptOpenAlgorithmProvider%") and qn = "BCryptOpenAlgorithmProvider" or
  target.getQualifiedName().matches("BCryptGenerateSymmetricKey%") and qn = "BCryptGenerateSymmetricKey" or
  target.getQualifiedName().matches("BCryptEncrypt%") and qn = "BCryptEncrypt" or
  target.getQualifiedName().matches("BCryptDecrypt%") and qn = "BCryptDecrypt" or
  target.getQualifiedName().matches("SslCreateContext%") and qn = "SslCreateContext" or
  target.getQualifiedName().matches("SslFreeContext%") and qn = "SslFreeContext" or
  target.getQualifiedName().matches("SslSetCipherList%") and qn = "SslSetCipherList" or
  target.getQualifiedName().matches("PKCS11_C_GetFunctionList%") and qn = "PKCS11_C_GetFunctionList" or
  target.getQualifiedName().matches("PKCS11_C_GenerateKey%") and qn = "PKCS11_C_GenerateKey" or
  target.getQualifiedName().matches("PKCS11_C_GenerateRandom%") and qn = "PKCS11_C_GenerateRandom" or
  target.getQualifiedName().matches("PKCS11_C_DeriveKey%") and qn = "PKCS11_C_DeriveKey" or
  target.getQualifiedName().matches("PKCS11_C_Sign%") and qn = "PKCS11_C_Sign" or
  target.getQualifiedName().matches("PKCS11_C_Verify%") and qn = "PKCS11_C_Verify" or
  target.getQualifiedName().matches("SECMOD_ListModules%") and qn = "SECMOD_ListModules" or
  target.getQualifiedName().matches("SECMOD_LoadModule%") and qn = "SECMOD_LoadModule" or
  target.getQualifiedName().matches("EVP_PBE_pbkdf2%") and qn = "EVP_PBE_pbkdf2" or
  target.getQualifiedName().matches("EVP_PBE_pbkdf1%") and qn = "EVP_PBE_pbkdf1" or
  target.getQualifiedName().matches("PKCS5_PBKDF2_HMAC_SHA256%") and qn = "PKCS5_PBKDF2_HMAC_SHA256" or
  target.getQualifiedName().matches("PKCS5_PBKDF2_HMAC_SHA512%") and qn = "PKCS5_PBKDF2_HMAC_SHA512" or
  target.getQualifiedName().matches("EVP_SealInit%") and qn = "EVP_SealInit" or
  target.getQualifiedName().matches("EVP_OpenInit%") and qn = "EVP_OpenInit" or
  target.getQualifiedName().matches("EVP_SealUpdate%") and qn = "EVP_SealUpdate" or
  target.getQualifiedName().matches("EVP_OpenUpdate%") and qn = "EVP_OpenUpdate" or
  target.getQualifiedName().matches("EVP_SealFinal%") and qn = "EVP_SealFinal" or
  target.getQualifiedName().matches("EVP_OpenFinal%") and qn = "EVP_OpenFinal" or
  target.getQualifiedName().matches("CMS_encrypt%") and qn = "CMS_encrypt" or
  target.getQualifiedName().matches("CMS_decrypt%") and qn = "CMS_decrypt" or
  target.getQualifiedName().matches("SSL_get_current_cipher%") and qn = "SSL_get_current_cipher" or
  target.getQualifiedName().matches("SSL_CIPHER_get_name%") and qn = "SSL_CIPHER_get_name" or
  target.getQualifiedName().matches("EVP_CIPHER_CTX_ctrl%") and qn = "EVP_CIPHER_CTX_ctrl" or
  target.getQualifiedName().matches("EVP_MD_ctrl%") and qn = "EVP_MD_ctrl" or
  target.getQualifiedName().matches("EC_KEY_generate_key%") and qn = "EC_KEY_generate_key" or
  target.getQualifiedName().matches("EC_KEY_check_key%") and qn = "EC_KEY_check_key" or
  target.getQualifiedName().matches("ECDSA_sign%") and qn = "ECDSA_sign" or
  target.getQualifiedName().matches("ECDSA_verify%") and qn = "ECDSA_verify" or
  target.getQualifiedName().matches("EVP_PKEY_keygen_init%") and qn = "EVP_PKEY_keygen_init" or
  target.getQualifiedName().matches("EVP_PKEY_keygen%") and qn = "EVP_PKEY_keygen" or
  target.getQualifiedName().matches("EVP_PKEY_paramgen_init%") and qn = "EVP_PKEY_paramgen_init" or
  target.getQualifiedName().matches("EVP_PKEY_paramgen%") and qn = "EVP_PKEY_paramgen" or
  target.getQualifiedName().matches("DH_generate_key%") and qn = "DH_generate_key" or
  target.getQualifiedName().matches("DH_compute_key%") and qn = "DH_compute_key" or
  target.getQualifiedName().matches("DSA_sign%") and qn = "DSA_sign" or
  target.getQualifiedName().matches("DSA_verify%") and qn = "DSA_verify" or
  target.getQualifiedName().matches("RSA_padding_add_PKCS1_OAEP%") and qn = "RSA_padding_add_PKCS1_OAEP" or
  target.getQualifiedName().matches("RSA_padding_check_PKCS1_OAEP%") and qn = "RSA_padding_check_PKCS1_OAEP" or
  target.getQualifiedName().matches("RSA_padding_add_PKCS1_PSS%") and qn = "RSA_padding_add_PKCS1_PSS" or
  target.getQualifiedName().matches("RSA_verify_PKCS1_PSS%") and qn = "RSA_verify_PKCS1_PSS" or
  target.getQualifiedName().matches("EVP_CipherInit_ex%") and qn = "EVP_CipherInit_ex" or
  target.getQualifiedName().matches("EVP_CipherUpdate%") and qn = "EVP_CipherUpdate" or
  target.getQualifiedName().matches("EVP_CipherFinal_ex%") and qn = "EVP_CipherFinal_ex" or
  target.getQualifiedName().matches("PKCS12_create_cert%") and qn = "PKCS12_create_cert" or
  target.getQualifiedName().matches("X509_REQ_new%") and qn = "X509_REQ_new" or
  target.getQualifiedName().matches("X509_REQ_sign%") and qn = "X509_REQ_sign" or
  target.getQualifiedName().matches("X509_REQ_verify%") and qn = "X509_REQ_verify" or
  target.getQualifiedName().matches("EVP_PKEY_get1_RSA%") and qn = "EVP_PKEY_get1_RSA" or
  target.getQualifiedName().matches("EVP_PKEY_get1_DSA%") and qn = "EVP_PKEY_get1_DSA" or
  target.getQualifiedName().matches("EVP_PKEY_get1_EC_KEY%") and qn = "EVP_PKEY_get1_EC_KEY" or
  target.getQualifiedName().matches("EVP_PKEY_set_alias_type%") and qn = "EVP_PKEY_set_alias_type" or
  target.getQualifiedName().matches("EVP_PKEY_set_alias_type_RSA%") and qn = "EVP_PKEY_set_alias_type_RSA" or
  target.getQualifiedName().matches("EVP_PKEY_set_alias_type_DSA%") and qn = "EVP_PKEY_set_alias_type_DSA" or
  target.getQualifiedName().matches("EVP_PKEY_set_alias_type_EC%") and qn = "EVP_PKEY_set_alias_type_EC" or
  target.getQualifiedName().matches("EVP_PKEY_assign%") and qn = "EVP_PKEY_assign" or
  target.getQualifiedName().matches("EVP_SealInit_ex%") and qn = "EVP_SealInit_ex" or
  target.getQualifiedName().matches("EVP_OpenInit_ex%") and qn = "EVP_OpenInit_ex" or
  target.getQualifiedName().matches("PKCS7_encrypt%") and qn = "PKCS7_encrypt" or
  target.getQualifiedName().matches("PKCS7_decrypt%") and qn = "PKCS7_decrypt" or
  target.getQualifiedName().matches("RSA_blinding_on%") and qn = "RSA_blinding_on" or
  target.getQualifiedName().matches("RSA_blinding_off%") and qn = "RSA_blinding_off" or
  target.getQualifiedName().matches("CMS_sign_receipt%") and qn = "CMS_sign_receipt" or
  target.getQualifiedName().matches("CMS_verify_receipt%") and qn = "CMS_verify_receipt" or
  target.getQualifiedName().matches("ssl_library_init%") and qn = "ssl_library_init" or
  target.getQualifiedName().matches("SSL_library_init%") and qn = "SSL_library_init" or
  target.getQualifiedName().matches("SSLeay%") and qn = "SSLeay" or
  target.getQualifiedName().matches("SSLeay_version%") and qn = "SSLeay_version" or
  target.getQualifiedName().matches("ERR_get_error%") and qn = "ERR_get_error" or
  target.getQualifiedName().matches("ERR_error_string%") and qn = "ERR_error_string" or
  target.getQualifiedName().matches("ENGINE_by_id%") and qn = "ENGINE_by_id" or
  target.getQualifiedName().matches("ENGINE_finish%") and qn = "ENGINE_finish" or
  target.getQualifiedName().matches("ENGINE_load_builtin_engines%") and qn = "ENGINE_load_builtin_engines" or
  target.getQualifiedName().matches("ENGINE_cleanup%") and qn = "ENGINE_cleanup" or
  target.getQualifiedName().matches("PKCS11_FindObjectsInit%") and qn = "PKCS11_FindObjectsInit" or
  target.getQualifiedName().matches("PKCS11_FindObjects%") and qn = "PKCS11_FindObjects" or
  target.getQualifiedName().matches("PKCS11_FindObjectsFinal%") and qn = "PKCS11_FindObjectsFinal"
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
