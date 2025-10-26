// Auto-generated; CWE-329; number of APIs 84
import cpp

predicate isTargetApi(Function target, string qn) {
  target.getQualifiedName().matches("EVP_EncryptInit%") and qn = "EVP_EncryptInit" or
  target.getQualifiedName().matches("EVP_EncryptInit_ex%") and qn = "EVP_EncryptInit_ex" or
  target.getQualifiedName().matches("EVP_DecryptInit%") and qn = "EVP_DecryptInit" or
  target.getQualifiedName().matches("EVP_DecryptInit_ex%") and qn = "EVP_DecryptInit_ex" or
  target.getQualifiedName().matches("EVP_CipherInit_ex%") and qn = "EVP_CipherInit_ex" or
  target.getQualifiedName().matches("EVP_CIPHER_CTX_ctrl%") and qn = "EVP_CIPHER_CTX_ctrl" or
  target.getQualifiedName().matches("EVP_CIPHER_CTX_iv_length%") and qn = "EVP_CIPHER_CTX_iv_length" or
  target.getQualifiedName().matches("EVP_aes_128_cbc%") and qn = "EVP_aes_128_cbc" or
  target.getQualifiedName().matches("EVP_aes_192_cbc%") and qn = "EVP_aes_192_cbc" or
  target.getQualifiedName().matches("EVP_aes_256_cbc%") and qn = "EVP_aes_256_cbc" or
  target.getQualifiedName().matches("AES_cbc_encrypt%") and qn = "AES_cbc_encrypt" or
  target.getQualifiedName().matches("AES_cbc_decrypt%") and qn = "AES_cbc_decrypt" or
  target.getQualifiedName().matches("DES_ncbc_encrypt%") and qn = "DES_ncbc_encrypt" or
  target.getQualifiedName().matches("DES_ede3_cbc_encrypt%") and qn = "DES_ede3_cbc_encrypt" or
  target.getQualifiedName().matches("RC2_cbc_encrypt%") and qn = "RC2_cbc_encrypt" or
  target.getQualifiedName().matches("RC5_32_12_16_cbc_encrypt%") and qn = "RC5_32_12_16_cbc_encrypt" or
  target.getQualifiedName().matches("RAND_bytes%") and qn = "RAND_bytes" or
  target.getQualifiedName().matches("RAND_priv_bytes%") and qn = "RAND_priv_bytes" or
  target.getQualifiedName().matches("RAND_pseudo_bytes%") and qn = "RAND_pseudo_bytes" or
  target.getQualifiedName().matches("HMAC_Init_ex%") and qn = "HMAC_Init_ex" or
  target.getQualifiedName().matches("PKCS5_PBKDF2_HMAC%") and qn = "PKCS5_PBKDF2_HMAC" or
  target.getQualifiedName().matches("PKCS5_PBKDF2_HMAC_SHA1%") and qn = "PKCS5_PBKDF2_HMAC_SHA1" or
  target.getQualifiedName().matches("EVP_BytesToKey%") and qn = "EVP_BytesToKey" or
  target.getQualifiedName().matches("mbedtls_cipher_set_iv%") and qn = "mbedtls_cipher_set_iv" or
  target.getQualifiedName().matches("mbedtls_cipher_reset%") and qn = "mbedtls_cipher_reset" or
  target.getQualifiedName().matches("mbedtls_aes_crypt_cbc%") and qn = "mbedtls_aes_crypt_cbc" or
  target.getQualifiedName().matches("mbedtls_des_crypt_cbc%") and qn = "mbedtls_des_crypt_cbc" or
  target.getQualifiedName().matches("mbedtls_cipher_update%") and qn = "mbedtls_cipher_update" or
  target.getQualifiedName().matches("mbedtls_ctr_drbg_random%") and qn = "mbedtls_ctr_drbg_random" or
  target.getQualifiedName().matches("mbedtls_entropy_func%") and qn = "mbedtls_entropy_func" or
  target.getQualifiedName().matches("gcry_cipher_setiv%") and qn = "gcry_cipher_setiv" or
  target.getQualifiedName().matches("gcry_cipher_reset%") and qn = "gcry_cipher_reset" or
  target.getQualifiedName().matches("gcry_cipher_encrypt%") and qn = "gcry_cipher_encrypt" or
  target.getQualifiedName().matches("gcry_randomize%") and qn = "gcry_randomize" or
  target.getQualifiedName().matches("gcry_create_nonce%") and qn = "gcry_create_nonce" or
  target.getQualifiedName().matches("gnutls_cipher_set_iv%") and qn = "gnutls_cipher_set_iv" or
  target.getQualifiedName().matches("gnutls_cipher_init%") and qn = "gnutls_cipher_init" or
  target.getQualifiedName().matches("gnutls_rnd%") and qn = "gnutls_rnd" or
  target.getQualifiedName().matches("PK11_ParamFromIV%") and qn = "PK11_ParamFromIV" or
  target.getQualifiedName().matches("PK11_CipherOp%") and qn = "PK11_CipherOp" or
  target.getQualifiedName().matches("CryptSetKeyParam%") and qn = "CryptSetKeyParam" or
  target.getQualifiedName().matches("CryptEncrypt%") and qn = "CryptEncrypt" or
  target.getQualifiedName().matches("CryptGenRandom%") and qn = "CryptGenRandom" or
  target.getQualifiedName().matches("BCryptSetProperty%") and qn = "BCryptSetProperty" or
  target.getQualifiedName().matches("BCryptEncrypt%") and qn = "BCryptEncrypt" or
  target.getQualifiedName().matches("BCryptGenerateSymmetricKey%") and qn = "BCryptGenerateSymmetricKey" or
  target.getQualifiedName().matches("CryptoPP%::CBC_Mode< AES >%::Encryption%::SetKeyWithIV%") and qn = "CryptoPP::CBC_Mode< AES >::Encryption::SetKeyWithIV" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("CryptoPP::CBC_Mode< AES >", "Encryption") and
    memberFunc.getName() = "SetKeyWithIV" and
    qn = "CryptoPP::CBC_Mode< AES >::Encryption::SetKeyWithIV"
  ) or
  target.getQualifiedName().matches("CryptoPP%::CBC_Mode< AES >%::Decryption%::SetKeyWithIV%") and qn = "CryptoPP::CBC_Mode< AES >::Decryption::SetKeyWithIV" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("CryptoPP::CBC_Mode< AES >", "Decryption") and
    memberFunc.getName() = "SetKeyWithIV" and
    qn = "CryptoPP::CBC_Mode< AES >::Decryption::SetKeyWithIV"
  ) or
  target.getQualifiedName().matches("CryptoPP%::CBC_Mode< DES >%::Encryption%::SetKeyWithIV%") and qn = "CryptoPP::CBC_Mode< DES >::Encryption::SetKeyWithIV" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("CryptoPP::CBC_Mode< DES >", "Encryption") and
    memberFunc.getName() = "SetKeyWithIV" and
    qn = "CryptoPP::CBC_Mode< DES >::Encryption::SetKeyWithIV"
  ) or
  target.getQualifiedName().matches("CryptoPP%::CBC_Mode< DES_EDE3 >%::Encryption%::SetKeyWithIV%") and qn = "CryptoPP::CBC_Mode< DES_EDE3 >::Encryption::SetKeyWithIV" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("CryptoPP::CBC_Mode< DES_EDE3 >", "Encryption") and
    memberFunc.getName() = "SetKeyWithIV" and
    qn = "CryptoPP::CBC_Mode< DES_EDE3 >::Encryption::SetKeyWithIV"
  ) or
  target.getQualifiedName().matches("CryptoPP%::CBC_Mode< Blowfish >%::Encryption%::SetKeyWithIV%") and qn = "CryptoPP::CBC_Mode< Blowfish >::Encryption::SetKeyWithIV" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("CryptoPP::CBC_Mode< Blowfish >", "Encryption") and
    memberFunc.getName() = "SetKeyWithIV" and
    qn = "CryptoPP::CBC_Mode< Blowfish >::Encryption::SetKeyWithIV"
  ) or
  target.getQualifiedName().matches("CryptoPP%::CBC_Mode_ExternalCipher%::Encryption%::SetKeyWithIV%") and qn = "CryptoPP::CBC_Mode_ExternalCipher::Encryption::SetKeyWithIV" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("CryptoPP::CBC_Mode_ExternalCipher", "Encryption") and
    memberFunc.getName() = "SetKeyWithIV" and
    qn = "CryptoPP::CBC_Mode_ExternalCipher::Encryption::SetKeyWithIV"
  ) or
  target.getQualifiedName().matches("CryptoPP%::CBC_Mode_ExternalCipher%::Decryption%::SetKeyWithIV%") and qn = "CryptoPP::CBC_Mode_ExternalCipher::Decryption::SetKeyWithIV" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("CryptoPP::CBC_Mode_ExternalCipher", "Decryption") and
    memberFunc.getName() = "SetKeyWithIV" and
    qn = "CryptoPP::CBC_Mode_ExternalCipher::Decryption::SetKeyWithIV"
  ) or
  target.getQualifiedName().matches("Botan%::Cipher_Mode%::start%") and qn = "Botan::Cipher_Mode::start" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Botan", "Cipher_Mode") and
    memberFunc.getName() = "start" and
    qn = "Botan::Cipher_Mode::start"
  ) or
  target.getQualifiedName().matches("Botan%::Cipher_Mode%::set_key%") and qn = "Botan::Cipher_Mode::set_key" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Botan", "Cipher_Mode") and
    memberFunc.getName() = "set_key" and
    qn = "Botan::Cipher_Mode::set_key"
  ) or
  target.getQualifiedName().matches("Botan%::InitializationVector%") and qn = "Botan::InitializationVector" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "Botan") and
    memberFunc.getName() = "InitializationVector" and
    qn = "Botan::InitializationVector"
  ) or
  target.getQualifiedName().matches("nettle_cbc_encrypt%") and qn = "nettle_cbc_encrypt" or
  target.getQualifiedName().matches("nettle_cbc_decrypt%") and qn = "nettle_cbc_decrypt" or
  target.getQualifiedName().matches("nettle_aes128_cbc_encrypt%") and qn = "nettle_aes128_cbc_encrypt" or
  target.getQualifiedName().matches("nettle_aes128_cbc_decrypt%") and qn = "nettle_aes128_cbc_decrypt" or
  target.getQualifiedName().matches("nettle_des_cbc_encrypt%") and qn = "nettle_des_cbc_encrypt" or
  target.getQualifiedName().matches("nettle_des_cbc_decrypt%") and qn = "nettle_des_cbc_decrypt" or
  target.getQualifiedName().matches("NSS%::PK11_Encrypt%") and qn = "NSS::PK11_Encrypt" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "NSS") and
    memberFunc.getName() = "PK11_Encrypt" and
    qn = "NSS::PK11_Encrypt"
  ) or
  target.getQualifiedName().matches("NSS%::PK11_Decrypt%") and qn = "NSS::PK11_Decrypt" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "NSS") and
    memberFunc.getName() = "PK11_Decrypt" and
    qn = "NSS::PK11_Decrypt"
  ) or
  target.getQualifiedName().matches("std%::rand%") and qn = "std::rand" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "std") and
    memberFunc.getName() = "rand" and
    qn = "std::rand"
  ) or
  target.getQualifiedName().matches("std%::srand%") and qn = "std::srand" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "std") and
    memberFunc.getName() = "srand" and
    qn = "std::srand"
  ) or
  target.getQualifiedName().matches("rand%") and qn = "rand" or
  target.getQualifiedName().matches("srand%") and qn = "srand" or
  target.getQualifiedName().matches("random%") and qn = "random" or
  target.getQualifiedName().matches("srandom%") and qn = "srandom" or
  target.getQualifiedName().matches("drand48%") and qn = "drand48" or
  target.getQualifiedName().matches("erand48%") and qn = "erand48" or
  target.getQualifiedName().matches("lrand48%") and qn = "lrand48" or
  target.getQualifiedName().matches("mrand48%") and qn = "mrand48" or
  target.getQualifiedName().matches("seed48%") and qn = "seed48" or
  target.getQualifiedName().matches("initstate%") and qn = "initstate" or
  target.getQualifiedName().matches("setstate%") and qn = "setstate" or
  target.getQualifiedName().matches("std%::mt19937%") and qn = "std::mt19937" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "std") and
    memberFunc.getName() = "mt19937" and
    qn = "std::mt19937"
  ) or
  target.getQualifiedName().matches("std%::default_random_engine%") and qn = "std::default_random_engine" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "std") and
    memberFunc.getName() = "default_random_engine" and
    qn = "std::default_random_engine"
  ) or
  target.getQualifiedName().matches("time%") and qn = "time" or
  target.getQualifiedName().matches("std%::time%") and qn = "std::time" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "std") and
    memberFunc.getName() = "time" and
    qn = "std::time"
  ) or
  target.getQualifiedName().matches("gettimeofday%") and qn = "gettimeofday" or
  target.getQualifiedName().matches("clock_gettime%") and qn = "clock_gettime" or
  target.getQualifiedName().matches("QueryPerformanceCounter%") and qn = "QueryPerformanceCounter"
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
