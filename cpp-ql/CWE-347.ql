// Auto-generated; CWE-347; number of APIs 58
import cpp

predicate isTargetApi(Function target, string qn) {
  target.getQualifiedName().matches("EVP_DigestVerifyInit%") and qn = "EVP_DigestVerifyInit" or
  target.getQualifiedName().matches("EVP_DigestVerifyUpdate%") and qn = "EVP_DigestVerifyUpdate" or
  target.getQualifiedName().matches("EVP_DigestVerifyFinal%") and qn = "EVP_DigestVerifyFinal" or
  target.getQualifiedName().matches("EVP_DigestVerify%") and qn = "EVP_DigestVerify" or
  target.getQualifiedName().matches("EVP_VerifyInit%") and qn = "EVP_VerifyInit" or
  target.getQualifiedName().matches("EVP_VerifyUpdate%") and qn = "EVP_VerifyUpdate" or
  target.getQualifiedName().matches("EVP_VerifyFinal%") and qn = "EVP_VerifyFinal" or
  target.getQualifiedName().matches("EVP_PKEY_verify_init%") and qn = "EVP_PKEY_verify_init" or
  target.getQualifiedName().matches("EVP_PKEY_verify%") and qn = "EVP_PKEY_verify" or
  target.getQualifiedName().matches("EVP_PKEY_CTX_set_signature_md%") and qn = "EVP_PKEY_CTX_set_signature_md" or
  target.getQualifiedName().matches("EVP_PKEY_CTX_set_rsa_padding%") and qn = "EVP_PKEY_CTX_set_rsa_padding" or
  target.getQualifiedName().matches("RSA_verify%") and qn = "RSA_verify" or
  target.getQualifiedName().matches("RSA_verify_PKCS1_PSS_mgf1%") and qn = "RSA_verify_PKCS1_PSS_mgf1" or
  target.getQualifiedName().matches("DSA_do_verify%") and qn = "DSA_do_verify" or
  target.getQualifiedName().matches("ECDSA_verify%") and qn = "ECDSA_verify" or
  target.getQualifiedName().matches("ECDSA_do_verify%") and qn = "ECDSA_do_verify" or
  target.getQualifiedName().matches("ED25519_verify%") and qn = "ED25519_verify" or
  target.getQualifiedName().matches("X509_verify%") and qn = "X509_verify" or
  target.getQualifiedName().matches("X509_verify_cert%") and qn = "X509_verify_cert" or
  target.getQualifiedName().matches("X509_CRL_verify%") and qn = "X509_CRL_verify" or
  target.getQualifiedName().matches("mbedtls_pk_verify%") and qn = "mbedtls_pk_verify" or
  target.getQualifiedName().matches("mbedtls_pk_verify_ext%") and qn = "mbedtls_pk_verify_ext" or
  target.getQualifiedName().matches("mbedtls_rsa_pkcs1_verify%") and qn = "mbedtls_rsa_pkcs1_verify" or
  target.getQualifiedName().matches("mbedtls_rsa_rsassa_pss_verify%") and qn = "mbedtls_rsa_rsassa_pss_verify" or
  target.getQualifiedName().matches("mbedtls_ecdsa_read_signature%") and qn = "mbedtls_ecdsa_read_signature" or
  target.getQualifiedName().matches("mbedtls_ecdsa_verify%") and qn = "mbedtls_ecdsa_verify" or
  target.getQualifiedName().matches("mbedtls_x509_crt_verify%") and qn = "mbedtls_x509_crt_verify" or
  target.getQualifiedName().matches("gcry_pk_verify%") and qn = "gcry_pk_verify" or
  target.getQualifiedName().matches("PK11_Verify%") and qn = "PK11_Verify" or
  target.getQualifiedName().matches("VFY_VerifyDigest%") and qn = "VFY_VerifyDigest" or
  target.getQualifiedName().matches("VFY_VerifyDigestDirect%") and qn = "VFY_VerifyDigestDirect" or
  target.getQualifiedName().matches("CERT_VerifyCertificate%") and qn = "CERT_VerifyCertificate" or
  target.getQualifiedName().matches("CERT_VerifyCertificateNow%") and qn = "CERT_VerifyCertificateNow" or
  target.getQualifiedName().matches("CERT_VerifySignedData%") and qn = "CERT_VerifySignedData" or
  target.getQualifiedName().matches("CryptVerifySignature%") and qn = "CryptVerifySignature" or
  target.getQualifiedName().matches("CryptVerifyCertificateSignature%") and qn = "CryptVerifyCertificateSignature" or
  target.getQualifiedName().matches("CryptVerifyCertificateSignatureEx%") and qn = "CryptVerifyCertificateSignatureEx" or
  target.getQualifiedName().matches("BCryptVerifySignature%") and qn = "BCryptVerifySignature" or
  target.getQualifiedName().matches("NCryptVerifySignature%") and qn = "NCryptVerifySignature" or
  target.getQualifiedName().matches("CryptoPP%::RSASSA_PKCS1v15_SHA_Verifier%::VerifyMessage%") and qn = "CryptoPP::RSASSA_PKCS1v15_SHA_Verifier::VerifyMessage" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("CryptoPP", "RSASSA_PKCS1v15_SHA_Verifier") and
    memberFunc.getName() = "VerifyMessage" and
    qn = "CryptoPP::RSASSA_PKCS1v15_SHA_Verifier::VerifyMessage"
  ) or
  target.getQualifiedName().matches("CryptoPP%::RSASSA_PSS_SHA256_Verifier%::VerifyMessage%") and qn = "CryptoPP::RSASSA_PSS_SHA256_Verifier::VerifyMessage" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("CryptoPP", "RSASSA_PSS_SHA256_Verifier") and
    memberFunc.getName() = "VerifyMessage" and
    qn = "CryptoPP::RSASSA_PSS_SHA256_Verifier::VerifyMessage"
  ) or
  target.getQualifiedName().matches("CryptoPP%::ECDSA<ECP,SHA256>%::Verifier%::VerifyMessage%") and qn = "CryptoPP::ECDSA<ECP,SHA256>::Verifier::VerifyMessage" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("CryptoPP::ECDSA<ECP,SHA256>", "Verifier") and
    memberFunc.getName() = "VerifyMessage" and
    qn = "CryptoPP::ECDSA<ECP,SHA256>::Verifier::VerifyMessage"
  ) or
  target.getQualifiedName().matches("CryptoPP%::DSA%::Verifier%::VerifyMessage%") and qn = "CryptoPP::DSA::Verifier::VerifyMessage" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("CryptoPP::DSA", "Verifier") and
    memberFunc.getName() = "VerifyMessage" and
    qn = "CryptoPP::DSA::Verifier::VerifyMessage"
  ) or
  target.getQualifiedName().matches("CryptoPP%::SignatureVerificationFilter%") and qn = "CryptoPP::SignatureVerificationFilter" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "CryptoPP") and
    memberFunc.getName() = "SignatureVerificationFilter" and
    qn = "CryptoPP::SignatureVerificationFilter"
  ) or
  target.getQualifiedName().matches("Botan%::PK_Verifier%::verify_message%") and qn = "Botan::PK_Verifier::verify_message" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Botan", "PK_Verifier") and
    memberFunc.getName() = "verify_message" and
    qn = "Botan::PK_Verifier::verify_message"
  ) or
  target.getQualifiedName().matches("Botan%::X509_Certificate%::check_signature%") and qn = "Botan::X509_Certificate::check_signature" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Botan", "X509_Certificate") and
    memberFunc.getName() = "check_signature" and
    qn = "Botan::X509_Certificate::check_signature"
  ) or
  target.getQualifiedName().matches("nettle_rsa_pkcs1_verify%") and qn = "nettle_rsa_pkcs1_verify" or
  target.getQualifiedName().matches("nettle_rsa_pss_verify_digest%") and qn = "nettle_rsa_pss_verify_digest" or
  target.getQualifiedName().matches("nettle_ecdsa_verify%") and qn = "nettle_ecdsa_verify" or
  target.getQualifiedName().matches("crypto_sign_verify_detached%") and qn = "crypto_sign_verify_detached" or
  target.getQualifiedName().matches("crypto_sign_ed25519_open%") and qn = "crypto_sign_ed25519_open" or
  target.getQualifiedName().matches("crypto_sign_ed25519_verify_detached%") and qn = "crypto_sign_ed25519_verify_detached" or
  target.getQualifiedName().matches("wolfSSL_MakeCertVerify%") and qn = "wolfSSL_MakeCertVerify" or
  target.getQualifiedName().matches("wc_RsaSSL_Verify%") and qn = "wc_RsaSSL_Verify" or
  target.getQualifiedName().matches("wc_SignatureVerifyHash%") and qn = "wc_SignatureVerifyHash" or
  target.getQualifiedName().matches("wc_EccVerifyHash%") and qn = "wc_EccVerifyHash" or
  target.getQualifiedName().matches("NSS%::PK11_Verify%") and qn = "NSS::PK11_Verify" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "NSS") and
    memberFunc.getName() = "PK11_Verify" and
    qn = "NSS::PK11_Verify"
  ) or
  target.getQualifiedName().matches("NSS%::VFY_VerifyDigest%") and qn = "NSS::VFY_VerifyDigest" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "NSS") and
    memberFunc.getName() = "VFY_VerifyDigest" and
    qn = "NSS::VFY_VerifyDigest"
  )
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
