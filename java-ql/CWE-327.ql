// Auto-generated; CWE-327; number of APIs 107
import java

predicate isTargetApi(Callable target, string qn) {
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.crypto", "Cipher") and
    m.getName() = "getInstance" and
    qn = "javax.crypto.Cipher.getInstance"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.crypto", "Cipher") and
    m.getName() = "init" and
    qn = "javax.crypto.Cipher.init"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.crypto", "Cipher") and
    m.getName() = "doFinal" and
    qn = "javax.crypto.Cipher.doFinal"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.crypto", "Cipher") and
    m.getName() = "update" and
    qn = "javax.crypto.Cipher.update"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.crypto", "Cipher") and
    m.getName() = "wrap" and
    qn = "javax.crypto.Cipher.wrap"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.crypto", "Cipher") and
    m.getName() = "unwrap" and
    qn = "javax.crypto.Cipher.unwrap"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.crypto", "Mac") and
    m.getName() = "getInstance" and
    qn = "javax.crypto.Mac.getInstance"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.crypto", "Mac") and
    m.getName() = "init" and
    qn = "javax.crypto.Mac.init"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.crypto", "Mac") and
    m.getName() = "doFinal" and
    qn = "javax.crypto.Mac.doFinal"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.crypto", "Mac") and
    m.getName() = "update" and
    qn = "javax.crypto.Mac.update"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security", "MessageDigest") and
    m.getName() = "getInstance" and
    qn = "java.security.MessageDigest.getInstance"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security", "MessageDigest") and
    m.getName() = "update" and
    qn = "java.security.MessageDigest.update"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security", "MessageDigest") and
    m.getName() = "digest" and
    qn = "java.security.MessageDigest.digest"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security", "Signature") and
    m.getName() = "getInstance" and
    qn = "java.security.Signature.getInstance"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security", "Signature") and
    m.getName() = "initSign" and
    qn = "java.security.Signature.initSign"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security", "Signature") and
    m.getName() = "initVerify" and
    qn = "java.security.Signature.initVerify"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security", "Signature") and
    m.getName() = "update" and
    qn = "java.security.Signature.update"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security", "Signature") and
    m.getName() = "sign" and
    qn = "java.security.Signature.sign"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security", "Signature") and
    m.getName() = "verify" and
    qn = "java.security.Signature.verify"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security", "KeyPairGenerator") and
    m.getName() = "getInstance" and
    qn = "java.security.KeyPairGenerator.getInstance"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security", "KeyPairGenerator") and
    m.getName() = "initialize" and
    qn = "java.security.KeyPairGenerator.initialize"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security", "KeyPairGenerator") and
    m.getName() = "genKeyPair" and
    qn = "java.security.KeyPairGenerator.genKeyPair"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security", "KeyPairGenerator") and
    m.getName() = "generateKeyPair" and
    qn = "java.security.KeyPairGenerator.generateKeyPair"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security", "KeyGenerator") and
    m.getName() = "getInstance" and
    qn = "java.security.KeyGenerator.getInstance"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security", "KeyGenerator") and
    m.getName() = "init" and
    qn = "java.security.KeyGenerator.init"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security", "KeyGenerator") and
    m.getName() = "generateKey" and
    qn = "java.security.KeyGenerator.generateKey"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security", "KeyFactory") and
    m.getName() = "getInstance" and
    qn = "java.security.KeyFactory.getInstance"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security", "KeyFactory") and
    m.getName() = "generatePrivate" and
    qn = "java.security.KeyFactory.generatePrivate"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security", "KeyFactory") and
    m.getName() = "generatePublic" and
    qn = "java.security.KeyFactory.generatePublic"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security", "KeyAgreement") and
    m.getName() = "getInstance" and
    qn = "java.security.KeyAgreement.getInstance"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security", "KeyAgreement") and
    m.getName() = "init" and
    qn = "java.security.KeyAgreement.init"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security", "KeyAgreement") and
    m.getName() = "doPhase" and
    qn = "java.security.KeyAgreement.doPhase"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security", "KeyAgreement") and
    m.getName() = "generateSecret" and
    qn = "java.security.KeyAgreement.generateSecret"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security", "KeyStore") and
    m.getName() = "getInstance" and
    qn = "java.security.KeyStore.getInstance"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security", "KeyStore") and
    m.getName() = "load" and
    qn = "java.security.KeyStore.load"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security", "KeyStore") and
    m.getName() = "store" and
    qn = "java.security.KeyStore.store"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security", "KeyStore") and
    m.getName() = "getKey" and
    qn = "java.security.KeyStore.getKey"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security", "KeyStore") and
    m.getName() = "setKeyEntry" and
    qn = "java.security.KeyStore.setKeyEntry"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security", "KeyStore") and
    m.getName() = "getCertificate" and
    qn = "java.security.KeyStore.getCertificate"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.crypto", "SecretKeyFactory") and
    m.getName() = "getInstance" and
    qn = "javax.crypto.SecretKeyFactory.getInstance"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.crypto", "SecretKeyFactory") and
    m.getName() = "generateSecret" and
    qn = "javax.crypto.SecretKeyFactory.generateSecret"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("javax.crypto.spec", "SecretKeySpec") and
    qn = "javax.crypto.spec.SecretKeySpec.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("javax.crypto.spec", "IvParameterSpec") and
    qn = "javax.crypto.spec.IvParameterSpec.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("javax.crypto.spec", "GCMParameterSpec") and
    qn = "javax.crypto.spec.GCMParameterSpec.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("javax.crypto.spec", "PBEKeySpec") and
    qn = "javax.crypto.spec.PBEKeySpec.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("javax.crypto.spec", "PBEParameterSpec") and
    qn = "javax.crypto.spec.PBEParameterSpec.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security.cert", "CertificateFactory") and
    m.getName() = "getInstance" and
    qn = "java.security.cert.CertificateFactory.getInstance"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security.cert", "CertificateFactory") and
    m.getName() = "generateCertificate" and
    qn = "java.security.cert.CertificateFactory.generateCertificate"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security.cert", "CertificateFactory") and
    m.getName() = "generateCertificates" and
    qn = "java.security.cert.CertificateFactory.generateCertificates"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security.cert", "CertificateFactory") and
    m.getName() = "generateCRL" and
    qn = "java.security.cert.CertificateFactory.generateCRL"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security", "AlgorithmParameters") and
    m.getName() = "getInstance" and
    qn = "java.security.AlgorithmParameters.getInstance"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security", "AlgorithmParameters") and
    m.getName() = "init" and
    qn = "java.security.AlgorithmParameters.init"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security", "AlgorithmParameters") and
    m.getName() = "getParameterSpec" and
    qn = "java.security.AlgorithmParameters.getParameterSpec"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security", "Security") and
    m.getName() = "getProviders" and
    qn = "java.security.Security.getProviders"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security", "Security") and
    m.getName() = "getProvider" and
    qn = "java.security.Security.getProvider"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security", "Security") and
    m.getName() = "getAlgorithms" and
    qn = "java.security.Security.getAlgorithms"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security", "Security") and
    m.getName() = "addProvider" and
    qn = "java.security.Security.addProvider"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security", "Security") and
    m.getName() = "insertProviderAt" and
    qn = "java.security.Security.insertProviderAt"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.bouncycastle.jce.provider", "BouncyCastleProvider") and
    qn = "org.bouncycastle.jce.provider.BouncyCastleProvider.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.bouncycastle.crypto.engines", "AESEngine") and
    qn = "org.bouncycastle.crypto.engines.AESEngine.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.bouncycastle.crypto.engines", "DESedeEngine") and
    qn = "org.bouncycastle.crypto.engines.DESedeEngine.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.bouncycastle.crypto.engines", "DESEngine") and
    qn = "org.bouncycastle.crypto.engines.DESEngine.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.bouncycastle.crypto.engines", "RC2Engine") and
    qn = "org.bouncycastle.crypto.engines.RC2Engine.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.bouncycastle.crypto.engines", "RC4Engine") and
    qn = "org.bouncycastle.crypto.engines.RC4Engine.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.bouncycastle.crypto.engines", "BlowfishEngine") and
    qn = "org.bouncycastle.crypto.engines.BlowfishEngine.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.bouncycastle.crypto.engines", "TwofishEngine") and
    qn = "org.bouncycastle.crypto.engines.TwofishEngine.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.bouncycastle.crypto.engines", "SerpentEngine") and
    qn = "org.bouncycastle.crypto.engines.SerpentEngine.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.bouncycastle.crypto.macs", "HMac") and
    qn = "org.bouncycastle.crypto.macs.HMac.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.bouncycastle.crypto.digests", "MD2Digest") and
    qn = "org.bouncycastle.crypto.digests.MD2Digest.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.bouncycastle.crypto.digests", "MD4Digest") and
    qn = "org.bouncycastle.crypto.digests.MD4Digest.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.bouncycastle.crypto.digests", "MD5Digest") and
    qn = "org.bouncycastle.crypto.digests.MD5Digest.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.bouncycastle.crypto.digests", "SHA1Digest") and
    qn = "org.bouncycastle.crypto.digests.SHA1Digest.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.bouncycastle.crypto.digests", "SHA224Digest") and
    qn = "org.bouncycastle.crypto.digests.SHA224Digest.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.bouncycastle.crypto.digests", "SHA256Digest") and
    qn = "org.bouncycastle.crypto.digests.SHA256Digest.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.bouncycastle.crypto.digests", "SHA384Digest") and
    qn = "org.bouncycastle.crypto.digests.SHA384Digest.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.bouncycastle.crypto.digests", "SHA512Digest") and
    qn = "org.bouncycastle.crypto.digests.SHA512Digest.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.bouncycastle.crypto.signers", "RSADigestSigner") and
    qn = "org.bouncycastle.crypto.signers.RSADigestSigner.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.bouncycastle.crypto.signers", "DSADigestSigner") and
    qn = "org.bouncycastle.crypto.signers.DSADigestSigner.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.bouncycastle.crypto.signers", "ECDSASigner") and
    qn = "org.bouncycastle.crypto.signers.ECDSASigner.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.codec.digest", "DigestUtils") and
    m.getName() = "md2" and
    qn = "org.apache.commons.codec.digest.DigestUtils.md2"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.codec.digest", "DigestUtils") and
    m.getName() = "md5" and
    qn = "org.apache.commons.codec.digest.DigestUtils.md5"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.codec.digest", "DigestUtils") and
    m.getName() = "sha1" and
    qn = "org.apache.commons.codec.digest.DigestUtils.sha1"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.codec.digest", "DigestUtils") and
    m.getName() = "sha256" and
    qn = "org.apache.commons.codec.digest.DigestUtils.sha256"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.codec.digest", "DigestUtils") and
    m.getName() = "sha384" and
    qn = "org.apache.commons.codec.digest.DigestUtils.sha384"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.codec.digest", "DigestUtils") and
    m.getName() = "sha512" and
    qn = "org.apache.commons.codec.digest.DigestUtils.sha512"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.codec.digest", "HmacUtils") and
    m.getName() = "hmacMd5" and
    qn = "org.apache.commons.codec.digest.HmacUtils.hmacMd5"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.codec.digest", "HmacUtils") and
    m.getName() = "hmacSha1" and
    qn = "org.apache.commons.codec.digest.HmacUtils.hmacSha1"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.codec.digest", "HmacUtils") and
    m.getName() = "hmacSha256" and
    qn = "org.apache.commons.codec.digest.HmacUtils.hmacSha256"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.codec.digest", "HmacUtils") and
    m.getName() = "hmacSha512" and
    qn = "org.apache.commons.codec.digest.HmacUtils.hmacSha512"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.google.common.hash", "Hashing") and
    m.getName() = "md5" and
    qn = "com.google.common.hash.Hashing.md5"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.google.common.hash", "Hashing") and
    m.getName() = "sha1" and
    qn = "com.google.common.hash.Hashing.sha1"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.google.common.hash", "Hashing") and
    m.getName() = "sha256" and
    qn = "com.google.common.hash.Hashing.sha256"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.google.common.hash", "Hashing") and
    m.getName() = "sha512" and
    qn = "com.google.common.hash.Hashing.sha512"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.google.common.hash", "Hashing") and
    m.getName() = "hmacMd5" and
    qn = "com.google.common.hash.Hashing.hmacMd5"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.google.common.hash", "Hashing") and
    m.getName() = "hmacSha1" and
    qn = "com.google.common.hash.Hashing.hmacSha1"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.google.common.hash", "Hashing") and
    m.getName() = "hmacSha256" and
    qn = "com.google.common.hash.Hashing.hmacSha256"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.google.common.hash", "Hashing") and
    m.getName() = "hmacSha512" and
    qn = "com.google.common.hash.Hashing.hmacSha512"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("okio", "ByteString") and
    m.getName() = "md5" and
    qn = "okio.ByteString.md5"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("okio", "ByteString") and
    m.getName() = "sha1" and
    qn = "okio.ByteString.sha1"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("okio", "ByteString") and
    m.getName() = "sha256" and
    qn = "okio.ByteString.sha256"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("okio", "ByteString") and
    m.getName() = "sha512" and
    qn = "okio.ByteString.sha512"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.security.crypto.encrypt", "Encryptors") and
    m.getName() = "text" and
    qn = "org.springframework.security.crypto.encrypt.Encryptors.text"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.security.crypto.encrypt", "Encryptors") and
    m.getName() = "queryableText" and
    qn = "org.springframework.security.crypto.encrypt.Encryptors.queryableText"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.security.crypto.encrypt", "TextEncryptor") and
    m.getName() = "encrypt" and
    qn = "org.springframework.security.crypto.encrypt.TextEncryptor.encrypt"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.security.crypto.encrypt", "TextEncryptor") and
    m.getName() = "decrypt" and
    qn = "org.springframework.security.crypto.encrypt.TextEncryptor.decrypt"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.security.crypto.codec", "Hex") and
    m.getName() = "decode" and
    qn = "org.springframework.security.crypto.codec.Hex.decode"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.security.crypto.codec", "Hex") and
    m.getName() = "encode" and
    qn = "org.springframework.security.crypto.codec.Hex.encode"
  )
}

from Call call, Callable targetFunc, Callable enclosingFunc, string qn, ControlFlowNode node
where
  targetFunc = call.getCallee() and
  isTargetApi(targetFunc, qn) and
  enclosingFunc = call.getEnclosingCallable() and
  enclosingFunc.fromSource() and
  node.asExpr() = call
select
  "Path: " + call.getLocation().getFile().getAbsolutePath(),
  "call function: " +
    call.getLocation().getStartLine().toString() + ":" + call.getLocation().getStartColumn().toString() +
    "-" + call.getLocation().getEndLine().toString() + ":" + call.getLocation().getEndColumn().toString(),
  "call in function: " + enclosingFunc.getName() + "@" +
    enclosingFunc.getLocation().getStartLine().toString() + "-" +
    enclosingFunc.getBody().getLocation().getEndLine().toString(),
  "callee=" + qn,
  "basic block: " +
    node.getLocation().getStartLine().toString() + ":" + node.getLocation().getStartColumn().toString() + "-" +
    node.getLocation().getEndLine().toString() + ":" + node.getLocation().getEndColumn().toString()
