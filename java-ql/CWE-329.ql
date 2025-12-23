// Auto-generated; CWE-329; number of APIs 100
import java

predicate isTargetApi(Callable target, string qn) {
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("java.security", "SecureRandom") and
    qn = "java.security.SecureRandom.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security", "SecureRandom") and
    m.getName() = "getInstance" and
    qn = "java.security.SecureRandom.getInstance"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security", "SecureRandom") and
    m.getName() = "getInstanceStrong" and
    qn = "java.security.SecureRandom.getInstanceStrong"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security", "SecureRandom") and
    m.getName() = "setSeed" and
    qn = "java.security.SecureRandom.setSeed"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security", "SecureRandom") and
    m.getName() = "generateSeed" and
    qn = "java.security.SecureRandom.generateSeed"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security", "SecureRandom") and
    m.getName() = "nextBytes" and
    qn = "java.security.SecureRandom.nextBytes"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security", "SecureRandom") and
    m.getName() = "nextInt" and
    qn = "java.security.SecureRandom.nextInt"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security", "SecureRandom") and
    m.getName() = "nextLong" and
    qn = "java.security.SecureRandom.nextLong"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("java.util", "Random") and
    qn = "java.util.Random.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.util", "Random") and
    m.getName() = "setSeed" and
    qn = "java.util.Random.setSeed"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.util", "Random") and
    m.getName() = "nextBytes" and
    qn = "java.util.Random.nextBytes"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.util", "Random") and
    m.getName() = "nextInt" and
    qn = "java.util.Random.nextInt"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.util", "Random") and
    m.getName() = "nextLong" and
    qn = "java.util.Random.nextLong"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.util.concurrent", "ThreadLocalRandom") and
    m.getName() = "current" and
    qn = "java.util.concurrent.ThreadLocalRandom.current"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.util.concurrent", "ThreadLocalRandom") and
    m.getName() = "nextInt" and
    qn = "java.util.concurrent.ThreadLocalRandom.nextInt"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.util.concurrent", "ThreadLocalRandom") and
    m.getName() = "nextLong" and
    qn = "java.util.concurrent.ThreadLocalRandom.nextLong"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.util.concurrent", "ThreadLocalRandom") and
    m.getName() = "nextBytes" and
    qn = "java.util.concurrent.ThreadLocalRandom.nextBytes"
  ) or
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
    m.getDeclaringType().hasQualifiedName("javax.crypto", "KeyGenerator") and
    m.getName() = "getInstance" and
    qn = "javax.crypto.KeyGenerator.getInstance"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.crypto", "KeyGenerator") and
    m.getName() = "init" and
    qn = "javax.crypto.KeyGenerator.init"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.crypto", "KeyGenerator") and
    m.getName() = "generateKey" and
    qn = "javax.crypto.KeyGenerator.generateKey"
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
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.bouncycastle.crypto.engines", "AESEngine") and
    qn = "org.bouncycastle.crypto.engines.AESEngine.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.bouncycastle.crypto.engines", "DESEngine") and
    qn = "org.bouncycastle.crypto.engines.DESEngine.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.bouncycastle.crypto.engines", "DESedeEngine") and
    qn = "org.bouncycastle.crypto.engines.DESedeEngine.<init>"
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
    c.getDeclaringType().hasQualifiedName("org.bouncycastle.crypto.modes", "CBCBlockCipher") and
    qn = "org.bouncycastle.crypto.modes.CBCBlockCipher.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.bouncycastle.crypto.modes", "GCMBlockCipher") and
    qn = "org.bouncycastle.crypto.modes.GCMBlockCipher.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.bouncycastle.crypto.paddings", "PaddedBufferedBlockCipher") and
    qn = "org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.bouncycastle.crypto.params", "ParametersWithIV") and
    qn = "org.bouncycastle.crypto.params.ParametersWithIV.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.bouncycastle.crypto.params", "KeyParameter") and
    qn = "org.bouncycastle.crypto.params.KeyParameter.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.bouncycastle.crypto.macs", "HMac") and
    qn = "org.bouncycastle.crypto.macs.HMac.<init>"
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
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.bouncycastle.crypto.prng", "RandomGenerator") and
    m.getName() = "nextBytes" and
    qn = "org.bouncycastle.crypto.prng.RandomGenerator.nextBytes"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.bouncycastle.crypto.prng", "DigestRandomGenerator") and
    qn = "org.bouncycastle.crypto.prng.DigestRandomGenerator.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.bouncycastle.crypto.prng.drbg", "SP800SecureRandomBuilder") and
    qn = "org.bouncycastle.crypto.prng.drbg.SP800SecureRandomBuilder.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.bouncycastle.crypto.prng.drbg", "SP800SecureRandomBuilder") and
    m.getName() = "build" and
    qn = "org.bouncycastle.crypto.prng.drbg.SP800SecureRandomBuilder.build"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.codec.binary", "Hex") and
    m.getName() = "encodeHexString" and
    qn = "org.apache.commons.codec.binary.Hex.encodeHexString"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.codec.binary", "Hex") and
    m.getName() = "decodeHex" and
    qn = "org.apache.commons.codec.binary.Hex.decodeHex"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.codec.binary", "Base64") and
    m.getName() = "encodeBase64String" and
    qn = "org.apache.commons.codec.binary.Base64.encodeBase64String"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.codec.binary", "Base64") and
    m.getName() = "decodeBase64" and
    qn = "org.apache.commons.codec.binary.Base64.decodeBase64"
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
    m.getDeclaringType().hasQualifiedName("org.springframework.security.crypto.keygen", "KeyGenerators") and
    m.getName() = "secureRandom" and
    qn = "org.springframework.security.crypto.keygen.KeyGenerators.secureRandom"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.security.crypto.keygen", "KeyGenerators") and
    m.getName() = "shared" and
    qn = "org.springframework.security.crypto.keygen.KeyGenerators.shared"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.security.crypto.keygen", "StringKeyGenerator") and
    m.getName() = "generateKey" and
    qn = "org.springframework.security.crypto.keygen.StringKeyGenerator.generateKey"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.security.crypto.keygen", "BytesKeyGenerator") and
    m.getName() = "generateKey" and
    qn = "org.springframework.security.crypto.keygen.BytesKeyGenerator.generateKey"
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
