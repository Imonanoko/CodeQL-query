// Auto-generated; CWE-326; number of APIs 103
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
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("java.security.spec", "PBEKeySpec") and
    qn = "java.security.spec.PBEKeySpec.<init>"
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
    c.getDeclaringType().hasQualifiedName("javax.crypto.spec", "PBEParameterSpec") and
    qn = "javax.crypto.spec.PBEParameterSpec.<init>"
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
    c.getDeclaringType().hasQualifiedName("javax.crypto.spec", "SecretKeySpec") and
    qn = "javax.crypto.spec.SecretKeySpec.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security", "SecureRandomSpi") and
    m.getName() = "engineNextBytes" and
    qn = "java.security.SecureRandomSpi.engineNextBytes"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security", "SecureRandomSpi") and
    m.getName() = "engineGenerateSeed" and
    qn = "java.security.SecureRandomSpi.engineGenerateSeed"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security", "SecureRandomSpi") and
    m.getName() = "engineSetSeed" and
    qn = "java.security.SecureRandomSpi.engineSetSeed"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.bouncycastle.jce.provider", "BouncyCastleProvider") and
    qn = "org.bouncycastle.jce.provider.BouncyCastleProvider.<init>"
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
    m.getDeclaringType().hasQualifiedName("org.bouncycastle.crypto.prng.drbg", "DRBGProvider") and
    m.getName() = "get" and
    qn = "org.bouncycastle.crypto.prng.drbg.DRBGProvider.get"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.bouncycastle.crypto.prng.drbg", "HashSP800DRBG") and
    qn = "org.bouncycastle.crypto.prng.drbg.HashSP800DRBG.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.bouncycastle.crypto.prng.drbg", "HMacSP800DRBG") and
    qn = "org.bouncycastle.crypto.prng.drbg.HMacSP800DRBG.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.lang3", "RandomStringUtils") and
    m.getName() = "random" and
    qn = "org.apache.commons.lang3.RandomStringUtils.random"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.lang3", "RandomStringUtils") and
    m.getName() = "randomAlphabetic" and
    qn = "org.apache.commons.lang3.RandomStringUtils.randomAlphabetic"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.lang3", "RandomStringUtils") and
    m.getName() = "randomAlphanumeric" and
    qn = "org.apache.commons.lang3.RandomStringUtils.randomAlphanumeric"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.lang3", "RandomStringUtils") and
    m.getName() = "randomNumeric" and
    qn = "org.apache.commons.lang3.RandomStringUtils.randomNumeric"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.lang3", "RandomStringUtils") and
    m.getName() = "randomAscii" and
    qn = "org.apache.commons.lang3.RandomStringUtils.randomAscii"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.lang3", "RandomStringUtils") and
    m.getName() = "randomGraph" and
    qn = "org.apache.commons.lang3.RandomStringUtils.randomGraph"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.lang3", "RandomStringUtils") and
    m.getName() = "randomPrint" and
    qn = "org.apache.commons.lang3.RandomStringUtils.randomPrint"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.apache.commons.text", "RandomStringGenerator") and
    qn = "org.apache.commons.text.RandomStringGenerator.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.apache.commons.text.RandomStringGenerator", "Builder") and
    qn = "org.apache.commons.text.RandomStringGenerator.Builder.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.text.RandomStringGenerator", "Builder") and
    m.getName() = "build" and
    qn = "org.apache.commons.text.RandomStringGenerator.Builder.build"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.text", "RandomStringGenerator") and
    m.getName() = "generate" and
    qn = "org.apache.commons.text.RandomStringGenerator.generate"
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
    m.getDeclaringType().hasQualifiedName("org.springframework.security.crypto.password", "PasswordEncoder") and
    m.getName() = "encode" and
    qn = "org.springframework.security.crypto.password.PasswordEncoder.encode"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.security.crypto.password", "PasswordEncoder") and
    m.getName() = "matches" and
    qn = "org.springframework.security.crypto.password.PasswordEncoder.matches"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.security.crypto.password", "NoOpPasswordEncoder") and
    m.getName() = "getInstance" and
    qn = "org.springframework.security.crypto.password.NoOpPasswordEncoder.getInstance"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.springframework.security.crypto.bcrypt", "BCryptPasswordEncoder") and
    qn = "org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.springframework.security.crypto.scrypt", "SCryptPasswordEncoder") and
    qn = "org.springframework.security.crypto.scrypt.SCryptPasswordEncoder.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.springframework.security.crypto.argon2", "Argon2PasswordEncoder") and
    qn = "org.springframework.security.crypto.argon2.Argon2PasswordEncoder.<init>"
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
