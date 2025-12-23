// Auto-generated; CWE-760; number of APIs 125
import java

predicate isTargetApi(Callable target, string qn) {
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
    m.getDeclaringType().hasQualifiedName("java.security", "MessageDigest") and
    m.getName() = "isEqual" and
    qn = "java.security.MessageDigest.isEqual"
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
    m.getName() = "update" and
    qn = "javax.crypto.Mac.update"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.crypto", "Mac") and
    m.getName() = "doFinal" and
    qn = "javax.crypto.Mac.doFinal"
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
    m.getName() = "verify" and
    qn = "java.security.Signature.verify"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.util", "Arrays") and
    m.getName() = "equals" and
    qn = "java.util.Arrays.equals"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.util", "Objects") and
    m.getName() = "equals" and
    qn = "java.util.Objects.equals"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.util", "Objects") and
    m.getName() = "deepEquals" and
    qn = "java.util.Objects.deepEquals"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.lang", "String") and
    m.getName() = "equals" and
    qn = "java.lang.String.equals"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.lang", "String") and
    m.getName() = "equalsIgnoreCase" and
    qn = "java.lang.String.equalsIgnoreCase"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.lang", "String") and
    m.getName() = "contentEquals" and
    qn = "java.lang.String.contentEquals"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.lang", "String") and
    m.getName() = "compareTo" and
    qn = "java.lang.String.compareTo"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.lang", "String") and
    m.getName() = "compareToIgnoreCase" and
    qn = "java.lang.String.compareToIgnoreCase"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.lang", "String") and
    m.getName() = "regionMatches" and
    qn = "java.lang.String.regionMatches"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.lang", "String") and
    m.getName() = "startsWith" and
    qn = "java.lang.String.startsWith"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.lang", "String") and
    m.getName() = "endsWith" and
    qn = "java.lang.String.endsWith"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.lang", "String") and
    m.getName() = "contains" and
    qn = "java.lang.String.contains"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.lang", "CharSequence") and
    m.getName() = "toString" and
    qn = "java.lang.CharSequence.toString"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.nio.charset", "CharsetEncoder") and
    m.getName() = "encode" and
    qn = "java.nio.charset.CharsetEncoder.encode"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.nio.charset", "CharsetDecoder") and
    m.getName() = "decode" and
    qn = "java.nio.charset.CharsetDecoder.decode"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.math", "BigInteger") and
    m.getName() = "equals" and
    qn = "java.math.BigInteger.equals"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.math", "BigInteger") and
    m.getName() = "compareTo" and
    qn = "java.math.BigInteger.compareTo"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.math", "BigInteger") and
    m.getName() = "modPow" and
    qn = "java.math.BigInteger.modPow"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.math", "BigInteger") and
    m.getName() = "gcd" and
    qn = "java.math.BigInteger.gcd"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security", "Key") and
    m.getName() = "equals" and
    qn = "java.security.Key.equals"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security", "PublicKey") and
    m.getName() = "equals" and
    qn = "java.security.PublicKey.equals"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security", "PrivateKey") and
    m.getName() = "equals" and
    qn = "java.security.PrivateKey.equals"
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
    m.getName() = "update" and
    qn = "javax.crypto.Cipher.update"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.crypto", "Cipher") and
    m.getName() = "doFinal" and
    qn = "javax.crypto.Cipher.doFinal"
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
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.net.ssl", "HostnameVerifier") and
    m.getName() = "verify" and
    qn = "javax.net.ssl.HostnameVerifier.verify"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.net.ssl", "X509TrustManager") and
    m.getName() = "checkServerTrusted" and
    qn = "javax.net.ssl.X509TrustManager.checkServerTrusted"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.net.ssl", "X509TrustManager") and
    m.getName() = "checkClientTrusted" and
    qn = "javax.net.ssl.X509TrustManager.checkClientTrusted"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security.cert", "X509Certificate") and
    m.getName() = "verify" and
    qn = "java.security.cert.X509Certificate.verify"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security.cert", "X509Certificate") and
    m.getName() = "checkValidity" and
    qn = "java.security.cert.X509Certificate.checkValidity"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.util", "Base64") and
    m.getName() = "getEncoder" and
    qn = "java.util.Base64.getEncoder"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.util", "Base64") and
    m.getName() = "getDecoder" and
    qn = "java.util.Base64.getDecoder"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.util", "Base64$Encoder") and
    m.getName() = "encode" and
    qn = "java.util.Base64$Encoder.encode"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.util", "Base64$Encoder") and
    m.getName() = "encodeToString" and
    qn = "java.util.Base64$Encoder.encodeToString"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.util", "Base64$Decoder") and
    m.getName() = "decode" and
    qn = "java.util.Base64$Decoder.decode"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.xml.bind", "DatatypeConverter") and
    m.getName() = "parseBase64Binary" and
    qn = "javax.xml.bind.DatatypeConverter.parseBase64Binary"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.xml.bind", "DatatypeConverter") and
    m.getName() = "printBase64Binary" and
    qn = "javax.xml.bind.DatatypeConverter.printBase64Binary"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.xml.bind", "DatatypeConverter") and
    m.getName() = "parseHexBinary" and
    qn = "javax.xml.bind.DatatypeConverter.parseHexBinary"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.xml.bind", "DatatypeConverter") and
    m.getName() = "printHexBinary" and
    qn = "javax.xml.bind.DatatypeConverter.printHexBinary"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.codec.binary", "Base64") and
    m.getName() = "encodeBase64" and
    qn = "org.apache.commons.codec.binary.Base64.encodeBase64"
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
    m.getDeclaringType().hasQualifiedName("com.google.common.io", "BaseEncoding") and
    m.getName() = "base16" and
    qn = "com.google.common.io.BaseEncoding.base16"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.google.common.io", "BaseEncoding") and
    m.getName() = "base32" and
    qn = "com.google.common.io.BaseEncoding.base32"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.google.common.io", "BaseEncoding") and
    m.getName() = "base64" and
    qn = "com.google.common.io.BaseEncoding.base64"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.google.common.io", "BaseEncoding") and
    m.getName() = "decode" and
    qn = "com.google.common.io.BaseEncoding.decode"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.google.common.io", "BaseEncoding") and
    m.getName() = "encode" and
    qn = "com.google.common.io.BaseEncoding.encode"
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
    m.getDeclaringType().hasQualifiedName("org.bouncycastle.util.encoders", "Base64") and
    m.getName() = "encode" and
    qn = "org.bouncycastle.util.encoders.Base64.encode"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.bouncycastle.util.encoders", "Base64") and
    m.getName() = "decode" and
    qn = "org.bouncycastle.util.encoders.Base64.decode"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.bouncycastle.util.encoders", "Hex") and
    m.getName() = "encode" and
    qn = "org.bouncycastle.util.encoders.Hex.encode"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.bouncycastle.util.encoders", "Hex") and
    m.getName() = "decode" and
    qn = "org.bouncycastle.util.encoders.Hex.decode"
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
    c.getDeclaringType().hasQualifiedName("org.bouncycastle.crypto.digests", "SHA256Digest") and
    qn = "org.bouncycastle.crypto.digests.SHA256Digest.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.bouncycastle.crypto.macs", "HMac") and
    qn = "org.bouncycastle.crypto.macs.HMac.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.bouncycastle.crypto.macs", "HMac") and
    m.getName() = "doFinal" and
    qn = "org.bouncycastle.crypto.macs.HMac.doFinal"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("okio", "ByteString") and
    m.getName() = "base64" and
    qn = "okio.ByteString.base64"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("okio", "ByteString") and
    m.getName() = "decodeBase64" and
    qn = "okio.ByteString.decodeBase64"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("okio", "ByteString") and
    m.getName() = "hex" and
    qn = "okio.ByteString.hex"
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
    m.getName() = "matches" and
    qn = "org.springframework.security.crypto.password.PasswordEncoder.matches"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.security.crypto.bcrypt", "BCryptPasswordEncoder") and
    m.getName() = "matches" and
    qn = "org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder.matches"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.security.crypto.scrypt", "SCryptPasswordEncoder") and
    m.getName() = "matches" and
    qn = "org.springframework.security.crypto.scrypt.SCryptPasswordEncoder.matches"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.security.crypto.argon2", "Argon2PasswordEncoder") and
    m.getName() = "matches" and
    qn = "org.springframework.security.crypto.argon2.Argon2PasswordEncoder.matches"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.security.crypto.codec", "Base64") and
    m.getName() = "encode" and
    qn = "org.springframework.security.crypto.codec.Base64.encode"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.security.crypto.codec", "Base64") and
    m.getName() = "decode" and
    qn = "org.springframework.security.crypto.codec.Base64.decode"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.security.crypto.codec", "Hex") and
    m.getName() = "encode" and
    qn = "org.springframework.security.crypto.codec.Hex.encode"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.security.crypto.codec", "Hex") and
    m.getName() = "decode" and
    qn = "org.springframework.security.crypto.codec.Hex.decode"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.owasp.encoder", "Encode") and
    m.getName() = "forJava" and
    qn = "org.owasp.encoder.Encode.forJava"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.owasp.encoder", "Encode") and
    m.getName() = "forJson" and
    qn = "org.owasp.encoder.Encode.forJson"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.nimbusds.jwt", "SignedJWT") and
    m.getName() = "parse" and
    qn = "com.nimbusds.jwt.SignedJWT.parse"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.nimbusds.jwt", "SignedJWT") and
    m.getName() = "verify" and
    qn = "com.nimbusds.jwt.SignedJWT.verify"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.nimbusds.jose", "JWSObject") and
    m.getName() = "parse" and
    qn = "com.nimbusds.jose.JWSObject.parse"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.nimbusds.jose", "JWSObject") and
    m.getName() = "verify" and
    qn = "com.nimbusds.jose.JWSObject.verify"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("com.nimbusds.jose.crypto", "MACVerifier") and
    qn = "com.nimbusds.jose.crypto.MACVerifier.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("com.nimbusds.jose.crypto", "RSASSAVerifier") and
    qn = "com.nimbusds.jose.crypto.RSASSAVerifier.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("com.nimbusds.jose.crypto", "ECDSAVerifier") and
    qn = "com.nimbusds.jose.crypto.ECDSAVerifier.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("io.jsonwebtoken", "Jwts") and
    m.getName() = "parser" and
    qn = "io.jsonwebtoken.Jwts.parser"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("io.jsonwebtoken", "Jwts") and
    m.getName() = "parserBuilder" and
    qn = "io.jsonwebtoken.Jwts.parserBuilder"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("io.jsonwebtoken", "JwtParser") and
    m.getName() = "parseClaimsJws" and
    qn = "io.jsonwebtoken.JwtParser.parseClaimsJws"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("io.jsonwebtoken", "JwtParser") and
    m.getName() = "parse" and
    qn = "io.jsonwebtoken.JwtParser.parse"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("io.jsonwebtoken", "JwtParserBuilder") and
    m.getName() = "setSigningKey" and
    qn = "io.jsonwebtoken.JwtParserBuilder.setSigningKey"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("io.jsonwebtoken", "JwtParserBuilder") and
    m.getName() = "build" and
    qn = "io.jsonwebtoken.JwtParserBuilder.build"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.auth0.jwt", "JWT") and
    m.getName() = "decode" and
    qn = "com.auth0.jwt.JWT.decode"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.auth0.jwt", "JWT") and
    m.getName() = "require" and
    qn = "com.auth0.jwt.JWT.require"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.auth0.jwt", "JWTVerifier") and
    m.getName() = "verify" and
    qn = "com.auth0.jwt.JWTVerifier.verify"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.lang", "System") and
    m.getName() = "nanoTime" and
    qn = "java.lang.System.nanoTime"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.lang", "System") and
    m.getName() = "currentTimeMillis" and
    qn = "java.lang.System.currentTimeMillis"
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
