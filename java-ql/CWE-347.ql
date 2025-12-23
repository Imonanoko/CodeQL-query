// Auto-generated; CWE-347; number of APIs 130
import java

predicate isTargetApi(Callable target, string qn) {
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
    m.getDeclaringType().hasQualifiedName("java.security", "Signature") and
    m.getName() = "setParameter" and
    qn = "java.security.Signature.setParameter"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security.cert", "Certificate") and
    m.getName() = "verify" and
    qn = "java.security.cert.Certificate.verify"
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
    m.getDeclaringType().hasQualifiedName("java.security.cert", "X509Certificate") and
    m.getName() = "getPublicKey" and
    qn = "java.security.cert.X509Certificate.getPublicKey"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security.cert", "X509Certificate") and
    m.getName() = "getSigAlgName" and
    qn = "java.security.cert.X509Certificate.getSigAlgName"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security.cert", "X509Certificate") and
    m.getName() = "getSigAlgOID" and
    qn = "java.security.cert.X509Certificate.getSigAlgOID"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security.cert", "X509Certificate") and
    m.getName() = "getSignature" and
    qn = "java.security.cert.X509Certificate.getSignature"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security.cert", "X509Certificate") and
    m.getName() = "getTBSCertificate" and
    qn = "java.security.cert.X509Certificate.getTBSCertificate"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security.cert", "X509CRL") and
    m.getName() = "verify" and
    qn = "java.security.cert.X509CRL.verify"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security.cert", "X509CRL") and
    m.getName() = "getSignature" and
    qn = "java.security.cert.X509CRL.getSignature"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security.cert", "X509CRL") and
    m.getName() = "getTBSCertList" and
    qn = "java.security.cert.X509CRL.getTBSCertList"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security.cert", "X509CRL") and
    m.getName() = "getSigAlgName" and
    qn = "java.security.cert.X509CRL.getSigAlgName"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security.cert", "X509CRL") and
    m.getName() = "getSigAlgOID" and
    qn = "java.security.cert.X509CRL.getSigAlgOID"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security.cert", "CertPathValidator") and
    m.getName() = "getInstance" and
    qn = "java.security.cert.CertPathValidator.getInstance"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security.cert", "CertPathValidator") and
    m.getName() = "validate" and
    qn = "java.security.cert.CertPathValidator.validate"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security.cert", "CertPathValidatorResult") and
    m.getName() = "toString" and
    qn = "java.security.cert.CertPathValidatorResult.toString"
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
    m.getName() = "generateCertPath" and
    qn = "java.security.cert.CertificateFactory.generateCertPath"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security.cert", "CertificateFactory") and
    m.getName() = "generateCRL" and
    qn = "java.security.cert.CertificateFactory.generateCRL"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security.cert", "CertificateFactory") and
    m.getName() = "generateCRLs" and
    qn = "java.security.cert.CertificateFactory.generateCRLs"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("java.security.cert", "PKIXParameters") and
    qn = "java.security.cert.PKIXParameters.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security.cert", "PKIXParameters") and
    m.getName() = "setTrustAnchors" and
    qn = "java.security.cert.PKIXParameters.setTrustAnchors"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security.cert", "PKIXParameters") and
    m.getName() = "addCertStore" and
    qn = "java.security.cert.PKIXParameters.addCertStore"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security.cert", "PKIXParameters") and
    m.getName() = "setRevocationEnabled" and
    qn = "java.security.cert.PKIXParameters.setRevocationEnabled"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("java.security.cert", "PKIXBuilderParameters") and
    qn = "java.security.cert.PKIXBuilderParameters.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security.cert", "PKIXBuilderParameters") and
    m.getName() = "setMaxPathLength" and
    qn = "java.security.cert.PKIXBuilderParameters.setMaxPathLength"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security.cert", "CertStore") and
    m.getName() = "getInstance" and
    qn = "java.security.cert.CertStore.getInstance"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("java.security.cert", "CertStoreParameters") and
    qn = "java.security.cert.CertStoreParameters.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.net.ssl", "TrustManagerFactory") and
    m.getName() = "getInstance" and
    qn = "javax.net.ssl.TrustManagerFactory.getInstance"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.net.ssl", "TrustManagerFactory") and
    m.getName() = "init" and
    qn = "javax.net.ssl.TrustManagerFactory.init"
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
    m.getDeclaringType().hasQualifiedName("javax.net.ssl", "SSLContext") and
    m.getName() = "getInstance" and
    qn = "javax.net.ssl.SSLContext.getInstance"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.net.ssl", "SSLContext") and
    m.getName() = "init" and
    qn = "javax.net.ssl.SSLContext.init"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.net.ssl", "HttpsURLConnection") and
    m.getName() = "setSSLSocketFactory" and
    qn = "javax.net.ssl.HttpsURLConnection.setSSLSocketFactory"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.net.ssl", "HttpsURLConnection") and
    m.getName() = "setHostnameVerifier" and
    qn = "javax.net.ssl.HttpsURLConnection.setHostnameVerifier"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.xml.crypto.dsig", "XMLSignatureFactory") and
    m.getName() = "getInstance" and
    qn = "javax.xml.crypto.dsig.XMLSignatureFactory.getInstance"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.xml.crypto.dsig", "XMLSignatureFactory") and
    m.getName() = "unmarshalXMLSignature" and
    qn = "javax.xml.crypto.dsig.XMLSignatureFactory.unmarshalXMLSignature"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.xml.crypto.dsig", "XMLSignature") and
    m.getName() = "validate" and
    qn = "javax.xml.crypto.dsig.XMLSignature.validate"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("javax.xml.crypto.dsig.dom", "DOMValidateContext") and
    qn = "javax.xml.crypto.dsig.dom.DOMValidateContext.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.xml.crypto.dsig.dom", "DOMValidateContext") and
    m.getName() = "setProperty" and
    qn = "javax.xml.crypto.dsig.dom.DOMValidateContext.setProperty"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.xml.crypto.dsig.keyinfo", "KeyInfoFactory") and
    m.getName() = "getInstance" and
    qn = "javax.xml.crypto.dsig.keyinfo.KeyInfoFactory.getInstance"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.xml.crypto.dsig.keyinfo", "KeyInfoFactory") and
    m.getName() = "unmarshalKeyInfo" and
    qn = "javax.xml.crypto.dsig.keyinfo.KeyInfoFactory.unmarshalKeyInfo"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.xml.crypto", "KeySelector") and
    m.getName() = "select" and
    qn = "javax.xml.crypto.KeySelector.select"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.xml.crypto.dsig.keyinfo", "KeyValue") and
    m.getName() = "getPublicKey" and
    qn = "javax.xml.crypto.dsig.keyinfo.KeyValue.getPublicKey"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.xml.crypto.dsig", "XMLSignatureFactory") and
    m.getName() = "getInstance" and
    qn = "jakarta.xml.crypto.dsig.XMLSignatureFactory.getInstance"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.xml.crypto.dsig", "XMLSignatureFactory") and
    m.getName() = "unmarshalXMLSignature" and
    qn = "jakarta.xml.crypto.dsig.XMLSignatureFactory.unmarshalXMLSignature"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.xml.crypto.dsig", "XMLSignature") and
    m.getName() = "validate" and
    qn = "jakarta.xml.crypto.dsig.XMLSignature.validate"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("jakarta.xml.crypto.dsig.dom", "DOMValidateContext") and
    qn = "jakarta.xml.crypto.dsig.dom.DOMValidateContext.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.xml.crypto.dsig.dom", "DOMValidateContext") and
    m.getName() = "setProperty" and
    qn = "jakarta.xml.crypto.dsig.dom.DOMValidateContext.setProperty"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.xml.crypto.dsig.keyinfo", "KeyInfoFactory") and
    m.getName() = "getInstance" and
    qn = "jakarta.xml.crypto.dsig.keyinfo.KeyInfoFactory.getInstance"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.xml.crypto.dsig.keyinfo", "KeyInfoFactory") and
    m.getName() = "unmarshalKeyInfo" and
    qn = "jakarta.xml.crypto.dsig.keyinfo.KeyInfoFactory.unmarshalKeyInfo"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.xml.crypto", "KeySelector") and
    m.getName() = "select" and
    qn = "jakarta.xml.crypto.KeySelector.select"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.xml.crypto.dsig.keyinfo", "KeyValue") and
    m.getName() = "getPublicKey" and
    qn = "jakarta.xml.crypto.dsig.keyinfo.KeyValue.getPublicKey"
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
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.nimbusds.jose", "JWSHeader") and
    m.getName() = "getAlgorithm" and
    qn = "com.nimbusds.jose.JWSHeader.getAlgorithm"
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
    m.getDeclaringType().hasQualifiedName("com.nimbusds.jose.jwk", "JWK") and
    m.getName() = "parse" and
    qn = "com.nimbusds.jose.jwk.JWK.parse"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.nimbusds.jose.jwk", "JWKSet") and
    m.getName() = "load" and
    qn = "com.nimbusds.jose.jwk.JWKSet.load"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.nimbusds.jose.jwk", "JWKSet") and
    m.getName() = "parse" and
    qn = "com.nimbusds.jose.jwk.JWKSet.parse"
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
    m.getDeclaringType().hasQualifiedName("com.nimbusds.jwt", "SignedJWT") and
    m.getName() = "getJWTClaimsSet" and
    qn = "com.nimbusds.jwt.SignedJWT.getJWTClaimsSet"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.nimbusds.jwt", "JWTClaimsSet") and
    m.getName() = "getIssuer" and
    qn = "com.nimbusds.jwt.JWTClaimsSet.getIssuer"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.nimbusds.jwt", "JWTClaimsSet") and
    m.getName() = "getSubject" and
    qn = "com.nimbusds.jwt.JWTClaimsSet.getSubject"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.nimbusds.jwt", "JWTClaimsSet") and
    m.getName() = "getAudience" and
    qn = "com.nimbusds.jwt.JWTClaimsSet.getAudience"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.nimbusds.jwt", "JWTClaimsSet") and
    m.getName() = "getExpirationTime" and
    qn = "com.nimbusds.jwt.JWTClaimsSet.getExpirationTime"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.nimbusds.jwt", "JWTClaimsSet") and
    m.getName() = "getNotBeforeTime" and
    qn = "com.nimbusds.jwt.JWTClaimsSet.getNotBeforeTime"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.nimbusds.jwt", "JWTClaimsSet") and
    m.getName() = "getIssueTime" and
    qn = "com.nimbusds.jwt.JWTClaimsSet.getIssueTime"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("com.nimbusds.jose.proc", "DefaultJOSEObjectTypeVerifier") and
    qn = "com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("com.nimbusds.jose.proc", "JWSVerificationKeySelector") and
    qn = "com.nimbusds.jose.proc.JWSVerificationKeySelector.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("com.nimbusds.jose.proc", "DefaultJWTProcessor") and
    qn = "com.nimbusds.jose.proc.DefaultJWTProcessor.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.nimbusds.jose.proc", "DefaultJWTProcessor") and
    m.getName() = "process" and
    qn = "com.nimbusds.jose.proc.DefaultJWTProcessor.process"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("com.nimbusds.jose.proc", "SecurityContext") and
    qn = "com.nimbusds.jose.proc.SecurityContext.<init>"
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
    m.getName() = "parseClaimsJwt" and
    qn = "io.jsonwebtoken.JwtParser.parseClaimsJwt"
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
    m.getName() = "setSigningKeyResolver" and
    qn = "io.jsonwebtoken.JwtParserBuilder.setSigningKeyResolver"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("io.jsonwebtoken", "JwtParserBuilder") and
    m.getName() = "requireIssuer" and
    qn = "io.jsonwebtoken.JwtParserBuilder.requireIssuer"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("io.jsonwebtoken", "JwtParserBuilder") and
    m.getName() = "requireAudience" and
    qn = "io.jsonwebtoken.JwtParserBuilder.requireAudience"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("io.jsonwebtoken", "JwtParserBuilder") and
    m.getName() = "requireSubject" and
    qn = "io.jsonwebtoken.JwtParserBuilder.requireSubject"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("io.jsonwebtoken", "JwtParserBuilder") and
    m.getName() = "build" and
    qn = "io.jsonwebtoken.JwtParserBuilder.build"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("io.jsonwebtoken.security", "Keys") and
    m.getName() = "hmacShaKeyFor" and
    qn = "io.jsonwebtoken.security.Keys.hmacShaKeyFor"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.auth0.jwt", "JWT") and
    m.getName() = "require" and
    qn = "com.auth0.jwt.JWT.require"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.auth0.jwt", "JWT") and
    m.getName() = "decode" and
    qn = "com.auth0.jwt.JWT.decode"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.auth0.jwt", "JWTVerifier") and
    m.getName() = "verify" and
    qn = "com.auth0.jwt.JWTVerifier.verify"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("com.auth0.jwt", "JWTVerifier$BaseVerification") and
    qn = "com.auth0.jwt.JWTVerifier$BaseVerification.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.auth0.jwt", "JWTVerifier$BaseVerification") and
    m.getName() = "build" and
    qn = "com.auth0.jwt.JWTVerifier$BaseVerification.build"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.auth0.jwt.algorithms", "Algorithm") and
    m.getName() = "HMAC256" and
    qn = "com.auth0.jwt.algorithms.Algorithm.HMAC256"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.auth0.jwt.algorithms", "Algorithm") and
    m.getName() = "HMAC384" and
    qn = "com.auth0.jwt.algorithms.Algorithm.HMAC384"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.auth0.jwt.algorithms", "Algorithm") and
    m.getName() = "HMAC512" and
    qn = "com.auth0.jwt.algorithms.Algorithm.HMAC512"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.auth0.jwt.algorithms", "Algorithm") and
    m.getName() = "RSA256" and
    qn = "com.auth0.jwt.algorithms.Algorithm.RSA256"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.auth0.jwt.algorithms", "Algorithm") and
    m.getName() = "RSA384" and
    qn = "com.auth0.jwt.algorithms.Algorithm.RSA384"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.auth0.jwt.algorithms", "Algorithm") and
    m.getName() = "RSA512" and
    qn = "com.auth0.jwt.algorithms.Algorithm.RSA512"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.auth0.jwt.algorithms", "Algorithm") and
    m.getName() = "ECDSA256" and
    qn = "com.auth0.jwt.algorithms.Algorithm.ECDSA256"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.auth0.jwt.algorithms", "Algorithm") and
    m.getName() = "ECDSA384" and
    qn = "com.auth0.jwt.algorithms.Algorithm.ECDSA384"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.auth0.jwt.algorithms", "Algorithm") and
    m.getName() = "ECDSA512" and
    qn = "com.auth0.jwt.algorithms.Algorithm.ECDSA512"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.security.oauth2.jwt", "JwtDecoder") and
    m.getName() = "decode" and
    qn = "org.springframework.security.oauth2.jwt.JwtDecoder.decode"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.security.oauth2.jwt", "NimbusJwtDecoder") and
    m.getName() = "decode" and
    qn = "org.springframework.security.oauth2.jwt.NimbusJwtDecoder.decode"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.security.oauth2.jwt", "NimbusJwtDecoder") and
    m.getName() = "withPublicKey" and
    qn = "org.springframework.security.oauth2.jwt.NimbusJwtDecoder.withPublicKey"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.security.oauth2.jwt", "NimbusJwtDecoder") and
    m.getName() = "withSecretKey" and
    qn = "org.springframework.security.oauth2.jwt.NimbusJwtDecoder.withSecretKey"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.security.oauth2.jwt", "NimbusJwtDecoder") and
    m.getName() = "withJwkSetUri" and
    qn = "org.springframework.security.oauth2.jwt.NimbusJwtDecoder.withJwkSetUri"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.security.oauth2.jwt", "JwtValidators") and
    m.getName() = "createDefault" and
    qn = "org.springframework.security.oauth2.jwt.JwtValidators.createDefault"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.security.oauth2.jwt", "JwtValidators") and
    m.getName() = "createDefaultWithIssuer" and
    qn = "org.springframework.security.oauth2.jwt.JwtValidators.createDefaultWithIssuer"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.springframework.security.oauth2.jwt", "JwtTimestampValidator") and
    qn = "org.springframework.security.oauth2.jwt.JwtTimestampValidator.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.springframework.security.oauth2.jwt", "JwtIssuerValidator") and
    qn = "org.springframework.security.oauth2.jwt.JwtIssuerValidator.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.springframework.security.oauth2.jwt", "DelegatingOAuth2TokenValidator") and
    qn = "org.springframework.security.oauth2.jwt.DelegatingOAuth2TokenValidator.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.security.oauth2.jwt", "OAuth2TokenValidator") and
    m.getName() = "validate" and
    qn = "org.springframework.security.oauth2.jwt.OAuth2TokenValidator.validate"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.xml.security", "Init") and
    m.getName() = "init" and
    qn = "org.apache.xml.security.Init.init"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.apache.xml.security.signature", "XMLSignature") and
    qn = "org.apache.xml.security.signature.XMLSignature.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.xml.security.signature", "XMLSignature") and
    m.getName() = "checkSignatureValue" and
    qn = "org.apache.xml.security.signature.XMLSignature.checkSignatureValue"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.xml.security.signature", "XMLSignature") and
    m.getName() = "sign" and
    qn = "org.apache.xml.security.signature.XMLSignature.sign"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.apache.xml.security.keys", "KeyInfo") and
    qn = "org.apache.xml.security.keys.KeyInfo.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.xml.security.keys", "KeyInfo") and
    m.getName() = "getPublicKey" and
    qn = "org.apache.xml.security.keys.KeyInfo.getPublicKey"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.xml.security.keys", "KeyInfo") and
    m.getName() = "getX509Certificate" and
    qn = "org.apache.xml.security.keys.KeyInfo.getX509Certificate"
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
