// Auto-generated; CWE-113; number of APIs 160
import java

predicate isTargetApi(Callable target, string qn) {
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.servlet.http", "HttpServletRequest") and
    m.getName() = "getParameter" and
    qn = "jakarta.servlet.http.HttpServletRequest.getParameter"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.servlet.http", "HttpServletRequest") and
    m.getName() = "getParameterValues" and
    qn = "jakarta.servlet.http.HttpServletRequest.getParameterValues"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.servlet.http", "HttpServletRequest") and
    m.getName() = "getParameterMap" and
    qn = "jakarta.servlet.http.HttpServletRequest.getParameterMap"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.servlet.http", "HttpServletRequest") and
    m.getName() = "getHeader" and
    qn = "jakarta.servlet.http.HttpServletRequest.getHeader"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.servlet.http", "HttpServletRequest") and
    m.getName() = "getHeaders" and
    qn = "jakarta.servlet.http.HttpServletRequest.getHeaders"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.servlet.http", "HttpServletRequest") and
    m.getName() = "getHeaderNames" and
    qn = "jakarta.servlet.http.HttpServletRequest.getHeaderNames"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.servlet.http", "HttpServletRequest") and
    m.getName() = "getQueryString" and
    qn = "jakarta.servlet.http.HttpServletRequest.getQueryString"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.servlet.http", "HttpServletRequest") and
    m.getName() = "getRequestURI" and
    qn = "jakarta.servlet.http.HttpServletRequest.getRequestURI"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.servlet.http", "HttpServletRequest") and
    m.getName() = "getRequestURL" and
    qn = "jakarta.servlet.http.HttpServletRequest.getRequestURL"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.servlet.http", "HttpServletRequest") and
    m.getName() = "getPathInfo" and
    qn = "jakarta.servlet.http.HttpServletRequest.getPathInfo"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.servlet.http", "HttpServletRequest") and
    m.getName() = "getServletPath" and
    qn = "jakarta.servlet.http.HttpServletRequest.getServletPath"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.servlet.http", "HttpServletRequest") and
    m.getName() = "getCookies" and
    qn = "jakarta.servlet.http.HttpServletRequest.getCookies"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.servlet.http", "Cookie") and
    m.getName() = "getName" and
    qn = "jakarta.servlet.http.Cookie.getName"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.servlet.http", "Cookie") and
    m.getName() = "getValue" and
    qn = "jakarta.servlet.http.Cookie.getValue"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletRequest") and
    m.getName() = "getParameter" and
    qn = "javax.servlet.http.HttpServletRequest.getParameter"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletRequest") and
    m.getName() = "getParameterValues" and
    qn = "javax.servlet.http.HttpServletRequest.getParameterValues"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletRequest") and
    m.getName() = "getParameterMap" and
    qn = "javax.servlet.http.HttpServletRequest.getParameterMap"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletRequest") and
    m.getName() = "getHeader" and
    qn = "javax.servlet.http.HttpServletRequest.getHeader"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletRequest") and
    m.getName() = "getHeaders" and
    qn = "javax.servlet.http.HttpServletRequest.getHeaders"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletRequest") and
    m.getName() = "getHeaderNames" and
    qn = "javax.servlet.http.HttpServletRequest.getHeaderNames"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletRequest") and
    m.getName() = "getQueryString" and
    qn = "javax.servlet.http.HttpServletRequest.getQueryString"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletRequest") and
    m.getName() = "getRequestURI" and
    qn = "javax.servlet.http.HttpServletRequest.getRequestURI"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletRequest") and
    m.getName() = "getRequestURL" and
    qn = "javax.servlet.http.HttpServletRequest.getRequestURL"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletRequest") and
    m.getName() = "getPathInfo" and
    qn = "javax.servlet.http.HttpServletRequest.getPathInfo"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletRequest") and
    m.getName() = "getServletPath" and
    qn = "javax.servlet.http.HttpServletRequest.getServletPath"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletRequest") and
    m.getName() = "getCookies" and
    qn = "javax.servlet.http.HttpServletRequest.getCookies"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.servlet.http", "Cookie") and
    m.getName() = "getName" and
    qn = "javax.servlet.http.Cookie.getName"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.servlet.http", "Cookie") and
    m.getName() = "getValue" and
    qn = "javax.servlet.http.Cookie.getValue"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.servlet.http", "HttpServletResponse") and
    m.getName() = "setHeader" and
    qn = "jakarta.servlet.http.HttpServletResponse.setHeader"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.servlet.http", "HttpServletResponse") and
    m.getName() = "addHeader" and
    qn = "jakarta.servlet.http.HttpServletResponse.addHeader"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.servlet.http", "HttpServletResponse") and
    m.getName() = "setIntHeader" and
    qn = "jakarta.servlet.http.HttpServletResponse.setIntHeader"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.servlet.http", "HttpServletResponse") and
    m.getName() = "addIntHeader" and
    qn = "jakarta.servlet.http.HttpServletResponse.addIntHeader"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.servlet.http", "HttpServletResponse") and
    m.getName() = "setDateHeader" and
    qn = "jakarta.servlet.http.HttpServletResponse.setDateHeader"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.servlet.http", "HttpServletResponse") and
    m.getName() = "addDateHeader" and
    qn = "jakarta.servlet.http.HttpServletResponse.addDateHeader"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.servlet.http", "HttpServletResponse") and
    m.getName() = "setStatus" and
    qn = "jakarta.servlet.http.HttpServletResponse.setStatus"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.servlet.http", "HttpServletResponse") and
    m.getName() = "sendError" and
    qn = "jakarta.servlet.http.HttpServletResponse.sendError"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.servlet.http", "HttpServletResponse") and
    m.getName() = "sendRedirect" and
    qn = "jakarta.servlet.http.HttpServletResponse.sendRedirect"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.servlet.http", "HttpServletResponse") and
    m.getName() = "addCookie" and
    qn = "jakarta.servlet.http.HttpServletResponse.addCookie"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.servlet.http", "HttpServletResponse") and
    m.getName() = "setContentType" and
    qn = "jakarta.servlet.http.HttpServletResponse.setContentType"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.servlet.http", "HttpServletResponse") and
    m.getName() = "setCharacterEncoding" and
    qn = "jakarta.servlet.http.HttpServletResponse.setCharacterEncoding"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletResponse") and
    m.getName() = "setHeader" and
    qn = "javax.servlet.http.HttpServletResponse.setHeader"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletResponse") and
    m.getName() = "addHeader" and
    qn = "javax.servlet.http.HttpServletResponse.addHeader"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletResponse") and
    m.getName() = "setIntHeader" and
    qn = "javax.servlet.http.HttpServletResponse.setIntHeader"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletResponse") and
    m.getName() = "addIntHeader" and
    qn = "javax.servlet.http.HttpServletResponse.addIntHeader"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletResponse") and
    m.getName() = "setDateHeader" and
    qn = "javax.servlet.http.HttpServletResponse.setDateHeader"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletResponse") and
    m.getName() = "addDateHeader" and
    qn = "javax.servlet.http.HttpServletResponse.addDateHeader"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletResponse") and
    m.getName() = "setStatus" and
    qn = "javax.servlet.http.HttpServletResponse.setStatus"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletResponse") and
    m.getName() = "sendError" and
    qn = "javax.servlet.http.HttpServletResponse.sendError"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletResponse") and
    m.getName() = "sendRedirect" and
    qn = "javax.servlet.http.HttpServletResponse.sendRedirect"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletResponse") and
    m.getName() = "addCookie" and
    qn = "javax.servlet.http.HttpServletResponse.addCookie"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletResponse") and
    m.getName() = "setContentType" and
    qn = "javax.servlet.http.HttpServletResponse.setContentType"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletResponse") and
    m.getName() = "setCharacterEncoding" and
    qn = "javax.servlet.http.HttpServletResponse.setCharacterEncoding"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("jakarta.servlet.http", "Cookie") and
    qn = "jakarta.servlet.http.Cookie.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.servlet.http", "Cookie") and
    m.getName() = "setValue" and
    qn = "jakarta.servlet.http.Cookie.setValue"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.servlet.http", "Cookie") and
    m.getName() = "setPath" and
    qn = "jakarta.servlet.http.Cookie.setPath"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.servlet.http", "Cookie") and
    m.getName() = "setDomain" and
    qn = "jakarta.servlet.http.Cookie.setDomain"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.servlet.http", "Cookie") and
    m.getName() = "setComment" and
    qn = "jakarta.servlet.http.Cookie.setComment"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.servlet.http", "Cookie") and
    m.getName() = "setMaxAge" and
    qn = "jakarta.servlet.http.Cookie.setMaxAge"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.servlet.http", "Cookie") and
    m.getName() = "setSecure" and
    qn = "jakarta.servlet.http.Cookie.setSecure"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.servlet.http", "Cookie") and
    m.getName() = "setHttpOnly" and
    qn = "jakarta.servlet.http.Cookie.setHttpOnly"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.servlet.http", "Cookie") and
    m.getName() = "setAttribute" and
    qn = "jakarta.servlet.http.Cookie.setAttribute"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("javax.servlet.http", "Cookie") and
    qn = "javax.servlet.http.Cookie.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.servlet.http", "Cookie") and
    m.getName() = "setValue" and
    qn = "javax.servlet.http.Cookie.setValue"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.servlet.http", "Cookie") and
    m.getName() = "setPath" and
    qn = "javax.servlet.http.Cookie.setPath"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.servlet.http", "Cookie") and
    m.getName() = "setDomain" and
    qn = "javax.servlet.http.Cookie.setDomain"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.servlet.http", "Cookie") and
    m.getName() = "setComment" and
    qn = "javax.servlet.http.Cookie.setComment"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.servlet.http", "Cookie") and
    m.getName() = "setMaxAge" and
    qn = "javax.servlet.http.Cookie.setMaxAge"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.servlet.http", "Cookie") and
    m.getName() = "setSecure" and
    qn = "javax.servlet.http.Cookie.setSecure"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.servlet.http", "Cookie") and
    m.getName() = "setHttpOnly" and
    qn = "javax.servlet.http.Cookie.setHttpOnly"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.http", "HttpHeaders") and
    m.getName() = "add" and
    qn = "org.springframework.http.HttpHeaders.add"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.http", "HttpHeaders") and
    m.getName() = "set" and
    qn = "org.springframework.http.HttpHeaders.set"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.http", "HttpHeaders") and
    m.getName() = "setAll" and
    qn = "org.springframework.http.HttpHeaders.setAll"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.http", "HttpHeaders") and
    m.getName() = "put" and
    qn = "org.springframework.http.HttpHeaders.put"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.http", "HttpHeaders") and
    m.getName() = "setContentType" and
    qn = "org.springframework.http.HttpHeaders.setContentType"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.http", "HttpHeaders") and
    m.getName() = "setLocation" and
    qn = "org.springframework.http.HttpHeaders.setLocation"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.http", "HttpHeaders") and
    m.getName() = "setContentDisposition" and
    qn = "org.springframework.http.HttpHeaders.setContentDisposition"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.http", "HttpHeaders") and
    m.getName() = "setCacheControl" and
    qn = "org.springframework.http.HttpHeaders.setCacheControl"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.http", "HttpHeaders") and
    m.getName() = "setETag" and
    qn = "org.springframework.http.HttpHeaders.setETag"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.http", "HttpHeaders") and
    m.getName() = "setAccessControlAllowOrigin" and
    qn = "org.springframework.http.HttpHeaders.setAccessControlAllowOrigin"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.http", "HttpHeaders") and
    m.getName() = "setAccessControlAllowHeaders" and
    qn = "org.springframework.http.HttpHeaders.setAccessControlAllowHeaders"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.http", "HttpHeaders") and
    m.getName() = "setAccessControlAllowMethods" and
    qn = "org.springframework.http.HttpHeaders.setAccessControlAllowMethods"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.http", "HttpHeaders") and
    m.getName() = "setAccessControlExposeHeaders" and
    qn = "org.springframework.http.HttpHeaders.setAccessControlExposeHeaders"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.http", "HttpHeaders") and
    m.getName() = "setAccessControlAllowCredentials" and
    qn = "org.springframework.http.HttpHeaders.setAccessControlAllowCredentials"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.springframework.http", "ResponseEntity") and
    qn = "org.springframework.http.ResponseEntity.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.http", "ResponseEntity") and
    m.getName() = "ok" and
    qn = "org.springframework.http.ResponseEntity.ok"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.http", "ResponseEntity") and
    m.getName() = "status" and
    qn = "org.springframework.http.ResponseEntity.status"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.http", "ResponseEntity") and
    m.getName() = "headers" and
    qn = "org.springframework.http.ResponseEntity.headers"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.http", "ResponseEntity") and
    m.getName() = "header" and
    qn = "org.springframework.http.ResponseEntity.header"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.http", "ResponseEntity") and
    m.getName() = "body" and
    qn = "org.springframework.http.ResponseEntity.body"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.springframework.web.servlet.view", "RedirectView") and
    qn = "org.springframework.web.servlet.view.RedirectView.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.web.servlet.view", "RedirectView") and
    m.getName() = "setUrl" and
    qn = "org.springframework.web.servlet.view.RedirectView.setUrl"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.web.servlet.view", "RedirectView") and
    m.getName() = "setContextRelative" and
    qn = "org.springframework.web.servlet.view.RedirectView.setContextRelative"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.web.servlet.view", "RedirectView") and
    m.getName() = "setExposeModelAttributes" and
    qn = "org.springframework.web.servlet.view.RedirectView.setExposeModelAttributes"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.web.util", "UriComponentsBuilder") and
    m.getName() = "fromUriString" and
    qn = "org.springframework.web.util.UriComponentsBuilder.fromUriString"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.web.util", "UriComponentsBuilder") and
    m.getName() = "fromHttpUrl" and
    qn = "org.springframework.web.util.UriComponentsBuilder.fromHttpUrl"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.web.util", "UriComponentsBuilder") and
    m.getName() = "path" and
    qn = "org.springframework.web.util.UriComponentsBuilder.path"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.web.util", "UriComponentsBuilder") and
    m.getName() = "queryParam" and
    qn = "org.springframework.web.util.UriComponentsBuilder.queryParam"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.web.util", "UriComponentsBuilder") and
    m.getName() = "fragment" and
    qn = "org.springframework.web.util.UriComponentsBuilder.fragment"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.web.util", "UriComponentsBuilder") and
    m.getName() = "build" and
    qn = "org.springframework.web.util.UriComponentsBuilder.build"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.web.util", "UriComponentsBuilder") and
    m.getName() = "toUriString" and
    qn = "org.springframework.web.util.UriComponentsBuilder.toUriString"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("io.undertow.server", "HttpServerExchange") and
    m.getName() = "getRequestHeaders" and
    qn = "io.undertow.server.HttpServerExchange.getRequestHeaders"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("io.undertow.server", "HttpServerExchange") and
    m.getName() = "getResponseHeaders" and
    qn = "io.undertow.server.HttpServerExchange.getResponseHeaders"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("io.undertow.server", "HttpServerExchange") and
    m.getName() = "setStatusCode" and
    qn = "io.undertow.server.HttpServerExchange.setStatusCode"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("io.undertow.server.handlers", "RedirectHandler") and
    m.getName() = "handleRequest" and
    qn = "io.undertow.server.handlers.RedirectHandler.handleRequest"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("io.undertow.server.handlers", "ResponseCodeHandler") and
    m.getName() = "handleRequest" and
    qn = "io.undertow.server.handlers.ResponseCodeHandler.handleRequest"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("io.undertow.util", "HeaderMap") and
    m.getName() = "put" and
    qn = "io.undertow.util.HeaderMap.put"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("io.undertow.util", "HeaderMap") and
    m.getName() = "add" and
    qn = "io.undertow.util.HeaderMap.add"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("io.undertow.util", "Headers") and
    m.getName() = "create" and
    qn = "io.undertow.util.Headers.create"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("io.vertx.core.http", "HttpServerRequest") and
    m.getName() = "getHeader" and
    qn = "io.vertx.core.http.HttpServerRequest.getHeader"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("io.vertx.core.http", "HttpServerRequest") and
    m.getName() = "getParam" and
    qn = "io.vertx.core.http.HttpServerRequest.getParam"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("io.vertx.core.http", "HttpServerResponse") and
    m.getName() = "putHeader" and
    qn = "io.vertx.core.http.HttpServerResponse.putHeader"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("io.vertx.core.http", "HttpServerResponse") and
    m.getName() = "headers" and
    qn = "io.vertx.core.http.HttpServerResponse.headers"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("io.vertx.core.http", "HttpServerResponse") and
    m.getName() = "setStatusCode" and
    qn = "io.vertx.core.http.HttpServerResponse.setStatusCode"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("io.vertx.core.http", "HttpServerResponse") and
    m.getName() = "setStatusMessage" and
    qn = "io.vertx.core.http.HttpServerResponse.setStatusMessage"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("io.vertx.core.http", "HttpServerResponse") and
    m.getName() = "setChunked" and
    qn = "io.vertx.core.http.HttpServerResponse.setChunked"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("io.vertx.core.http", "HttpServerResponse") and
    m.getName() = "write" and
    qn = "io.vertx.core.http.HttpServerResponse.write"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("io.vertx.core.http", "HttpServerResponse") and
    m.getName() = "end" and
    qn = "io.vertx.core.http.HttpServerResponse.end"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("io.vertx.core.http", "HttpServerResponse") and
    m.getName() = "endHandler" and
    qn = "io.vertx.core.http.HttpServerResponse.endHandler"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("io.javalin.http", "Context") and
    m.getName() = "header" and
    qn = "io.javalin.http.Context.header"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("io.javalin.http", "Context") and
    m.getName() = "result" and
    qn = "io.javalin.http.Context.result"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("io.javalin.http", "Context") and
    m.getName() = "status" and
    qn = "io.javalin.http.Context.status"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("io.javalin.http", "Context") and
    m.getName() = "redirect" and
    qn = "io.javalin.http.Context.redirect"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("io.javalin.http", "Context") and
    m.getName() = "contentType" and
    qn = "io.javalin.http.Context.contentType"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("spark", "Response") and
    m.getName() = "header" and
    qn = "spark.Response.header"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("spark", "Response") and
    m.getName() = "status" and
    qn = "spark.Response.status"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("spark", "Response") and
    m.getName() = "redirect" and
    qn = "spark.Response.redirect"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("spark", "Response") and
    m.getName() = "type" and
    qn = "spark.Response.type"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("okhttp3", "Headers") and
    qn = "okhttp3.Headers.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("okhttp3", "Headers") and
    m.getName() = "of" and
    qn = "okhttp3.Headers.of"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("okhttp3", "Headers$Builder") and
    qn = "okhttp3.Headers$Builder.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("okhttp3", "Headers$Builder") and
    m.getName() = "add" and
    qn = "okhttp3.Headers$Builder.add"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("okhttp3", "Headers$Builder") and
    m.getName() = "set" and
    qn = "okhttp3.Headers$Builder.set"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("okhttp3", "Headers$Builder") and
    m.getName() = "build" and
    qn = "okhttp3.Headers$Builder.build"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("okhttp3", "Response$Builder") and
    m.getName() = "header" and
    qn = "okhttp3.Response$Builder.header"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("okhttp3", "Response$Builder") and
    m.getName() = "addHeader" and
    qn = "okhttp3.Response$Builder.addHeader"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("okhttp3", "Response$Builder") and
    m.getName() = "headers" and
    qn = "okhttp3.Response$Builder.headers"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("okhttp3", "Request$Builder") and
    m.getName() = "header" and
    qn = "okhttp3.Request$Builder.header"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("okhttp3", "Request$Builder") and
    m.getName() = "addHeader" and
    qn = "okhttp3.Request$Builder.addHeader"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("okhttp3", "Request$Builder") and
    m.getName() = "headers" and
    qn = "okhttp3.Request$Builder.headers"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.google.common.net", "HttpHeaders") and
    m.getName() = "CONTENT_TYPE" and
    qn = "com.google.common.net.HttpHeaders.CONTENT_TYPE"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.google.common.net", "HttpHeaders") and
    m.getName() = "LOCATION" and
    qn = "com.google.common.net.HttpHeaders.LOCATION"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.google.common.net", "HttpHeaders") and
    m.getName() = "SET_COOKIE" and
    qn = "com.google.common.net.HttpHeaders.SET_COOKIE"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.http", "HttpResponse") and
    m.getName() = "setHeader" and
    qn = "org.apache.http.HttpResponse.setHeader"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.http", "HttpResponse") and
    m.getName() = "addHeader" and
    qn = "org.apache.http.HttpResponse.addHeader"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.apache.http.message", "BasicHeader") and
    qn = "org.apache.http.message.BasicHeader.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.http.message", "BasicHeaderValueParser") and
    m.getName() = "parseElements" and
    qn = "org.apache.http.message.BasicHeaderValueParser.parseElements"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.http.client.methods", "HttpResponseBase") and
    m.getName() = "setHeader" and
    qn = "org.apache.http.client.methods.HttpResponseBase.setHeader"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.http.client.methods", "HttpResponseBase") and
    m.getName() = "addHeader" and
    qn = "org.apache.http.client.methods.HttpResponseBase.addHeader"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.http.client.methods", "HttpResponseBase") and
    m.getName() = "setStatusCode" and
    qn = "org.apache.http.client.methods.HttpResponseBase.setStatusCode"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("io.netty.handler.codec.http", "HttpHeaders") and
    m.getName() = "set" and
    qn = "io.netty.handler.codec.http.HttpHeaders.set"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("io.netty.handler.codec.http", "HttpHeaders") and
    m.getName() = "add" and
    qn = "io.netty.handler.codec.http.HttpHeaders.add"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("io.netty.handler.codec.http", "DefaultHttpHeaders") and
    qn = "io.netty.handler.codec.http.DefaultHttpHeaders.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("io.netty.handler.codec.http", "DefaultHttpHeaders") and
    m.getName() = "set" and
    qn = "io.netty.handler.codec.http.DefaultHttpHeaders.set"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("io.netty.handler.codec.http", "DefaultHttpHeaders") and
    m.getName() = "add" and
    qn = "io.netty.handler.codec.http.DefaultHttpHeaders.add"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("io.netty.handler.codec.http", "DefaultFullHttpResponse") and
    qn = "io.netty.handler.codec.http.DefaultFullHttpResponse.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("io.netty.handler.codec.http", "DefaultFullHttpResponse") and
    m.getName() = "headers" and
    qn = "io.netty.handler.codec.http.DefaultFullHttpResponse.headers"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("io.netty.handler.codec.http", "HttpResponse") and
    m.getName() = "setStatus" and
    qn = "io.netty.handler.codec.http.HttpResponse.setStatus"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("io.netty.handler.codec.http", "HttpResponse") and
    m.getName() = "headers" and
    qn = "io.netty.handler.codec.http.HttpResponse.headers"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("io.netty.handler.codec.http", "HttpResponse") and
    m.getName() = "setProtocolVersion" and
    qn = "io.netty.handler.codec.http.HttpResponse.setProtocolVersion"
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
