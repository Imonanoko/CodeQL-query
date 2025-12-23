// Auto-generated; CWE-943; number of APIs 97
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
    m.getDeclaringType().hasQualifiedName("jakarta.servlet.http", "HttpServletRequest") and
    m.getName() = "getInputStream" and
    qn = "jakarta.servlet.http.HttpServletRequest.getInputStream"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.servlet.http", "HttpServletRequest") and
    m.getName() = "getReader" and
    qn = "jakarta.servlet.http.HttpServletRequest.getReader"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.servlet", "ServletRequest") and
    m.getName() = "getParameter" and
    qn = "jakarta.servlet.ServletRequest.getParameter"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.servlet", "ServletRequest") and
    m.getName() = "getParameterValues" and
    qn = "jakarta.servlet.ServletRequest.getParameterValues"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.servlet", "ServletRequest") and
    m.getName() = "getParameterMap" and
    qn = "jakarta.servlet.ServletRequest.getParameterMap"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.servlet", "ServletRequest") and
    m.getName() = "getAttribute" and
    qn = "jakarta.servlet.ServletRequest.getAttribute"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.servlet", "ServletRequest") and
    m.getName() = "getReader" and
    qn = "jakarta.servlet.ServletRequest.getReader"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.servlet", "ServletRequest") and
    m.getName() = "getInputStream" and
    qn = "jakarta.servlet.ServletRequest.getInputStream"
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
    m.getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletRequest") and
    m.getName() = "getInputStream" and
    qn = "javax.servlet.http.HttpServletRequest.getInputStream"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletRequest") and
    m.getName() = "getReader" and
    qn = "javax.servlet.http.HttpServletRequest.getReader"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.servlet", "ServletRequest") and
    m.getName() = "getParameter" and
    qn = "javax.servlet.ServletRequest.getParameter"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.servlet", "ServletRequest") and
    m.getName() = "getParameterValues" and
    qn = "javax.servlet.ServletRequest.getParameterValues"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.servlet", "ServletRequest") and
    m.getName() = "getParameterMap" and
    qn = "javax.servlet.ServletRequest.getParameterMap"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.servlet", "ServletRequest") and
    m.getName() = "getAttribute" and
    qn = "javax.servlet.ServletRequest.getAttribute"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.servlet", "ServletRequest") and
    m.getName() = "getReader" and
    qn = "javax.servlet.ServletRequest.getReader"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.servlet", "ServletRequest") and
    m.getName() = "getInputStream" and
    qn = "javax.servlet.ServletRequest.getInputStream"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.web.client", "RestTemplate") and
    m.getName() = "getForObject" and
    qn = "org.springframework.web.client.RestTemplate.getForObject"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.web.client", "RestTemplate") and
    m.getName() = "getForEntity" and
    qn = "org.springframework.web.client.RestTemplate.getForEntity"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.web.client", "RestTemplate") and
    m.getName() = "postForObject" and
    qn = "org.springframework.web.client.RestTemplate.postForObject"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.web.client", "RestTemplate") and
    m.getName() = "postForEntity" and
    qn = "org.springframework.web.client.RestTemplate.postForEntity"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.web.client", "RestTemplate") and
    m.getName() = "exchange" and
    qn = "org.springframework.web.client.RestTemplate.exchange"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.web.client", "RestTemplate") and
    m.getName() = "execute" and
    qn = "org.springframework.web.client.RestTemplate.execute"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.web.reactive.function.client", "WebClient$RequestHeadersUriSpec") and
    m.getName() = "uri" and
    qn = "org.springframework.web.reactive.function.client.WebClient$RequestHeadersUriSpec.uri"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.web.reactive.function.client", "WebClient$RequestBodyUriSpec") and
    m.getName() = "uri" and
    qn = "org.springframework.web.reactive.function.client.WebClient$RequestBodyUriSpec.uri"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.web.reactive.function.client", "WebClient$RequestHeadersSpec") and
    m.getName() = "retrieve" and
    qn = "org.springframework.web.reactive.function.client.WebClient$RequestHeadersSpec.retrieve"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.web.reactive.function.client", "WebClient$ResponseSpec") and
    m.getName() = "bodyToMono" and
    qn = "org.springframework.web.reactive.function.client.WebClient$ResponseSpec.bodyToMono"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.web.reactive.function.client", "WebClient$ResponseSpec") and
    m.getName() = "bodyToFlux" and
    qn = "org.springframework.web.reactive.function.client.WebClient$ResponseSpec.bodyToFlux"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.ws.rs.client", "Client") and
    m.getName() = "target" and
    qn = "javax.ws.rs.client.Client.target"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.ws.rs.client", "WebTarget") and
    m.getName() = "request" and
    qn = "javax.ws.rs.client.WebTarget.request"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.ws.rs.client", "Invocation$Builder") and
    m.getName() = "get" and
    qn = "javax.ws.rs.client.Invocation$Builder.get"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.ws.rs.client", "Invocation$Builder") and
    m.getName() = "post" and
    qn = "javax.ws.rs.client.Invocation$Builder.post"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.ws.rs.client", "Invocation$Builder") and
    m.getName() = "put" and
    qn = "javax.ws.rs.client.Invocation$Builder.put"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.ws.rs.client", "Invocation$Builder") and
    m.getName() = "delete" and
    qn = "javax.ws.rs.client.Invocation$Builder.delete"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.ws.rs.client", "Client") and
    m.getName() = "target" and
    qn = "jakarta.ws.rs.client.Client.target"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.ws.rs.client", "WebTarget") and
    m.getName() = "request" and
    qn = "jakarta.ws.rs.client.WebTarget.request"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.ws.rs.client", "Invocation$Builder") and
    m.getName() = "get" and
    qn = "jakarta.ws.rs.client.Invocation$Builder.get"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.ws.rs.client", "Invocation$Builder") and
    m.getName() = "post" and
    qn = "jakarta.ws.rs.client.Invocation$Builder.post"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.ws.rs.client", "Invocation$Builder") and
    m.getName() = "put" and
    qn = "jakarta.ws.rs.client.Invocation$Builder.put"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.ws.rs.client", "Invocation$Builder") and
    m.getName() = "delete" and
    qn = "jakarta.ws.rs.client.Invocation$Builder.delete"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.http.client", "HttpClient") and
    m.getName() = "execute" and
    qn = "org.apache.http.client.HttpClient.execute"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.http.impl.client", "CloseableHttpClient") and
    m.getName() = "execute" and
    qn = "org.apache.http.impl.client.CloseableHttpClient.execute"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.http.client.methods", "RequestBuilder") and
    m.getName() = "setUri" and
    qn = "org.apache.http.client.methods.RequestBuilder.setUri"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.hc.client5.http.classic", "HttpClient") and
    m.getName() = "execute" and
    qn = "org.apache.hc.client5.http.classic.HttpClient.execute"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.hc.client5.http.impl.classic", "CloseableHttpClient") and
    m.getName() = "execute" and
    qn = "org.apache.hc.client5.http.impl.classic.CloseableHttpClient.execute"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("okhttp3", "OkHttpClient") and
    m.getName() = "newCall" and
    qn = "okhttp3.OkHttpClient.newCall"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("okhttp3", "Request$Builder") and
    m.getName() = "url" and
    qn = "okhttp3.Request$Builder.url"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("okhttp3", "Call") and
    m.getName() = "execute" and
    qn = "okhttp3.Call.execute"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("okhttp3", "Call") and
    m.getName() = "enqueue" and
    qn = "okhttp3.Call.enqueue"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("okhttp3", "HttpUrl") and
    m.getName() = "parse" and
    qn = "okhttp3.HttpUrl.parse"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("okhttp3", "HttpUrl") and
    m.getName() = "get" and
    qn = "okhttp3.HttpUrl.get"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("java.net", "URL") and
    qn = "java.net.URL.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.net", "URL") and
    m.getName() = "openConnection" and
    qn = "java.net.URL.openConnection"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.net", "URL") and
    m.getName() = "openStream" and
    qn = "java.net.URL.openStream"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("java.net", "URI") and
    qn = "java.net.URI.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.net", "URI") and
    m.getName() = "create" and
    qn = "java.net.URI.create"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.net.http", "HttpClient") and
    m.getName() = "send" and
    qn = "java.net.http.HttpClient.send"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.net.http", "HttpClient") and
    m.getName() = "sendAsync" and
    qn = "java.net.http.HttpClient.sendAsync"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.net.http", "HttpRequest$Builder") and
    m.getName() = "uri" and
    qn = "java.net.http.HttpRequest$Builder.uri"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("java.net", "Socket") and
    qn = "java.net.Socket.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.net", "Socket") and
    m.getName() = "connect" and
    qn = "java.net.Socket.connect"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.nio.channels", "SocketChannel") and
    m.getName() = "connect" and
    qn = "java.nio.channels.SocketChannel.connect"
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
    m.getDeclaringType().hasQualifiedName("jakarta.servlet.http", "HttpServletResponse") and
    m.getName() = "sendRedirect" and
    qn = "jakarta.servlet.http.HttpServletResponse.sendRedirect"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletResponse") and
    m.getName() = "sendRedirect" and
    qn = "javax.servlet.http.HttpServletResponse.sendRedirect"
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
    m.getDeclaringType().hasQualifiedName("org.springframework.web.servlet.support", "ServletUriComponentsBuilder") and
    m.getName() = "fromUriString" and
    qn = "org.springframework.web.servlet.support.ServletUriComponentsBuilder.fromUriString"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.web.servlet.support", "ServletUriComponentsBuilder") and
    m.getName() = "fromHttpUrl" and
    qn = "org.springframework.web.servlet.support.ServletUriComponentsBuilder.fromHttpUrl"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.web.servlet.support", "ServletUriComponentsBuilder") and
    m.getName() = "fromCurrentRequest" and
    qn = "org.springframework.web.servlet.support.ServletUriComponentsBuilder.fromCurrentRequest"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.web.servlet.support", "ServletUriComponentsBuilder") and
    m.getName() = "toUriString" and
    qn = "org.springframework.web.servlet.support.ServletUriComponentsBuilder.toUriString"
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
