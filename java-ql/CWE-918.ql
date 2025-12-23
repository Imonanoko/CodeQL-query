// Auto-generated; CWE-918; number of APIs 130
import java

predicate isTargetApi(Callable target, string qn) {
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
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.net", "URL") and
    m.getName() = "getHost" and
    qn = "java.net.URL.getHost"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.net", "URL") and
    m.getName() = "getPort" and
    qn = "java.net.URL.getPort"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.net", "URL") and
    m.getName() = "getProtocol" and
    qn = "java.net.URL.getProtocol"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.net", "URL") and
    m.getName() = "toURI" and
    qn = "java.net.URL.toURI"
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
    m.getDeclaringType().hasQualifiedName("java.net", "URI") and
    m.getName() = "resolve" and
    qn = "java.net.URI.resolve"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.net", "URI") and
    m.getName() = "normalize" and
    qn = "java.net.URI.normalize"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.net", "URI") and
    m.getName() = "getHost" and
    qn = "java.net.URI.getHost"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.net", "URI") and
    m.getName() = "getPort" and
    qn = "java.net.URI.getPort"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.net", "URI") and
    m.getName() = "getScheme" and
    qn = "java.net.URI.getScheme"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.net", "URLConnection") and
    m.getName() = "connect" and
    qn = "java.net.URLConnection.connect"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.net", "URLConnection") and
    m.getName() = "getInputStream" and
    qn = "java.net.URLConnection.getInputStream"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.net", "URLConnection") and
    m.getName() = "getOutputStream" and
    qn = "java.net.URLConnection.getOutputStream"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.net", "URLConnection") and
    m.getName() = "getHeaderField" and
    qn = "java.net.URLConnection.getHeaderField"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.net", "URLConnection") and
    m.getName() = "getHeaderFields" and
    qn = "java.net.URLConnection.getHeaderFields"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.net", "HttpURLConnection") and
    m.getName() = "connect" and
    qn = "java.net.HttpURLConnection.connect"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.net", "HttpURLConnection") and
    m.getName() = "getInputStream" and
    qn = "java.net.HttpURLConnection.getInputStream"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.net", "HttpURLConnection") and
    m.getName() = "getOutputStream" and
    qn = "java.net.HttpURLConnection.getOutputStream"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.net", "HttpURLConnection") and
    m.getName() = "getResponseCode" and
    qn = "java.net.HttpURLConnection.getResponseCode"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.net", "HttpURLConnection") and
    m.getName() = "getHeaderField" and
    qn = "java.net.HttpURLConnection.getHeaderField"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.net", "HttpURLConnection") and
    m.getName() = "getHeaderFields" and
    qn = "java.net.HttpURLConnection.getHeaderFields"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.net.ssl", "HttpsURLConnection") and
    m.getName() = "connect" and
    qn = "javax.net.ssl.HttpsURLConnection.connect"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.net.ssl", "HttpsURLConnection") and
    m.getName() = "getInputStream" and
    qn = "javax.net.ssl.HttpsURLConnection.getInputStream"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.net.ssl", "HttpsURLConnection") and
    m.getName() = "getOutputStream" and
    qn = "javax.net.ssl.HttpsURLConnection.getOutputStream"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.net.http", "HttpClient") and
    m.getName() = "newHttpClient" and
    qn = "java.net.http.HttpClient.newHttpClient"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.net.http", "HttpClient") and
    m.getName() = "newBuilder" and
    qn = "java.net.http.HttpClient.newBuilder"
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
    m.getDeclaringType().hasQualifiedName("java.net.http", "HttpRequest") and
    m.getName() = "newBuilder" and
    qn = "java.net.http.HttpRequest.newBuilder"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.net.http", "HttpRequest$Builder") and
    m.getName() = "uri" and
    qn = "java.net.http.HttpRequest$Builder.uri"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.net.http", "HttpRequest$Builder") and
    m.getName() = "build" and
    qn = "java.net.http.HttpRequest$Builder.build"
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
    m.getDeclaringType().hasQualifiedName("java.net", "Socket") and
    m.getName() = "getInputStream" and
    qn = "java.net.Socket.getInputStream"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.net", "Socket") and
    m.getName() = "getOutputStream" and
    qn = "java.net.Socket.getOutputStream"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("java.net", "ServerSocket") and
    qn = "java.net.ServerSocket.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("java.net", "DatagramSocket") and
    qn = "java.net.DatagramSocket.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.net", "DatagramSocket") and
    m.getName() = "connect" and
    qn = "java.net.DatagramSocket.connect"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.nio.channels", "SocketChannel") and
    m.getName() = "open" and
    qn = "java.nio.channels.SocketChannel.open"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.nio.channels", "SocketChannel") and
    m.getName() = "connect" and
    qn = "java.nio.channels.SocketChannel.connect"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.nio.channels", "AsynchronousSocketChannel") and
    m.getName() = "open" and
    qn = "java.nio.channels.AsynchronousSocketChannel.open"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.nio.channels", "AsynchronousSocketChannel") and
    m.getName() = "connect" and
    qn = "java.nio.channels.AsynchronousSocketChannel.connect"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.net", "SocketFactory") and
    m.getName() = "getDefault" and
    qn = "javax.net.SocketFactory.getDefault"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.net", "SocketFactory") and
    m.getName() = "createSocket" and
    qn = "javax.net.SocketFactory.createSocket"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.net.ssl", "SSLSocketFactory") and
    m.getName() = "getDefault" and
    qn = "javax.net.ssl.SSLSocketFactory.getDefault"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.net.ssl", "SSLSocketFactory") and
    m.getName() = "createSocket" and
    qn = "javax.net.ssl.SSLSocketFactory.createSocket"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.net", "InetAddress") and
    m.getName() = "getByName" and
    qn = "java.net.InetAddress.getByName"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.net", "InetAddress") and
    m.getName() = "getAllByName" and
    qn = "java.net.InetAddress.getAllByName"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.net", "InetAddress") and
    m.getName() = "getHostAddress" and
    qn = "java.net.InetAddress.getHostAddress"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.net", "InetAddress") and
    m.getName() = "isAnyLocalAddress" and
    qn = "java.net.InetAddress.isAnyLocalAddress"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.net", "InetAddress") and
    m.getName() = "isLoopbackAddress" and
    qn = "java.net.InetAddress.isLoopbackAddress"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.net", "InetAddress") and
    m.getName() = "isLinkLocalAddress" and
    qn = "java.net.InetAddress.isLinkLocalAddress"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.net", "InetAddress") and
    m.getName() = "isSiteLocalAddress" and
    qn = "java.net.InetAddress.isSiteLocalAddress"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.net", "IDN") and
    m.getName() = "toASCII" and
    qn = "java.net.IDN.toASCII"
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
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.apache.http.client.methods", "HttpGet") and
    qn = "org.apache.http.client.methods.HttpGet.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.apache.http.client.methods", "HttpPost") and
    qn = "org.apache.http.client.methods.HttpPost.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.apache.http.client.methods", "HttpPut") and
    qn = "org.apache.http.client.methods.HttpPut.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.apache.http.client.methods", "HttpDelete") and
    qn = "org.apache.http.client.methods.HttpDelete.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.http.client.methods", "RequestBuilder") and
    m.getName() = "get" and
    qn = "org.apache.http.client.methods.RequestBuilder.get"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.http.client.methods", "RequestBuilder") and
    m.getName() = "post" and
    qn = "org.apache.http.client.methods.RequestBuilder.post"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.http.client.methods", "RequestBuilder") and
    m.getName() = "put" and
    qn = "org.apache.http.client.methods.RequestBuilder.put"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.http.client.methods", "RequestBuilder") and
    m.getName() = "delete" and
    qn = "org.apache.http.client.methods.RequestBuilder.delete"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.http.client.methods", "RequestBuilder") and
    m.getName() = "setUri" and
    qn = "org.apache.http.client.methods.RequestBuilder.setUri"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.http.client.methods", "RequestBuilder") and
    m.getName() = "build" and
    qn = "org.apache.http.client.methods.RequestBuilder.build"
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
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.apache.hc.client5.http.classic.methods", "HttpGet") and
    qn = "org.apache.hc.client5.http.classic.methods.HttpGet.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.apache.hc.client5.http.classic.methods", "HttpPost") and
    qn = "org.apache.hc.client5.http.classic.methods.HttpPost.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.apache.hc.client5.http.classic.methods", "HttpPut") and
    qn = "org.apache.hc.client5.http.classic.methods.HttpPut.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.apache.hc.client5.http.classic.methods", "HttpDelete") and
    qn = "org.apache.hc.client5.http.classic.methods.HttpDelete.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.hc.core5.http.io.entity", "EntityUtils") and
    m.getName() = "toString" and
    qn = "org.apache.hc.core5.http.io.entity.EntityUtils.toString"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("okhttp3", "OkHttpClient") and
    m.getName() = "newCall" and
    qn = "okhttp3.OkHttpClient.newCall"
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
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("okhttp3", "Request$Builder") and
    qn = "okhttp3.Request$Builder.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("okhttp3", "Request$Builder") and
    m.getName() = "url" and
    qn = "okhttp3.Request$Builder.url"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("okhttp3", "Request$Builder") and
    m.getName() = "build" and
    qn = "okhttp3.Request$Builder.build"
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
    c.getDeclaringType().hasQualifiedName("org.springframework.web.client", "RestTemplate") and
    qn = "org.springframework.web.client.RestTemplate.<init>"
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
    m.getDeclaringType().hasQualifiedName("org.springframework.web.reactive.function.client", "WebClient") and
    m.getName() = "create" and
    qn = "org.springframework.web.reactive.function.client.WebClient.create"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.web.reactive.function.client", "WebClient") and
    m.getName() = "builder" and
    qn = "org.springframework.web.reactive.function.client.WebClient.builder"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.web.reactive.function.client", "WebClient$Builder") and
    m.getName() = "baseUrl" and
    qn = "org.springframework.web.reactive.function.client.WebClient$Builder.baseUrl"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.web.reactive.function.client", "WebClient$Builder") and
    m.getName() = "build" and
    qn = "org.springframework.web.reactive.function.client.WebClient$Builder.build"
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
    m.getDeclaringType().hasQualifiedName("javax.ws.rs.client", "ClientBuilder") and
    m.getName() = "newClient" and
    qn = "javax.ws.rs.client.ClientBuilder.newClient"
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
    m.getDeclaringType().hasQualifiedName("jakarta.ws.rs.client", "ClientBuilder") and
    m.getName() = "newClient" and
    qn = "jakarta.ws.rs.client.ClientBuilder.newClient"
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
    m.getDeclaringType().hasQualifiedName("kong.unirest", "Unirest") and
    m.getName() = "get" and
    qn = "kong.unirest.Unirest.get"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("kong.unirest", "Unirest") and
    m.getName() = "post" and
    qn = "kong.unirest.Unirest.post"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("kong.unirest", "Unirest") and
    m.getName() = "put" and
    qn = "kong.unirest.Unirest.put"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("kong.unirest", "Unirest") and
    m.getName() = "delete" and
    qn = "kong.unirest.Unirest.delete"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("kong.unirest", "GetRequest") and
    m.getName() = "asString" and
    qn = "kong.unirest.GetRequest.asString"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("kong.unirest", "GetRequest") and
    m.getName() = "asJson" and
    qn = "kong.unirest.GetRequest.asJson"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("kong.unirest", "GetRequest") and
    m.getName() = "asObject" and
    qn = "kong.unirest.GetRequest.asObject"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("kong.unirest", "HttpRequestWithBody") and
    m.getName() = "asString" and
    qn = "kong.unirest.HttpRequestWithBody.asString"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("kong.unirest", "HttpRequestWithBody") and
    m.getName() = "asJson" and
    qn = "kong.unirest.HttpRequestWithBody.asJson"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("kong.unirest", "HttpRequestWithBody") and
    m.getName() = "asObject" and
    qn = "kong.unirest.HttpRequestWithBody.asObject"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("retrofit2", "Retrofit$Builder") and
    qn = "retrofit2.Retrofit$Builder.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("retrofit2", "Retrofit$Builder") and
    m.getName() = "baseUrl" and
    qn = "retrofit2.Retrofit$Builder.baseUrl"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("retrofit2", "Retrofit$Builder") and
    m.getName() = "build" and
    qn = "retrofit2.Retrofit$Builder.build"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("retrofit2", "Call") and
    m.getName() = "execute" and
    qn = "retrofit2.Call.execute"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("retrofit2", "Call") and
    m.getName() = "enqueue" and
    qn = "retrofit2.Call.enqueue"
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
