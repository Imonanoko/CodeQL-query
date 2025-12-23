// Auto-generated; CWE-117; number of APIs 126
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
    m.getDeclaringType().hasQualifiedName("jakarta.servlet.http", "HttpSession") and
    m.getName() = "getAttribute" and
    qn = "jakarta.servlet.http.HttpSession.getAttribute"
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
    m.getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpSession") and
    m.getName() = "getAttribute" and
    qn = "javax.servlet.http.HttpSession.getAttribute"
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
    m.getDeclaringType().hasQualifiedName("java.util.logging", "Logger") and
    m.getName() = "getLogger" and
    qn = "java.util.logging.Logger.getLogger"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.util.logging", "Logger") and
    m.getName() = "log" and
    qn = "java.util.logging.Logger.log"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.util.logging", "Logger") and
    m.getName() = "severe" and
    qn = "java.util.logging.Logger.severe"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.util.logging", "Logger") and
    m.getName() = "warning" and
    qn = "java.util.logging.Logger.warning"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.util.logging", "Logger") and
    m.getName() = "info" and
    qn = "java.util.logging.Logger.info"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.util.logging", "Logger") and
    m.getName() = "config" and
    qn = "java.util.logging.Logger.config"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.util.logging", "Logger") and
    m.getName() = "fine" and
    qn = "java.util.logging.Logger.fine"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.util.logging", "Logger") and
    m.getName() = "finer" and
    qn = "java.util.logging.Logger.finer"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.util.logging", "Logger") and
    m.getName() = "finest" and
    qn = "java.util.logging.Logger.finest"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.util.logging", "Logger") and
    m.getName() = "throwing" and
    qn = "java.util.logging.Logger.throwing"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.slf4j", "LoggerFactory") and
    m.getName() = "getLogger" and
    qn = "org.slf4j.LoggerFactory.getLogger"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.slf4j", "Logger") and
    m.getName() = "trace" and
    qn = "org.slf4j.Logger.trace"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.slf4j", "Logger") and
    m.getName() = "debug" and
    qn = "org.slf4j.Logger.debug"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.slf4j", "Logger") and
    m.getName() = "info" and
    qn = "org.slf4j.Logger.info"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.slf4j", "Logger") and
    m.getName() = "warn" and
    qn = "org.slf4j.Logger.warn"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.slf4j", "Logger") and
    m.getName() = "error" and
    qn = "org.slf4j.Logger.error"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.logging.log4j", "LogManager") and
    m.getName() = "getLogger" and
    qn = "org.apache.logging.log4j.LogManager.getLogger"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.logging.log4j", "Logger") and
    m.getName() = "trace" and
    qn = "org.apache.logging.log4j.Logger.trace"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.logging.log4j", "Logger") and
    m.getName() = "debug" and
    qn = "org.apache.logging.log4j.Logger.debug"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.logging.log4j", "Logger") and
    m.getName() = "info" and
    qn = "org.apache.logging.log4j.Logger.info"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.logging.log4j", "Logger") and
    m.getName() = "warn" and
    qn = "org.apache.logging.log4j.Logger.warn"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.logging.log4j", "Logger") and
    m.getName() = "error" and
    qn = "org.apache.logging.log4j.Logger.error"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.logging.log4j", "Logger") and
    m.getName() = "fatal" and
    qn = "org.apache.logging.log4j.Logger.fatal"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.logging.log4j", "Logger") and
    m.getName() = "log" and
    qn = "org.apache.logging.log4j.Logger.log"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.log4j", "Logger") and
    m.getName() = "getLogger" and
    qn = "org.apache.log4j.Logger.getLogger"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.log4j", "Logger") and
    m.getName() = "trace" and
    qn = "org.apache.log4j.Logger.trace"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.log4j", "Logger") and
    m.getName() = "debug" and
    qn = "org.apache.log4j.Logger.debug"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.log4j", "Logger") and
    m.getName() = "info" and
    qn = "org.apache.log4j.Logger.info"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.log4j", "Logger") and
    m.getName() = "warn" and
    qn = "org.apache.log4j.Logger.warn"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.log4j", "Logger") and
    m.getName() = "error" and
    qn = "org.apache.log4j.Logger.error"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.log4j", "Logger") and
    m.getName() = "fatal" and
    qn = "org.apache.log4j.Logger.fatal"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.log4j", "Logger") and
    m.getName() = "log" and
    qn = "org.apache.log4j.Logger.log"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("ch.qos.logback.classic", "Logger") and
    m.getName() = "trace" and
    qn = "ch.qos.logback.classic.Logger.trace"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("ch.qos.logback.classic", "Logger") and
    m.getName() = "debug" and
    qn = "ch.qos.logback.classic.Logger.debug"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("ch.qos.logback.classic", "Logger") and
    m.getName() = "info" and
    qn = "ch.qos.logback.classic.Logger.info"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("ch.qos.logback.classic", "Logger") and
    m.getName() = "warn" and
    qn = "ch.qos.logback.classic.Logger.warn"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("ch.qos.logback.classic", "Logger") and
    m.getName() = "error" and
    qn = "ch.qos.logback.classic.Logger.error"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.jboss.logging", "Logger") and
    m.getName() = "getLogger" and
    qn = "org.jboss.logging.Logger.getLogger"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.jboss.logging", "Logger") and
    m.getName() = "trace" and
    qn = "org.jboss.logging.Logger.trace"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.jboss.logging", "Logger") and
    m.getName() = "debug" and
    qn = "org.jboss.logging.Logger.debug"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.jboss.logging", "Logger") and
    m.getName() = "info" and
    qn = "org.jboss.logging.Logger.info"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.jboss.logging", "Logger") and
    m.getName() = "warn" and
    qn = "org.jboss.logging.Logger.warn"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.jboss.logging", "Logger") and
    m.getName() = "error" and
    qn = "org.jboss.logging.Logger.error"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.jboss.logging", "Logger") and
    m.getName() = "fatal" and
    qn = "org.jboss.logging.Logger.fatal"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.logging", "LogFactory") and
    m.getName() = "getLog" and
    qn = "org.apache.commons.logging.LogFactory.getLog"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.logging", "Log") and
    m.getName() = "trace" and
    qn = "org.apache.commons.logging.Log.trace"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.logging", "Log") and
    m.getName() = "debug" and
    qn = "org.apache.commons.logging.Log.debug"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.logging", "Log") and
    m.getName() = "info" and
    qn = "org.apache.commons.logging.Log.info"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.logging", "Log") and
    m.getName() = "warn" and
    qn = "org.apache.commons.logging.Log.warn"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.logging", "Log") and
    m.getName() = "error" and
    qn = "org.apache.commons.logging.Log.error"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.logging", "Log") and
    m.getName() = "fatal" and
    qn = "org.apache.commons.logging.Log.fatal"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.boot.logging", "LogLevel") and
    m.getName() = "values" and
    qn = "org.springframework.boot.logging.LogLevel.values"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.boot.logging", "LogLevel") and
    m.getName() = "valueOf" and
    qn = "org.springframework.boot.logging.LogLevel.valueOf"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.springframework.web.bind.annotation", "RequestParam") and
    qn = "org.springframework.web.bind.annotation.RequestParam.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.springframework.web.bind.annotation", "PathVariable") and
    qn = "org.springframework.web.bind.annotation.PathVariable.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.springframework.web.bind.annotation", "RequestHeader") and
    qn = "org.springframework.web.bind.annotation.RequestHeader.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.springframework.web.bind.annotation", "CookieValue") and
    qn = "org.springframework.web.bind.annotation.CookieValue.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.springframework.web.bind.annotation", "RequestBody") and
    qn = "org.springframework.web.bind.annotation.RequestBody.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.web.filter", "AbstractRequestLoggingFilter") and
    m.getName() = "doFilterInternal" and
    qn = "org.springframework.web.filter.AbstractRequestLoggingFilter.doFilterInternal"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.web.filter", "CommonsRequestLoggingFilter") and
    m.getName() = "beforeRequest" and
    qn = "org.springframework.web.filter.CommonsRequestLoggingFilter.beforeRequest"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.web.filter", "CommonsRequestLoggingFilter") and
    m.getName() = "afterRequest" and
    qn = "org.springframework.web.filter.CommonsRequestLoggingFilter.afterRequest"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.web.util", "HtmlUtils") and
    m.getName() = "htmlEscape" and
    qn = "org.springframework.web.util.HtmlUtils.htmlEscape"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.web.util", "HtmlUtils") and
    m.getName() = "htmlUnescape" and
    qn = "org.springframework.web.util.HtmlUtils.htmlUnescape"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.text", "StringEscapeUtils") and
    m.getName() = "escapeJava" and
    qn = "org.apache.commons.text.StringEscapeUtils.escapeJava"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.text", "StringEscapeUtils") and
    m.getName() = "escapeJson" and
    qn = "org.apache.commons.text.StringEscapeUtils.escapeJson"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.lang3", "StringEscapeUtils") and
    m.getName() = "escapeJava" and
    qn = "org.apache.commons.lang3.StringEscapeUtils.escapeJava"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.lang3", "StringEscapeUtils") and
    m.getName() = "escapeJson" and
    qn = "org.apache.commons.lang3.StringEscapeUtils.escapeJson"
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
    m.getName() = "forJavaScript" and
    qn = "org.owasp.encoder.Encode.forJavaScript"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.owasp.encoder", "Encode") and
    m.getName() = "forJson" and
    qn = "org.owasp.encoder.Encode.forJson"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.fasterxml.jackson.databind", "ObjectMapper") and
    m.getName() = "writeValueAsString" and
    qn = "com.fasterxml.jackson.databind.ObjectMapper.writeValueAsString"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.fasterxml.jackson.core", "JsonGenerator") and
    m.getName() = "writeString" and
    qn = "com.fasterxml.jackson.core.JsonGenerator.writeString"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.lang", "String") and
    m.getName() = "format" and
    qn = "java.lang.String.format"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.text", "MessageFormat") and
    m.getName() = "format" and
    qn = "java.text.MessageFormat.format"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.io", "PrintWriter") and
    m.getName() = "println" and
    qn = "java.io.PrintWriter.println"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.io", "PrintWriter") and
    m.getName() = "print" and
    qn = "java.io.PrintWriter.print"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.io", "PrintWriter") and
    m.getName() = "write" and
    qn = "java.io.PrintWriter.write"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.servlet", "ServletOutputStream") and
    m.getName() = "print" and
    qn = "jakarta.servlet.ServletOutputStream.print"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.servlet", "ServletOutputStream") and
    m.getName() = "println" and
    qn = "jakarta.servlet.ServletOutputStream.println"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.servlet", "ServletOutputStream") and
    m.getName() = "write" and
    qn = "jakarta.servlet.ServletOutputStream.write"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.servlet", "ServletOutputStream") and
    m.getName() = "print" and
    qn = "javax.servlet.ServletOutputStream.print"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.servlet", "ServletOutputStream") and
    m.getName() = "println" and
    qn = "javax.servlet.ServletOutputStream.println"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.servlet", "ServletOutputStream") and
    m.getName() = "write" and
    qn = "javax.servlet.ServletOutputStream.write"
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
