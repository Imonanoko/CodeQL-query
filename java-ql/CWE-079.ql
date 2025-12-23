// Auto-generated; CWE-079; number of APIs 250
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
    m.getDeclaringType().hasQualifiedName("jakarta.servlet.http", "HttpServletRequest") and
    m.getName() = "getAttribute" and
    qn = "jakarta.servlet.http.HttpServletRequest.getAttribute"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.servlet.http", "HttpServletRequest") and
    m.getName() = "getAttributeNames" and
    qn = "jakarta.servlet.http.HttpServletRequest.getAttributeNames"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.servlet.http", "HttpSession") and
    m.getName() = "getAttribute" and
    qn = "jakarta.servlet.http.HttpSession.getAttribute"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.servlet.http", "HttpSession") and
    m.getName() = "getValue" and
    qn = "jakarta.servlet.http.HttpSession.getValue"
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
    m.getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletRequest") and
    m.getName() = "getAttribute" and
    qn = "javax.servlet.http.HttpServletRequest.getAttribute"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletRequest") and
    m.getName() = "getAttributeNames" and
    qn = "javax.servlet.http.HttpServletRequest.getAttributeNames"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpSession") and
    m.getName() = "getAttribute" and
    qn = "javax.servlet.http.HttpSession.getAttribute"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpSession") and
    m.getName() = "getValue" and
    qn = "javax.servlet.http.HttpSession.getValue"
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
    m.getDeclaringType().hasQualifiedName("jakarta.servlet.http", "HttpServletResponse") and
    m.getName() = "getWriter" and
    qn = "jakarta.servlet.http.HttpServletResponse.getWriter"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.servlet.http", "HttpServletResponse") and
    m.getName() = "getOutputStream" and
    qn = "jakarta.servlet.http.HttpServletResponse.getOutputStream"
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
    m.getDeclaringType().hasQualifiedName("jakarta.servlet.http", "HttpServletResponse") and
    m.getName() = "setStatus" and
    qn = "jakarta.servlet.http.HttpServletResponse.setStatus"
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
    m.getDeclaringType().hasQualifiedName("jakarta.servlet.http", "HttpServletResponse") and
    m.getName() = "addCookie" and
    qn = "jakarta.servlet.http.HttpServletResponse.addCookie"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.servlet", "ServletResponse") and
    m.getName() = "getWriter" and
    qn = "jakarta.servlet.ServletResponse.getWriter"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.servlet", "ServletResponse") and
    m.getName() = "getOutputStream" and
    qn = "jakarta.servlet.ServletResponse.getOutputStream"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.servlet", "ServletResponse") and
    m.getName() = "setContentType" and
    qn = "jakarta.servlet.ServletResponse.setContentType"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.servlet", "ServletResponse") and
    m.getName() = "setCharacterEncoding" and
    qn = "jakarta.servlet.ServletResponse.setCharacterEncoding"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletResponse") and
    m.getName() = "getWriter" and
    qn = "javax.servlet.http.HttpServletResponse.getWriter"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletResponse") and
    m.getName() = "getOutputStream" and
    qn = "javax.servlet.http.HttpServletResponse.getOutputStream"
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
    m.getName() = "setContentType" and
    qn = "javax.servlet.http.HttpServletResponse.setContentType"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletResponse") and
    m.getName() = "setCharacterEncoding" and
    qn = "javax.servlet.http.HttpServletResponse.setCharacterEncoding"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletResponse") and
    m.getName() = "setStatus" and
    qn = "javax.servlet.http.HttpServletResponse.setStatus"
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
    m.getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletResponse") and
    m.getName() = "addCookie" and
    qn = "javax.servlet.http.HttpServletResponse.addCookie"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.servlet", "ServletResponse") and
    m.getName() = "getWriter" and
    qn = "javax.servlet.ServletResponse.getWriter"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.servlet", "ServletResponse") and
    m.getName() = "getOutputStream" and
    qn = "javax.servlet.ServletResponse.getOutputStream"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.servlet", "ServletResponse") and
    m.getName() = "setContentType" and
    qn = "javax.servlet.ServletResponse.setContentType"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.servlet", "ServletResponse") and
    m.getName() = "setCharacterEncoding" and
    qn = "javax.servlet.ServletResponse.setCharacterEncoding"
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
    m.getName() = "println" and
    qn = "java.io.PrintWriter.println"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.io", "PrintWriter") and
    m.getName() = "write" and
    qn = "java.io.PrintWriter.write"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.io", "Writer") and
    m.getName() = "write" and
    qn = "java.io.Writer.write"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.io", "OutputStream") and
    m.getName() = "write" and
    qn = "java.io.OutputStream.write"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.servlet.jsp", "JspWriter") and
    m.getName() = "print" and
    qn = "jakarta.servlet.jsp.JspWriter.print"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.servlet.jsp", "JspWriter") and
    m.getName() = "println" and
    qn = "jakarta.servlet.jsp.JspWriter.println"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.servlet.jsp", "JspWriter") and
    m.getName() = "write" and
    qn = "jakarta.servlet.jsp.JspWriter.write"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.servlet.jsp", "JspWriter") and
    m.getName() = "print" and
    qn = "javax.servlet.jsp.JspWriter.print"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.servlet.jsp", "JspWriter") and
    m.getName() = "println" and
    qn = "javax.servlet.jsp.JspWriter.println"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.servlet.jsp", "JspWriter") and
    m.getName() = "write" and
    qn = "javax.servlet.jsp.JspWriter.write"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.servlet", "RequestDispatcher") and
    m.getName() = "forward" and
    qn = "jakarta.servlet.RequestDispatcher.forward"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.servlet", "RequestDispatcher") and
    m.getName() = "include" and
    qn = "jakarta.servlet.RequestDispatcher.include"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.servlet", "RequestDispatcher") and
    m.getName() = "forward" and
    qn = "javax.servlet.RequestDispatcher.forward"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.servlet", "RequestDispatcher") and
    m.getName() = "include" and
    qn = "javax.servlet.RequestDispatcher.include"
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
    m.getDeclaringType().hasQualifiedName("org.springframework.ui", "Model") and
    m.getName() = "addAttribute" and
    qn = "org.springframework.ui.Model.addAttribute"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.ui", "ModelMap") and
    m.getName() = "addAttribute" and
    qn = "org.springframework.ui.ModelMap.addAttribute"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.springframework.web.servlet", "ModelAndView") and
    qn = "org.springframework.web.servlet.ModelAndView.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.web.servlet", "ModelAndView") and
    m.getName() = "addObject" and
    qn = "org.springframework.web.servlet.ModelAndView.addObject"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.web.servlet", "ModelAndView") and
    m.getName() = "setViewName" and
    qn = "org.springframework.web.servlet.ModelAndView.setViewName"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.web.servlet.view", "AbstractView") and
    m.getName() = "render" and
    qn = "org.springframework.web.servlet.view.AbstractView.render"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.web.servlet.view", "AbstractView") and
    m.getName() = "renderMergedOutputModel" and
    qn = "org.springframework.web.servlet.view.AbstractView.renderMergedOutputModel"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.web.servlet.view", "InternalResourceView") and
    m.getName() = "renderMergedOutputModel" and
    qn = "org.springframework.web.servlet.view.InternalResourceView.renderMergedOutputModel"
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
    m.getDeclaringType().hasQualifiedName("org.springframework.web.servlet.support", "ServletUriComponentsBuilder") and
    m.getName() = "fromCurrentRequest" and
    qn = "org.springframework.web.servlet.support.ServletUriComponentsBuilder.fromCurrentRequest"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.web.servlet.support", "ServletUriComponentsBuilder") and
    m.getName() = "fromRequest" and
    qn = "org.springframework.web.servlet.support.ServletUriComponentsBuilder.fromRequest"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.web.servlet.support", "ServletUriComponentsBuilder") and
    m.getName() = "fromRequestUri" and
    qn = "org.springframework.web.servlet.support.ServletUriComponentsBuilder.fromRequestUri"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.web.servlet.support", "ServletUriComponentsBuilder") and
    m.getName() = "fromPath" and
    qn = "org.springframework.web.servlet.support.ServletUriComponentsBuilder.fromPath"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.web.servlet.support", "ServletUriComponentsBuilder") and
    m.getName() = "fromUriString" and
    qn = "org.springframework.web.servlet.support.ServletUriComponentsBuilder.fromUriString"
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
    m.getName() = "body" and
    qn = "org.springframework.http.ResponseEntity.body"
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
    m.getName() = "htmlEscapeDecimal" and
    qn = "org.springframework.web.util.HtmlUtils.htmlEscapeDecimal"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.web.util", "HtmlUtils") and
    m.getName() = "htmlEscapeHex" and
    qn = "org.springframework.web.util.HtmlUtils.htmlEscapeHex"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.web.util", "UriUtils") and
    m.getName() = "encode" and
    qn = "org.springframework.web.util.UriUtils.encode"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.web.util", "UriUtils") and
    m.getName() = "encodePath" and
    qn = "org.springframework.web.util.UriUtils.encodePath"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.web.util", "UriUtils") and
    m.getName() = "encodePathSegment" and
    qn = "org.springframework.web.util.UriUtils.encodePathSegment"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.web.util", "UriUtils") and
    m.getName() = "encodeQuery" and
    qn = "org.springframework.web.util.UriUtils.encodeQuery"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.web.util", "UriUtils") and
    m.getName() = "encodeQueryParam" and
    qn = "org.springframework.web.util.UriUtils.encodeQueryParam"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.web.util", "UriUtils") and
    m.getName() = "encodeFragment" and
    qn = "org.springframework.web.util.UriUtils.encodeFragment"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.web.util", "JavaScriptUtils") and
    m.getName() = "javaScriptEscape" and
    qn = "org.springframework.web.util.JavaScriptUtils.javaScriptEscape"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.web.util", "HtmlUtils") and
    m.getName() = "htmlUnescape" and
    qn = "org.springframework.web.util.HtmlUtils.htmlUnescape"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.web.util", "UriUtils") and
    m.getName() = "decode" and
    qn = "org.springframework.web.util.UriUtils.decode"
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
    m.getDeclaringType().hasQualifiedName("org.thymeleaf", "TemplateEngine") and
    m.getName() = "process" and
    qn = "org.thymeleaf.TemplateEngine.process"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.thymeleaf.context", "Context") and
    qn = "org.thymeleaf.context.Context.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.thymeleaf.context", "Context") and
    m.getName() = "setVariable" and
    qn = "org.thymeleaf.context.Context.setVariable"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.thymeleaf.context", "WebContext") and
    qn = "org.thymeleaf.context.WebContext.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.thymeleaf.context", "WebContext") and
    m.getName() = "setVariable" and
    qn = "org.thymeleaf.context.WebContext.setVariable"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("freemarker.template", "Configuration") and
    qn = "freemarker.template.Configuration.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("freemarker.template", "Configuration") and
    m.getName() = "getTemplate" and
    qn = "freemarker.template.Configuration.getTemplate"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("freemarker.template", "Template") and
    m.getName() = "process" and
    qn = "freemarker.template.Template.process"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("freemarker.template", "Template") and
    qn = "freemarker.template.Template.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("freemarker.template", "SimpleHash") and
    m.getName() = "put" and
    qn = "freemarker.template.SimpleHash.put"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("freemarker.template", "SimpleSequence") and
    m.getName() = "add" and
    qn = "freemarker.template.SimpleSequence.add"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("freemarker.core", "Environment") and
    m.getName() = "process" and
    qn = "freemarker.core.Environment.process"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("freemarker.core", "Environment") and
    m.getName() = "setVariable" and
    qn = "freemarker.core.Environment.setVariable"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.apache.velocity.app", "VelocityEngine") and
    qn = "org.apache.velocity.app.VelocityEngine.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.velocity.app", "VelocityEngine") and
    m.getName() = "evaluate" and
    qn = "org.apache.velocity.app.VelocityEngine.evaluate"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.velocity.app", "VelocityEngine") and
    m.getName() = "mergeTemplate" and
    qn = "org.apache.velocity.app.VelocityEngine.mergeTemplate"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.velocity", "Template") and
    m.getName() = "merge" and
    qn = "org.apache.velocity.Template.merge"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.apache.velocity", "VelocityContext") and
    qn = "org.apache.velocity.VelocityContext.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.velocity", "VelocityContext") and
    m.getName() = "put" and
    qn = "org.apache.velocity.VelocityContext.put"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("com.github.mustachejava", "DefaultMustacheFactory") and
    qn = "com.github.mustachejava.DefaultMustacheFactory.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.github.mustachejava", "DefaultMustacheFactory") and
    m.getName() = "compile" and
    qn = "com.github.mustachejava.DefaultMustacheFactory.compile"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.github.mustachejava", "Mustache") and
    m.getName() = "execute" and
    qn = "com.github.mustachejava.Mustache.execute"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("com.mitchellbosecke.pebble", "PebbleEngine") and
    qn = "com.mitchellbosecke.pebble.PebbleEngine.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.mitchellbosecke.pebble", "PebbleEngine") and
    m.getName() = "getTemplate" and
    qn = "com.mitchellbosecke.pebble.PebbleEngine.getTemplate"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.mitchellbosecke.pebble.template", "PebbleTemplate") and
    m.getName() = "evaluate" and
    qn = "com.mitchellbosecke.pebble.template.PebbleTemplate.evaluate"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("com.github.jknack.handlebars", "Handlebars") and
    qn = "com.github.jknack.handlebars.Handlebars.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.github.jknack.handlebars", "Handlebars") and
    m.getName() = "compile" and
    qn = "com.github.jknack.handlebars.Handlebars.compile"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.github.jknack.handlebars", "Template") and
    m.getName() = "apply" and
    qn = "com.github.jknack.handlebars.Template.apply"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.struts2.dispatcher", "Dispatcher") and
    m.getName() = "serviceAction" and
    qn = "org.apache.struts2.dispatcher.Dispatcher.serviceAction"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.struts2.dispatcher", "StrutsResultSupport") and
    m.getName() = "execute" and
    qn = "org.apache.struts2.dispatcher.StrutsResultSupport.execute"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.opensymphony.xwork2.util", "ValueStack") and
    m.getName() = "set" and
    qn = "com.opensymphony.xwork2.util.ValueStack.set"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("play.twirl.api", "Html") and
    qn = "play.twirl.api.Html.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("play.twirl.api", "HtmlFormat") and
    m.getName() = "raw" and
    qn = "play.twirl.api.HtmlFormat.raw"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("play.twirl.api", "Content") and
    m.getName() = "body" and
    qn = "play.twirl.api.Content.body"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("io.undertow.server", "HttpServerExchange") and
    m.getName() = "getQueryParameters" and
    qn = "io.undertow.server.HttpServerExchange.getQueryParameters"
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
    m.getName() = "getRequestPath" and
    qn = "io.undertow.server.HttpServerExchange.getRequestPath"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("io.undertow.server", "HttpServerExchange") and
    m.getName() = "getRequestURI" and
    qn = "io.undertow.server.HttpServerExchange.getRequestURI"
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
    m.getName() = "getResponseSender" and
    qn = "io.undertow.server.HttpServerExchange.getResponseSender"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("io.undertow.io", "Sender") and
    m.getName() = "send" and
    qn = "io.undertow.io.Sender.send"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("io.vertx.ext.web", "RoutingContext") and
    m.getName() = "request" and
    qn = "io.vertx.ext.web.RoutingContext.request"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("io.vertx.ext.web", "RoutingContext") and
    m.getName() = "response" and
    qn = "io.vertx.ext.web.RoutingContext.response"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("io.vertx.ext.web", "RoutingContext") and
    m.getName() = "getBodyAsString" and
    qn = "io.vertx.ext.web.RoutingContext.getBodyAsString"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("io.vertx.ext.web", "RoutingContext") and
    m.getName() = "pathParam" and
    qn = "io.vertx.ext.web.RoutingContext.pathParam"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("io.vertx.ext.web", "RoutingContext") and
    m.getName() = "queryParam" and
    qn = "io.vertx.ext.web.RoutingContext.queryParam"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("io.vertx.core.http", "HttpServerRequest") and
    m.getName() = "getParam" and
    qn = "io.vertx.core.http.HttpServerRequest.getParam"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("io.vertx.core.http", "HttpServerRequest") and
    m.getName() = "getHeader" and
    qn = "io.vertx.core.http.HttpServerRequest.getHeader"
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
    m.getName() = "end" and
    qn = "io.vertx.core.http.HttpServerResponse.end"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("io.vertx.core.http", "HttpServerResponse") and
    m.getName() = "write" and
    qn = "io.vertx.core.http.HttpServerResponse.write"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("spark", "Request") and
    m.getName() = "queryParams" and
    qn = "spark.Request.queryParams"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("spark", "Request") and
    m.getName() = "params" and
    qn = "spark.Request.params"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("spark", "Request") and
    m.getName() = "headers" and
    qn = "spark.Request.headers"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("spark", "Request") and
    m.getName() = "body" and
    qn = "spark.Request.body"
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
    m.getName() = "redirect" and
    qn = "spark.Response.redirect"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("spark", "Response") and
    m.getName() = "type" and
    qn = "spark.Response.type"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("spark", "Response") and
    m.getName() = "body" and
    qn = "spark.Response.body"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("io.javalin.http", "Context") and
    m.getName() = "queryParam" and
    qn = "io.javalin.http.Context.queryParam"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("io.javalin.http", "Context") and
    m.getName() = "pathParam" and
    qn = "io.javalin.http.Context.pathParam"
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
    m.getName() = "body" and
    qn = "io.javalin.http.Context.body"
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
    m.getName() = "html" and
    qn = "io.javalin.http.Context.html"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("io.javalin.http", "Context") and
    m.getName() = "json" and
    qn = "io.javalin.http.Context.json"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("io.javalin.http", "Context") and
    m.getName() = "redirect" and
    qn = "io.javalin.http.Context.redirect"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.text", "StringEscapeUtils") and
    m.getName() = "escapeHtml4" and
    qn = "org.apache.commons.text.StringEscapeUtils.escapeHtml4"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.text", "StringEscapeUtils") and
    m.getName() = "unescapeHtml4" and
    qn = "org.apache.commons.text.StringEscapeUtils.unescapeHtml4"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.text", "StringEscapeUtils") and
    m.getName() = "escapeEcmaScript" and
    qn = "org.apache.commons.text.StringEscapeUtils.escapeEcmaScript"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.text", "StringEscapeUtils") and
    m.getName() = "unescapeEcmaScript" and
    qn = "org.apache.commons.text.StringEscapeUtils.unescapeEcmaScript"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.text", "StringEscapeUtils") and
    m.getName() = "escapeJson" and
    qn = "org.apache.commons.text.StringEscapeUtils.escapeJson"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.text", "StringEscapeUtils") and
    m.getName() = "unescapeJson" and
    qn = "org.apache.commons.text.StringEscapeUtils.unescapeJson"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.text", "StringEscapeUtils") and
    m.getName() = "escapeXml10" and
    qn = "org.apache.commons.text.StringEscapeUtils.escapeXml10"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.text", "StringEscapeUtils") and
    m.getName() = "unescapeXml" and
    qn = "org.apache.commons.text.StringEscapeUtils.unescapeXml"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.lang3", "StringEscapeUtils") and
    m.getName() = "escapeHtml4" and
    qn = "org.apache.commons.lang3.StringEscapeUtils.escapeHtml4"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.lang3", "StringEscapeUtils") and
    m.getName() = "unescapeHtml4" and
    qn = "org.apache.commons.lang3.StringEscapeUtils.unescapeHtml4"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.lang3", "StringEscapeUtils") and
    m.getName() = "escapeEcmaScript" and
    qn = "org.apache.commons.lang3.StringEscapeUtils.escapeEcmaScript"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.lang3", "StringEscapeUtils") and
    m.getName() = "unescapeEcmaScript" and
    qn = "org.apache.commons.lang3.StringEscapeUtils.unescapeEcmaScript"
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
    m.getName() = "unescapeJava" and
    qn = "org.apache.commons.lang3.StringEscapeUtils.unescapeJava"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.lang3", "StringEscapeUtils") and
    m.getName() = "escapeXml10" and
    qn = "org.apache.commons.lang3.StringEscapeUtils.escapeXml10"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.lang3", "StringEscapeUtils") and
    m.getName() = "unescapeXml" and
    qn = "org.apache.commons.lang3.StringEscapeUtils.unescapeXml"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.google.common.html", "HtmlEscapers") and
    m.getName() = "htmlEscaper" and
    qn = "com.google.common.html.HtmlEscapers.htmlEscaper"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.google.common.escape", "Escaper") and
    m.getName() = "escape" and
    qn = "com.google.common.escape.Escaper.escape"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.google.common.net", "UrlEscapers") and
    m.getName() = "urlFormParameterEscaper" and
    qn = "com.google.common.net.UrlEscapers.urlFormParameterEscaper"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.google.common.net", "UrlEscapers") and
    m.getName() = "urlFragmentEscaper" and
    qn = "com.google.common.net.UrlEscapers.urlFragmentEscaper"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.google.common.net", "UrlEscapers") and
    m.getName() = "urlPathSegmentEscaper" and
    qn = "com.google.common.net.UrlEscapers.urlPathSegmentEscaper"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.owasp.encoder", "Encode") and
    m.getName() = "forHtml" and
    qn = "org.owasp.encoder.Encode.forHtml"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.owasp.encoder", "Encode") and
    m.getName() = "forHtmlContent" and
    qn = "org.owasp.encoder.Encode.forHtmlContent"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.owasp.encoder", "Encode") and
    m.getName() = "forHtmlAttribute" and
    qn = "org.owasp.encoder.Encode.forHtmlAttribute"
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
    m.getName() = "forJavaScriptAttribute" and
    qn = "org.owasp.encoder.Encode.forJavaScriptAttribute"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.owasp.encoder", "Encode") and
    m.getName() = "forCssString" and
    qn = "org.owasp.encoder.Encode.forCssString"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.owasp.encoder", "Encode") and
    m.getName() = "forCssUrl" and
    qn = "org.owasp.encoder.Encode.forCssUrl"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.owasp.encoder", "Encode") and
    m.getName() = "forUri" and
    qn = "org.owasp.encoder.Encode.forUri"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.owasp.encoder", "Encode") and
    m.getName() = "forUriComponent" and
    qn = "org.owasp.encoder.Encode.forUriComponent"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.owasp.esapi", "ESAPI") and
    m.getName() = "encoder" and
    qn = "org.owasp.esapi.ESAPI.encoder"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.owasp.esapi", "Encoder") and
    m.getName() = "encodeForHTML" and
    qn = "org.owasp.esapi.Encoder.encodeForHTML"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.owasp.esapi", "Encoder") and
    m.getName() = "encodeForHTMLAttribute" and
    qn = "org.owasp.esapi.Encoder.encodeForHTMLAttribute"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.owasp.esapi", "Encoder") and
    m.getName() = "encodeForJavaScript" and
    qn = "org.owasp.esapi.Encoder.encodeForJavaScript"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.owasp.esapi", "Encoder") and
    m.getName() = "encodeForCSS" and
    qn = "org.owasp.esapi.Encoder.encodeForCSS"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.owasp.esapi", "Encoder") and
    m.getName() = "encodeForURL" and
    qn = "org.owasp.esapi.Encoder.encodeForURL"
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
