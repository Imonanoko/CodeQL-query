// Auto-generated; CWE-643; number of APIs 103
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
    m.getDeclaringType().hasQualifiedName("javax.xml.parsers", "DocumentBuilderFactory") and
    m.getName() = "newInstance" and
    qn = "javax.xml.parsers.DocumentBuilderFactory.newInstance"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.xml.parsers", "DocumentBuilderFactory") and
    m.getName() = "newDocumentBuilder" and
    qn = "javax.xml.parsers.DocumentBuilderFactory.newDocumentBuilder"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.xml.parsers", "DocumentBuilder") and
    m.getName() = "parse" and
    qn = "javax.xml.parsers.DocumentBuilder.parse"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.xml.parsers", "SAXParserFactory") and
    m.getName() = "newInstance" and
    qn = "javax.xml.parsers.SAXParserFactory.newInstance"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.xml.parsers", "SAXParserFactory") and
    m.getName() = "newSAXParser" and
    qn = "javax.xml.parsers.SAXParserFactory.newSAXParser"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.xml.parsers", "SAXParser") and
    m.getName() = "parse" and
    qn = "javax.xml.parsers.SAXParser.parse"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.xml.sax", "InputSource") and
    qn = "org.xml.sax.InputSource.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.xml.sax", "InputSource") and
    m.getName() = "setCharacterStream" and
    qn = "org.xml.sax.InputSource.setCharacterStream"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.xml.sax", "InputSource") and
    m.getName() = "setByteStream" and
    qn = "org.xml.sax.InputSource.setByteStream"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.xml.sax", "InputSource") and
    m.getName() = "setSystemId" and
    qn = "org.xml.sax.InputSource.setSystemId"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.xml.xpath", "XPathFactory") and
    m.getName() = "newInstance" and
    qn = "javax.xml.xpath.XPathFactory.newInstance"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.xml.xpath", "XPathFactory") and
    m.getName() = "newXPath" and
    qn = "javax.xml.xpath.XPathFactory.newXPath"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.xml.xpath", "XPath") and
    m.getName() = "compile" and
    qn = "javax.xml.xpath.XPath.compile"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.xml.xpath", "XPath") and
    m.getName() = "evaluate" and
    qn = "javax.xml.xpath.XPath.evaluate"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.xml.xpath", "XPathExpression") and
    m.getName() = "evaluate" and
    qn = "javax.xml.xpath.XPathExpression.evaluate"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.dom4j", "Document") and
    m.getName() = "selectNodes" and
    qn = "org.dom4j.Document.selectNodes"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.dom4j", "Document") and
    m.getName() = "selectSingleNode" and
    qn = "org.dom4j.Document.selectSingleNode"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.dom4j", "Document") and
    m.getName() = "valueOf" and
    qn = "org.dom4j.Document.valueOf"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.dom4j", "Document") and
    m.getName() = "numberValueOf" and
    qn = "org.dom4j.Document.numberValueOf"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.dom4j", "Document") and
    m.getName() = "selectObject" and
    qn = "org.dom4j.Document.selectObject"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.dom4j", "Branch") and
    m.getName() = "selectNodes" and
    qn = "org.dom4j.Branch.selectNodes"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.dom4j", "Branch") and
    m.getName() = "selectSingleNode" and
    qn = "org.dom4j.Branch.selectSingleNode"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.dom4j", "Node") and
    m.getName() = "selectNodes" and
    qn = "org.dom4j.Node.selectNodes"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.dom4j", "Node") and
    m.getName() = "selectSingleNode" and
    qn = "org.dom4j.Node.selectSingleNode"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.dom4j", "Node") and
    m.getName() = "valueOf" and
    qn = "org.dom4j.Node.valueOf"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.dom4j", "XPath") and
    m.getName() = "selectNodes" and
    qn = "org.dom4j.XPath.selectNodes"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.dom4j", "XPath") and
    m.getName() = "selectSingleNode" and
    qn = "org.dom4j.XPath.selectSingleNode"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.dom4j", "XPath") and
    m.getName() = "valueOf" and
    qn = "org.dom4j.XPath.valueOf"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.dom4j", "XPath") and
    m.getName() = "numberValueOf" and
    qn = "org.dom4j.XPath.numberValueOf"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.jdom2.xpath", "XPathFactory") and
    m.getName() = "instance" and
    qn = "org.jdom2.xpath.XPathFactory.instance"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.jdom2.xpath", "XPathFactory") and
    m.getName() = "compile" and
    qn = "org.jdom2.xpath.XPathFactory.compile"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.jdom2.xpath", "XPathExpression") and
    m.getName() = "evaluate" and
    qn = "org.jdom2.xpath.XPathExpression.evaluate"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.jdom2.xpath", "XPathExpression") and
    m.getName() = "evaluateFirst" and
    qn = "org.jdom2.xpath.XPathExpression.evaluateFirst"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.jaxen", "XPath") and
    m.getName() = "selectNodes" and
    qn = "org.jaxen.XPath.selectNodes"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.jaxen", "XPath") and
    m.getName() = "selectSingleNode" and
    qn = "org.jaxen.XPath.selectSingleNode"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.jaxen", "XPath") and
    m.getName() = "valueOf" and
    qn = "org.jaxen.XPath.valueOf"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.jaxen", "XPath") and
    m.getName() = "numberValueOf" and
    qn = "org.jaxen.XPath.numberValueOf"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.jaxen.dom", "DOMXPath") and
    qn = "org.jaxen.dom.DOMXPath.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.jaxen.dom", "DOMXPath") and
    m.getName() = "selectNodes" and
    qn = "org.jaxen.dom.DOMXPath.selectNodes"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.jaxen.dom", "DOMXPath") and
    m.getName() = "selectSingleNode" and
    qn = "org.jaxen.dom.DOMXPath.selectSingleNode"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.jaxen.dom", "DOMXPath") and
    m.getName() = "valueOf" and
    qn = "org.jaxen.dom.DOMXPath.valueOf"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.jaxen.jdom", "JDOMXPath") and
    qn = "org.jaxen.jdom.JDOMXPath.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.jaxen.jdom", "JDOMXPath") and
    m.getName() = "selectNodes" and
    qn = "org.jaxen.jdom.JDOMXPath.selectNodes"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.jaxen.jdom", "JDOMXPath") and
    m.getName() = "selectSingleNode" and
    qn = "org.jaxen.jdom.JDOMXPath.selectSingleNode"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.jaxen.jdom", "JDOMXPath") and
    m.getName() = "valueOf" and
    qn = "org.jaxen.jdom.JDOMXPath.valueOf"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.jaxen.dom4j", "Dom4jXPath") and
    qn = "org.jaxen.dom4j.Dom4jXPath.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.jaxen.dom4j", "Dom4jXPath") and
    m.getName() = "selectNodes" and
    qn = "org.jaxen.dom4j.Dom4jXPath.selectNodes"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.jaxen.dom4j", "Dom4jXPath") and
    m.getName() = "selectSingleNode" and
    qn = "org.jaxen.dom4j.Dom4jXPath.selectSingleNode"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.jaxen.dom4j", "Dom4jXPath") and
    m.getName() = "valueOf" and
    qn = "org.jaxen.dom4j.Dom4jXPath.valueOf"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("net.sf.saxon.s9api", "Processor") and
    qn = "net.sf.saxon.s9api.Processor.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("net.sf.saxon.s9api", "Processor") and
    m.getName() = "newXPathCompiler" and
    qn = "net.sf.saxon.s9api.Processor.newXPathCompiler"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("net.sf.saxon.s9api", "XPathCompiler") and
    m.getName() = "compile" and
    qn = "net.sf.saxon.s9api.XPathCompiler.compile"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("net.sf.saxon.s9api", "XPathCompiler") and
    m.getName() = "declareNamespace" and
    qn = "net.sf.saxon.s9api.XPathCompiler.declareNamespace"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("net.sf.saxon.s9api", "XPathCompiler") and
    m.getName() = "declareVariable" and
    qn = "net.sf.saxon.s9api.XPathCompiler.declareVariable"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("net.sf.saxon.s9api", "XPathSelector") and
    m.getName() = "setContextItem" and
    qn = "net.sf.saxon.s9api.XPathSelector.setContextItem"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("net.sf.saxon.s9api", "XPathSelector") and
    m.getName() = "evaluate" and
    qn = "net.sf.saxon.s9api.XPathSelector.evaluate"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("net.sf.saxon.s9api", "XPathSelector") and
    m.getName() = "evaluateSingle" and
    qn = "net.sf.saxon.s9api.XPathSelector.evaluateSingle"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("net.sf.saxon.s9api", "XPathSelector") and
    m.getName() = "iterator" and
    qn = "net.sf.saxon.s9api.XPathSelector.iterator"
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
    m.getDeclaringType().hasQualifiedName("java.lang", "StringBuilder") and
    m.getName() = "append" and
    qn = "java.lang.StringBuilder.append"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.lang", "StringBuffer") and
    m.getName() = "append" and
    qn = "java.lang.StringBuffer.append"
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
