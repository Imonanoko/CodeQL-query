// Auto-generated; CWE-1333; number of APIs 104
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
    m.getDeclaringType().hasQualifiedName("java.util.regex", "Pattern") and
    m.getName() = "compile" and
    qn = "java.util.regex.Pattern.compile"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.util.regex", "Pattern") and
    m.getName() = "matches" and
    qn = "java.util.regex.Pattern.matches"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.util.regex", "Pattern") and
    m.getName() = "quote" and
    qn = "java.util.regex.Pattern.quote"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.util.regex", "Pattern") and
    m.getName() = "matcher" and
    qn = "java.util.regex.Pattern.matcher"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.util.regex", "Pattern") and
    m.getName() = "split" and
    qn = "java.util.regex.Pattern.split"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.util.regex", "Pattern") and
    m.getName() = "splitAsStream" and
    qn = "java.util.regex.Pattern.splitAsStream"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.util.regex", "Matcher") and
    m.getName() = "matches" and
    qn = "java.util.regex.Matcher.matches"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.util.regex", "Matcher") and
    m.getName() = "find" and
    qn = "java.util.regex.Matcher.find"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.util.regex", "Matcher") and
    m.getName() = "lookingAt" and
    qn = "java.util.regex.Matcher.lookingAt"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.util.regex", "Matcher") and
    m.getName() = "replaceAll" and
    qn = "java.util.regex.Matcher.replaceAll"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.util.regex", "Matcher") and
    m.getName() = "replaceFirst" and
    qn = "java.util.regex.Matcher.replaceFirst"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.util.regex", "Matcher") and
    m.getName() = "appendReplacement" and
    qn = "java.util.regex.Matcher.appendReplacement"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.util.regex", "Matcher") and
    m.getName() = "appendTail" and
    qn = "java.util.regex.Matcher.appendTail"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.util.regex", "Matcher") and
    m.getName() = "group" and
    qn = "java.util.regex.Matcher.group"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.util.regex", "Matcher") and
    m.getName() = "groupCount" and
    qn = "java.util.regex.Matcher.groupCount"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.util.regex", "Matcher") and
    m.getName() = "start" and
    qn = "java.util.regex.Matcher.start"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.util.regex", "Matcher") and
    m.getName() = "end" and
    qn = "java.util.regex.Matcher.end"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.lang", "String") and
    m.getName() = "matches" and
    qn = "java.lang.String.matches"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.lang", "String") and
    m.getName() = "split" and
    qn = "java.lang.String.split"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.lang", "String") and
    m.getName() = "replaceAll" and
    qn = "java.lang.String.replaceAll"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.lang", "String") and
    m.getName() = "replaceFirst" and
    qn = "java.lang.String.replaceFirst"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("java.util", "Scanner") and
    qn = "java.util.Scanner.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.util", "Scanner") and
    m.getName() = "useDelimiter" and
    qn = "java.util.Scanner.useDelimiter"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.util", "Scanner") and
    m.getName() = "findInLine" and
    qn = "java.util.Scanner.findInLine"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.util", "Scanner") and
    m.getName() = "findWithinHorizon" and
    qn = "java.util.Scanner.findWithinHorizon"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.util", "Scanner") and
    m.getName() = "hasNext" and
    qn = "java.util.Scanner.hasNext"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.util", "Scanner") and
    m.getName() = "next" and
    qn = "java.util.Scanner.next"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.util", "Scanner") and
    m.getName() = "nextLine" and
    qn = "java.util.Scanner.nextLine"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.util", "Scanner") and
    m.getName() = "skip" and
    qn = "java.util.Scanner.skip"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.util", "Formatter") and
    m.getName() = "format" and
    qn = "java.util.Formatter.format"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.lang", "String") and
    m.getName() = "format" and
    qn = "java.lang.String.format"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.lang3", "RegExUtils") and
    m.getName() = "removeAll" and
    qn = "org.apache.commons.lang3.RegExUtils.removeAll"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.lang3", "RegExUtils") and
    m.getName() = "removeFirst" and
    qn = "org.apache.commons.lang3.RegExUtils.removeFirst"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.lang3", "RegExUtils") and
    m.getName() = "replaceAll" and
    qn = "org.apache.commons.lang3.RegExUtils.replaceAll"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.lang3", "RegExUtils") and
    m.getName() = "replaceFirst" and
    qn = "org.apache.commons.lang3.RegExUtils.replaceFirst"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.lang3", "RegExUtils") and
    m.getName() = "replacePattern" and
    qn = "org.apache.commons.lang3.RegExUtils.replacePattern"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.apache.commons.validator.routines", "RegexValidator") and
    qn = "org.apache.commons.validator.routines.RegexValidator.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.validator.routines", "RegexValidator") and
    m.getName() = "isValid" and
    qn = "org.apache.commons.validator.routines.RegexValidator.isValid"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.validator.routines", "RegexValidator") and
    m.getName() = "match" and
    qn = "org.apache.commons.validator.routines.RegexValidator.match"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.google.re2j", "Pattern") and
    m.getName() = "compile" and
    qn = "com.google.re2j.Pattern.compile"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.google.re2j", "Pattern") and
    m.getName() = "matches" and
    qn = "com.google.re2j.Pattern.matches"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.google.re2j", "Pattern") and
    m.getName() = "quote" and
    qn = "com.google.re2j.Pattern.quote"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.google.re2j", "Pattern") and
    m.getName() = "matcher" and
    qn = "com.google.re2j.Pattern.matcher"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.google.re2j", "Matcher") and
    m.getName() = "matches" and
    qn = "com.google.re2j.Matcher.matches"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.google.re2j", "Matcher") and
    m.getName() = "find" and
    qn = "com.google.re2j.Matcher.find"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.google.re2j", "Matcher") and
    m.getName() = "lookingAt" and
    qn = "com.google.re2j.Matcher.lookingAt"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.google.re2j", "Matcher") and
    m.getName() = "replaceAll" and
    qn = "com.google.re2j.Matcher.replaceAll"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.google.re2j", "Matcher") and
    m.getName() = "replaceFirst" and
    qn = "com.google.re2j.Matcher.replaceFirst"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.ibm.icu.text", "RegexPattern") and
    m.getName() = "compile" and
    qn = "com.ibm.icu.text.RegexPattern.compile"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.ibm.icu.text", "RegexPattern") and
    m.getName() = "matcher" and
    qn = "com.ibm.icu.text.RegexPattern.matcher"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.ibm.icu.text", "RegexMatcher") and
    m.getName() = "matches" and
    qn = "com.ibm.icu.text.RegexMatcher.matches"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.ibm.icu.text", "RegexMatcher") and
    m.getName() = "find" and
    qn = "com.ibm.icu.text.RegexMatcher.find"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.ibm.icu.text", "RegexMatcher") and
    m.getName() = "lookingAt" and
    qn = "com.ibm.icu.text.RegexMatcher.lookingAt"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.ibm.icu.text", "RegexMatcher") and
    m.getName() = "replaceAll" and
    qn = "com.ibm.icu.text.RegexMatcher.replaceAll"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.ibm.icu.text", "RegexMatcher") and
    m.getName() = "replaceFirst" and
    qn = "com.ibm.icu.text.RegexMatcher.replaceFirst"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("kotlin.text", "Regex") and
    qn = "kotlin.text.Regex.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("kotlin.text", "Regex") and
    m.getName() = "matches" and
    qn = "kotlin.text.Regex.matches"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("kotlin.text", "Regex") and
    m.getName() = "containsMatchIn" and
    qn = "kotlin.text.Regex.containsMatchIn"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("kotlin.text", "Regex") and
    m.getName() = "find" and
    qn = "kotlin.text.Regex.find"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("kotlin.text", "Regex") and
    m.getName() = "findAll" and
    qn = "kotlin.text.Regex.findAll"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("kotlin.text", "Regex") and
    m.getName() = "replace" and
    qn = "kotlin.text.Regex.replace"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("kotlin.text", "Regex") and
    m.getName() = "replaceFirst" and
    qn = "kotlin.text.Regex.replaceFirst"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("kotlin.text", "Regex") and
    m.getName() = "split" and
    qn = "kotlin.text.Regex.split"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("kotlin.text", "Regex") and
    m.getName() = "toPattern" and
    qn = "kotlin.text.Regex.toPattern"
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
