// Auto-generated; CWE-1333; number of APIs 100
import cpp

predicate isTargetApi(Function target, string qn) {
  target.getQualifiedName().matches("std%::regex%") and qn = "std::regex" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "std") and
    memberFunc.getName() = "regex" and
    qn = "std::regex"
  ) or
  target.getQualifiedName().matches("std%::wregex%") and qn = "std::wregex" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "std") and
    memberFunc.getName() = "wregex" and
    qn = "std::wregex"
  ) or
  target.getQualifiedName().matches("std%::regex_search%") and qn = "std::regex_search" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "std") and
    memberFunc.getName() = "regex_search" and
    qn = "std::regex_search"
  ) or
  target.getQualifiedName().matches("std%::regex_match%") and qn = "std::regex_match" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "std") and
    memberFunc.getName() = "regex_match" and
    qn = "std::regex_match"
  ) or
  target.getQualifiedName().matches("std%::regex_replace%") and qn = "std::regex_replace" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "std") and
    memberFunc.getName() = "regex_replace" and
    qn = "std::regex_replace"
  ) or
  target.getQualifiedName().matches("std%::sregex_iterator%") and qn = "std::sregex_iterator" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "std") and
    memberFunc.getName() = "sregex_iterator" and
    qn = "std::sregex_iterator"
  ) or
  target.getQualifiedName().matches("std%::wsregex_iterator%") and qn = "std::wsregex_iterator" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "std") and
    memberFunc.getName() = "wsregex_iterator" and
    qn = "std::wsregex_iterator"
  ) or
  target.getQualifiedName().matches("std%::regex_token_iterator%") and qn = "std::regex_token_iterator" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "std") and
    memberFunc.getName() = "regex_token_iterator" and
    qn = "std::regex_token_iterator"
  ) or
  target.getQualifiedName().matches("std%::wregex_token_iterator%") and qn = "std::wregex_token_iterator" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "std") and
    memberFunc.getName() = "wregex_token_iterator" and
    qn = "std::wregex_token_iterator"
  ) or
  target.getQualifiedName().matches("std%::tr1%::regex%") and qn = "std::tr1::regex" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "tr1") and
    memberFunc.getName() = "regex" and
    qn = "std::tr1::regex"
  ) or
  target.getQualifiedName().matches("std%::tr1%::wregex%") and qn = "std::tr1::wregex" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "tr1") and
    memberFunc.getName() = "wregex" and
    qn = "std::tr1::wregex"
  ) or
  target.getQualifiedName().matches("std%::tr1%::regex_search%") and qn = "std::tr1::regex_search" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "tr1") and
    memberFunc.getName() = "regex_search" and
    qn = "std::tr1::regex_search"
  ) or
  target.getQualifiedName().matches("std%::tr1%::regex_match%") and qn = "std::tr1::regex_match" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "tr1") and
    memberFunc.getName() = "regex_match" and
    qn = "std::tr1::regex_match"
  ) or
  target.getQualifiedName().matches("std%::tr1%::regex_replace%") and qn = "std::tr1::regex_replace" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "tr1") and
    memberFunc.getName() = "regex_replace" and
    qn = "std::tr1::regex_replace"
  ) or
  target.getQualifiedName().matches("boost%::regex%") and qn = "boost::regex" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "boost") and
    memberFunc.getName() = "regex" and
    qn = "boost::regex"
  ) or
  target.getQualifiedName().matches("boost%::wregex%") and qn = "boost::wregex" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "boost") and
    memberFunc.getName() = "wregex" and
    qn = "boost::wregex"
  ) or
  target.getQualifiedName().matches("boost%::regex_search%") and qn = "boost::regex_search" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "boost") and
    memberFunc.getName() = "regex_search" and
    qn = "boost::regex_search"
  ) or
  target.getQualifiedName().matches("boost%::regex_match%") and qn = "boost::regex_match" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "boost") and
    memberFunc.getName() = "regex_match" and
    qn = "boost::regex_match"
  ) or
  target.getQualifiedName().matches("boost%::regex_replace%") and qn = "boost::regex_replace" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "boost") and
    memberFunc.getName() = "regex_replace" and
    qn = "boost::regex_replace"
  ) or
  target.getQualifiedName().matches("boost%::sregex_iterator%") and qn = "boost::sregex_iterator" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "boost") and
    memberFunc.getName() = "sregex_iterator" and
    qn = "boost::sregex_iterator"
  ) or
  target.getQualifiedName().matches("boost%::wsregex_iterator%") and qn = "boost::wsregex_iterator" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "boost") and
    memberFunc.getName() = "wsregex_iterator" and
    qn = "boost::wsregex_iterator"
  ) or
  target.getQualifiedName().matches("boost%::xpressive%::sregex%") and qn = "boost::xpressive::sregex" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost", "xpressive") and
    memberFunc.getName() = "sregex" and
    qn = "boost::xpressive::sregex"
  ) or
  target.getQualifiedName().matches("boost%::xpressive%::wsregex%") and qn = "boost::xpressive::wsregex" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost", "xpressive") and
    memberFunc.getName() = "wsregex" and
    qn = "boost::xpressive::wsregex"
  ) or
  target.getQualifiedName().matches("boost%::xpressive%::regex_search%") and qn = "boost::xpressive::regex_search" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost", "xpressive") and
    memberFunc.getName() = "regex_search" and
    qn = "boost::xpressive::regex_search"
  ) or
  target.getQualifiedName().matches("boost%::xpressive%::regex_match%") and qn = "boost::xpressive::regex_match" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost", "xpressive") and
    memberFunc.getName() = "regex_match" and
    qn = "boost::xpressive::regex_match"
  ) or
  target.getQualifiedName().matches("boost%::xpressive%::regex_replace%") and qn = "boost::xpressive::regex_replace" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost", "xpressive") and
    memberFunc.getName() = "regex_replace" and
    qn = "boost::xpressive::regex_replace"
  ) or
  target.getQualifiedName().matches("QRegularExpression%::QRegularExpression%") and qn = "QRegularExpression::QRegularExpression" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QRegularExpression") and
    memberFunc.getName() = "QRegularExpression" and
    qn = "QRegularExpression::QRegularExpression"
  ) or
  target.getQualifiedName().matches("QRegularExpression%::match%") and qn = "QRegularExpression::match" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QRegularExpression") and
    memberFunc.getName() = "match" and
    qn = "QRegularExpression::match"
  ) or
  target.getQualifiedName().matches("QRegularExpression%::globalMatch%") and qn = "QRegularExpression::globalMatch" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QRegularExpression") and
    memberFunc.getName() = "globalMatch" and
    qn = "QRegularExpression::globalMatch"
  ) or
  target.getQualifiedName().matches("QRegularExpressionMatch%::captured%") and qn = "QRegularExpressionMatch::captured" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QRegularExpressionMatch") and
    memberFunc.getName() = "captured" and
    qn = "QRegularExpressionMatch::captured"
  ) or
  target.getQualifiedName().matches("QRegularExpression%::replace%") and qn = "QRegularExpression::replace" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QRegularExpression") and
    memberFunc.getName() = "replace" and
    qn = "QRegularExpression::replace"
  ) or
  target.getQualifiedName().matches("QRegularExpression%::setPattern%") and qn = "QRegularExpression::setPattern" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QRegularExpression") and
    memberFunc.getName() = "setPattern" and
    qn = "QRegularExpression::setPattern"
  ) or
  target.getQualifiedName().matches("QRegExp%::QRegExp%") and qn = "QRegExp::QRegExp" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QRegExp") and
    memberFunc.getName() = "QRegExp" and
    qn = "QRegExp::QRegExp"
  ) or
  target.getQualifiedName().matches("QRegExp%::exactMatch%") and qn = "QRegExp::exactMatch" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QRegExp") and
    memberFunc.getName() = "exactMatch" and
    qn = "QRegExp::exactMatch"
  ) or
  target.getQualifiedName().matches("QRegExp%::indexIn%") and qn = "QRegExp::indexIn" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QRegExp") and
    memberFunc.getName() = "indexIn" and
    qn = "QRegExp::indexIn"
  ) or
  target.getQualifiedName().matches("QRegExp%::lastIndexIn%") and qn = "QRegExp::lastIndexIn" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QRegExp") and
    memberFunc.getName() = "lastIndexIn" and
    qn = "QRegExp::lastIndexIn"
  ) or
  target.getQualifiedName().matches("QRegExp%::cap%") and qn = "QRegExp::cap" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QRegExp") and
    memberFunc.getName() = "cap" and
    qn = "QRegExp::cap"
  ) or
  target.getQualifiedName().matches("QRegExp%::setPattern%") and qn = "QRegExp::setPattern" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QRegExp") and
    memberFunc.getName() = "setPattern" and
    qn = "QRegExp::setPattern"
  ) or
  target.getQualifiedName().matches("Poco%::RegularExpression%::RegularExpression%") and qn = "Poco::RegularExpression::RegularExpression" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Poco", "RegularExpression") and
    memberFunc.getName() = "RegularExpression" and
    qn = "Poco::RegularExpression::RegularExpression"
  ) or
  target.getQualifiedName().matches("Poco%::RegularExpression%::match%") and qn = "Poco::RegularExpression::match" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Poco", "RegularExpression") and
    memberFunc.getName() = "match" and
    qn = "Poco::RegularExpression::match"
  ) or
  target.getQualifiedName().matches("Poco%::RegularExpression%::matchNext%") and qn = "Poco::RegularExpression::matchNext" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Poco", "RegularExpression") and
    memberFunc.getName() = "matchNext" and
    qn = "Poco::RegularExpression::matchNext"
  ) or
  target.getQualifiedName().matches("Poco%::RegularExpression%::extract%") and qn = "Poco::RegularExpression::extract" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Poco", "RegularExpression") and
    memberFunc.getName() = "extract" and
    qn = "Poco::RegularExpression::extract"
  ) or
  target.getQualifiedName().matches("Poco%::RegularExpression%::split%") and qn = "Poco::RegularExpression::split" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Poco", "RegularExpression") and
    memberFunc.getName() = "split" and
    qn = "Poco::RegularExpression::split"
  ) or
  target.getQualifiedName().matches("Poco%::RegularExpression%::subst%") and qn = "Poco::RegularExpression::subst" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Poco", "RegularExpression") and
    memberFunc.getName() = "subst" and
    qn = "Poco::RegularExpression::subst"
  ) or
  target.getQualifiedName().matches("wxRegEx%::Compile%") and qn = "wxRegEx::Compile" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "wxRegEx") and
    memberFunc.getName() = "Compile" and
    qn = "wxRegEx::Compile"
  ) or
  target.getQualifiedName().matches("wxRegEx%::Matches%") and qn = "wxRegEx::Matches" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "wxRegEx") and
    memberFunc.getName() = "Matches" and
    qn = "wxRegEx::Matches"
  ) or
  target.getQualifiedName().matches("wxRegEx%::GetMatch%") and qn = "wxRegEx::GetMatch" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "wxRegEx") and
    memberFunc.getName() = "GetMatch" and
    qn = "wxRegEx::GetMatch"
  ) or
  target.getQualifiedName().matches("wxRegEx%::Replace%") and qn = "wxRegEx::Replace" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "wxRegEx") and
    memberFunc.getName() = "Replace" and
    qn = "wxRegEx::Replace"
  ) or
  target.getQualifiedName().matches("wxRegEx%::ReplaceAll%") and qn = "wxRegEx::ReplaceAll" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "wxRegEx") and
    memberFunc.getName() = "ReplaceAll" and
    qn = "wxRegEx::ReplaceAll"
  ) or
  target.getQualifiedName().matches("GRegex%::g_regex_new%") and qn = "GRegex::g_regex_new" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "GRegex") and
    memberFunc.getName() = "g_regex_new" and
    qn = "GRegex::g_regex_new"
  ) or
  target.getQualifiedName().matches("GRegex%::g_regex_match%") and qn = "GRegex::g_regex_match" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "GRegex") and
    memberFunc.getName() = "g_regex_match" and
    qn = "GRegex::g_regex_match"
  ) or
  target.getQualifiedName().matches("GRegex%::g_regex_match_all%") and qn = "GRegex::g_regex_match_all" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "GRegex") and
    memberFunc.getName() = "g_regex_match_all" and
    qn = "GRegex::g_regex_match_all"
  ) or
  target.getQualifiedName().matches("GRegex%::g_regex_replace%") and qn = "GRegex::g_regex_replace" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "GRegex") and
    memberFunc.getName() = "g_regex_replace" and
    qn = "GRegex::g_regex_replace"
  ) or
  target.getQualifiedName().matches("GRegex%::g_regex_split%") and qn = "GRegex::g_regex_split" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "GRegex") and
    memberFunc.getName() = "g_regex_split" and
    qn = "GRegex::g_regex_split"
  ) or
  target.getQualifiedName().matches("pcre_compile%") and qn = "pcre_compile" or
  target.getQualifiedName().matches("pcre_compile2%") and qn = "pcre_compile2" or
  target.getQualifiedName().matches("pcre_study%") and qn = "pcre_study" or
  target.getQualifiedName().matches("pcre_exec%") and qn = "pcre_exec" or
  target.getQualifiedName().matches("pcre_dfa_exec%") and qn = "pcre_dfa_exec" or
  target.getQualifiedName().matches("pcre2_compile%") and qn = "pcre2_compile" or
  target.getQualifiedName().matches("pcre2_compile_8%") and qn = "pcre2_compile_8" or
  target.getQualifiedName().matches("pcre2_compile_16%") and qn = "pcre2_compile_16" or
  target.getQualifiedName().matches("pcre2_compile_32%") and qn = "pcre2_compile_32" or
  target.getQualifiedName().matches("pcre2_match%") and qn = "pcre2_match" or
  target.getQualifiedName().matches("pcre2_jit_compile%") and qn = "pcre2_jit_compile" or
  target.getQualifiedName().matches("pcre2_jit_match%") and qn = "pcre2_jit_match" or
  target.getQualifiedName().matches("onig_new%") and qn = "onig_new" or
  target.getQualifiedName().matches("onig_search%") and qn = "onig_search" or
  target.getQualifiedName().matches("onig_match%") and qn = "onig_match" or
  target.getQualifiedName().matches("onig_regset_search%") and qn = "onig_regset_search" or
  target.getQualifiedName().matches("onig_free%") and qn = "onig_free" or
  target.getQualifiedName().matches("regex_t%") and qn = "regex_t" or
  target.getQualifiedName().matches("regcomp%") and qn = "regcomp" or
  target.getQualifiedName().matches("regexec%") and qn = "regexec" or
  target.getQualifiedName().matches("regerror%") and qn = "regerror" or
  target.getQualifiedName().matches("regfree%") and qn = "regfree" or
  target.getQualifiedName().matches("uregex_open%") and qn = "uregex_open" or
  target.getQualifiedName().matches("uregex_openC%") and qn = "uregex_openC" or
  target.getQualifiedName().matches("uregex_matches%") and qn = "uregex_matches" or
  target.getQualifiedName().matches("uregex_find%") and qn = "uregex_find" or
  target.getQualifiedName().matches("uregex_findNext%") and qn = "uregex_findNext" or
  target.getQualifiedName().matches("uregex_replaceAll%") and qn = "uregex_replaceAll" or
  target.getQualifiedName().matches("uregex_replaceFirst%") and qn = "uregex_replaceFirst" or
  target.getQualifiedName().matches("uregex_setText%") and qn = "uregex_setText" or
  target.getQualifiedName().matches("re2%::RE2%::RE2%") and qn = "re2::RE2::RE2" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("re2", "RE2") and
    memberFunc.getName() = "RE2" and
    qn = "re2::RE2::RE2"
  ) or
  target.getQualifiedName().matches("re2%::RE2%::FullMatch%") and qn = "re2::RE2::FullMatch" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("re2", "RE2") and
    memberFunc.getName() = "FullMatch" and
    qn = "re2::RE2::FullMatch"
  ) or
  target.getQualifiedName().matches("re2%::RE2%::PartialMatch%") and qn = "re2::RE2::PartialMatch" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("re2", "RE2") and
    memberFunc.getName() = "PartialMatch" and
    qn = "re2::RE2::PartialMatch"
  ) or
  target.getQualifiedName().matches("re2%::RE2%::Replace%") and qn = "re2::RE2::Replace" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("re2", "RE2") and
    memberFunc.getName() = "Replace" and
    qn = "re2::RE2::Replace"
  ) or
  target.getQualifiedName().matches("re2%::RE2%::GlobalReplace%") and qn = "re2::RE2::GlobalReplace" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("re2", "RE2") and
    memberFunc.getName() = "GlobalReplace" and
    qn = "re2::RE2::GlobalReplace"
  ) or
  target.getQualifiedName().matches("hs_compile%") and qn = "hs_compile" or
  target.getQualifiedName().matches("hs_compile_multi%") and qn = "hs_compile_multi" or
  target.getQualifiedName().matches("hs_scan%") and qn = "hs_scan" or
  target.getQualifiedName().matches("hs_scan_vector%") and qn = "hs_scan_vector" or
  target.getQualifiedName().matches("xmlRegexpCompile%") and qn = "xmlRegexpCompile" or
  target.getQualifiedName().matches("xmlRegexpExec%") and qn = "xmlRegexpExec" or
  target.getQualifiedName().matches("xmlRegexpPrint%") and qn = "xmlRegexpPrint" or
  target.getQualifiedName().matches("xmlRegExecPushString%") and qn = "xmlRegExecPushString" or
  target.getQualifiedName().matches("xmlRegNewExecCtxt%") and qn = "xmlRegNewExecCtxt" or
  target.getQualifiedName().matches("nettle_re_comp%") and qn = "nettle_re_comp" or
  target.getQualifiedName().matches("nettle_re_match%") and qn = "nettle_re_match"
}

predicate isInSourceCode(FunctionCall call) {
  call.getLocation().getFile().getRelativePath() != ""
}

from FunctionCall call, Function targetFunc, Function enclosingFunc, string qn
where
  targetFunc = call.getTarget() and
  isTargetApi(targetFunc, qn) and
  enclosingFunc = call.getEnclosingFunction() and
  isInSourceCode(call)
select 
"Path: " + call.getLocation().getFile(),
"call function: " + call.getLocation().getStartLine()+":"+call.getLocation().getStartColumn()+
"-"+call.getLocation().getEndLine()+":"+call.getLocation().getEndColumn(),
"call in function: " + enclosingFunc.getName() + "@" +
enclosingFunc.getLocation().getStartLine() + "-" +
enclosingFunc.getBlock().getLocation().getEndLine(),
"callee=" + qn,
"basic block: " + call.getBasicBlock().getStart().getLocation().getStartLine() + ":" +call.getBasicBlock().getStart().getLocation().getStartColumn()+
"-"+ call.getBasicBlock().getEnd().getLocation().getEndLine() + ":" + call.getBasicBlock().getEnd().getLocation().getEndColumn()
