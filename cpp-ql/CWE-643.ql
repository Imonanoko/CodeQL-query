// Auto-generated; CWE-643; number of APIs 41
import cpp

predicate isTargetApi(Function target, string qn) {
  target.getQualifiedName().matches("xmlXPathEvalExpression%") and qn = "xmlXPathEvalExpression" or
  target.getQualifiedName().matches("xmlXPathEval%") and qn = "xmlXPathEval" or
  target.getQualifiedName().matches("xmlXPathCompile%") and qn = "xmlXPathCompile" or
  target.getQualifiedName().matches("xmlXPathCompiledEval%") and qn = "xmlXPathCompiledEval" or
  target.getQualifiedName().matches("xmlXPathEvalExpression__libxml2%") and qn = "xmlXPathEvalExpression__libxml2" or
  target.getQualifiedName().matches("xmlXPathEval__libxml2%") and qn = "xmlXPathEval__libxml2" or
  target.getQualifiedName().matches("xmlXPathCompile__libxml2%") and qn = "xmlXPathCompile__libxml2" or
  target.getQualifiedName().matches("xmlXPathCompiledEval__libxml2%") and qn = "xmlXPathCompiledEval__libxml2" or
  target.getQualifiedName().matches("xmlpp%::Node%::find%") and qn = "xmlpp::Node::find" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("xmlpp", "Node") and
    memberFunc.getName() = "find" and
    qn = "xmlpp::Node::find"
  ) or
  target.getQualifiedName().matches("xmlpp%::Node%::find_raw%") and qn = "xmlpp::Node::find_raw" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("xmlpp", "Node") and
    memberFunc.getName() = "find_raw" and
    qn = "xmlpp::Node::find_raw"
  ) or
  target.getQualifiedName().matches("xmlpp%::Node%::find_nodes%") and qn = "xmlpp::Node::find_nodes" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("xmlpp", "Node") and
    memberFunc.getName() = "find_nodes" and
    qn = "xmlpp::Node::find_nodes"
  ) or
  target.getQualifiedName().matches("pugi%::xpath_query%::xpath_query%") and qn = "pugi::xpath_query::xpath_query" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("pugi", "xpath_query") and
    memberFunc.getName() = "xpath_query" and
    qn = "pugi::xpath_query::xpath_query"
  ) or
  target.getQualifiedName().matches("pugi%::xml_node%::select_node%") and qn = "pugi::xml_node::select_node" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("pugi", "xml_node") and
    memberFunc.getName() = "select_node" and
    qn = "pugi::xml_node::select_node"
  ) or
  target.getQualifiedName().matches("pugi%::xml_node%::select_nodes%") and qn = "pugi::xml_node::select_nodes" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("pugi", "xml_node") and
    memberFunc.getName() = "select_nodes" and
    qn = "pugi::xml_node::select_nodes"
  ) or
  target.getQualifiedName().matches("pugi%::xpath_query%::evaluate_node%") and qn = "pugi::xpath_query::evaluate_node" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("pugi", "xpath_query") and
    memberFunc.getName() = "evaluate_node" and
    qn = "pugi::xpath_query::evaluate_node"
  ) or
  target.getQualifiedName().matches("pugi%::xpath_query%::evaluate_node_set%") and qn = "pugi::xpath_query::evaluate_node_set" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("pugi", "xpath_query") and
    memberFunc.getName() = "evaluate_node_set" and
    qn = "pugi::xpath_query::evaluate_node_set"
  ) or
  target.getQualifiedName().matches("pugi%::xpath_query%::evaluate_boolean%") and qn = "pugi::xpath_query::evaluate_boolean" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("pugi", "xpath_query") and
    memberFunc.getName() = "evaluate_boolean" and
    qn = "pugi::xpath_query::evaluate_boolean"
  ) or
  target.getQualifiedName().matches("pugi%::xpath_query%::evaluate_string%") and qn = "pugi::xpath_query::evaluate_string" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("pugi", "xpath_query") and
    memberFunc.getName() = "evaluate_string" and
    qn = "pugi::xpath_query::evaluate_string"
  ) or
  target.getQualifiedName().matches("pugi%::xpath_query%::evaluate_number%") and qn = "pugi::xpath_query::evaluate_number" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("pugi", "xpath_query") and
    memberFunc.getName() = "evaluate_number" and
    qn = "pugi::xpath_query::evaluate_number"
  ) or
  target.getQualifiedName().matches("XalanXPathEvaluator%::evaluate%") and qn = "XalanXPathEvaluator::evaluate" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "XalanXPathEvaluator") and
    memberFunc.getName() = "evaluate" and
    qn = "XalanXPathEvaluator::evaluate"
  ) or
  target.getQualifiedName().matches("XalanXPathEvaluator%::selectNodeList%") and qn = "XalanXPathEvaluator::selectNodeList" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "XalanXPathEvaluator") and
    memberFunc.getName() = "selectNodeList" and
    qn = "XalanXPathEvaluator::selectNodeList"
  ) or
  target.getQualifiedName().matches("XalanXPathEvaluator%::selectSingleNode%") and qn = "XalanXPathEvaluator::selectSingleNode" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "XalanXPathEvaluator") and
    memberFunc.getName() = "selectSingleNode" and
    qn = "XalanXPathEvaluator::selectSingleNode"
  ) or
  target.getQualifiedName().matches("xalanc%::XPathEvaluator%::evaluate%") and qn = "xalanc::XPathEvaluator::evaluate" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("xalanc", "XPathEvaluator") and
    memberFunc.getName() = "evaluate" and
    qn = "xalanc::XPathEvaluator::evaluate"
  ) or
  target.getQualifiedName().matches("xalanc%::XPathEvaluator%::selectNodeList%") and qn = "xalanc::XPathEvaluator::selectNodeList" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("xalanc", "XPathEvaluator") and
    memberFunc.getName() = "selectNodeList" and
    qn = "xalanc::XPathEvaluator::selectNodeList"
  ) or
  target.getQualifiedName().matches("xalanc%::XPathEvaluator%::selectSingleNode%") and qn = "xalanc::XPathEvaluator::selectSingleNode" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("xalanc", "XPathEvaluator") and
    memberFunc.getName() = "selectSingleNode" and
    qn = "xalanc::XPathEvaluator::selectSingleNode"
  ) or
  target.getQualifiedName().matches("QXmlQuery%::setQuery%") and qn = "QXmlQuery::setQuery" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QXmlQuery") and
    memberFunc.getName() = "setQuery" and
    qn = "QXmlQuery::setQuery"
  ) or
  target.getQualifiedName().matches("QXmlQuery%::evaluateTo%") and qn = "QXmlQuery::evaluateTo" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QXmlQuery") and
    memberFunc.getName() = "evaluateTo" and
    qn = "QXmlQuery::evaluateTo"
  ) or
  target.getQualifiedName().matches("QXmlQuery%::evaluateTo(QString*)%") and qn = "QXmlQuery::evaluateTo(QString*)" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QXmlQuery") and
    memberFunc.getName() = "evaluateTo(QString*)" and
    qn = "QXmlQuery::evaluateTo(QString*)"
  ) or
  target.getQualifiedName().matches("QXmlQuery%::evaluateTo(QIODevice*)%") and qn = "QXmlQuery::evaluateTo(QIODevice*)" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QXmlQuery") and
    memberFunc.getName() = "evaluateTo(QIODevice*)" and
    qn = "QXmlQuery::evaluateTo(QIODevice*)"
  ) or
  target.getQualifiedName().matches("QXmlQuery%::evaluateTo(QStringList*)%") and qn = "QXmlQuery::evaluateTo(QStringList*)" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QXmlQuery") and
    memberFunc.getName() = "evaluateTo(QStringList*)" and
    qn = "QXmlQuery::evaluateTo(QStringList*)"
  ) or
  target.getQualifiedName().matches("QXmlQuery%::evaluateTo(QAbstractXmlReceiver*)%") and qn = "QXmlQuery::evaluateTo(QAbstractXmlReceiver*)" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QXmlQuery") and
    memberFunc.getName() = "evaluateTo(QAbstractXmlReceiver*)" and
    qn = "QXmlQuery::evaluateTo(QAbstractXmlReceiver*)"
  ) or
  target.getQualifiedName().matches("Poco%::XML%::Node%::selectNode%") and qn = "Poco::XML::Node::selectNode" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Poco::XML", "Node") and
    memberFunc.getName() = "selectNode" and
    qn = "Poco::XML::Node::selectNode"
  ) or
  target.getQualifiedName().matches("Poco%::XML%::Node%::selectNodes%") and qn = "Poco::XML::Node::selectNodes" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Poco::XML", "Node") and
    memberFunc.getName() = "selectNodes" and
    qn = "Poco::XML::Node::selectNodes"
  ) or
  target.getQualifiedName().matches("IXMLDOMDocument%::selectNodes%") and qn = "IXMLDOMDocument::selectNodes" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "IXMLDOMDocument") and
    memberFunc.getName() = "selectNodes" and
    qn = "IXMLDOMDocument::selectNodes"
  ) or
  target.getQualifiedName().matches("IXMLDOMDocument%::selectSingleNode%") and qn = "IXMLDOMDocument::selectSingleNode" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "IXMLDOMDocument") and
    memberFunc.getName() = "selectSingleNode" and
    qn = "IXMLDOMDocument::selectSingleNode"
  ) or
  target.getQualifiedName().matches("IXMLDOMNode%::selectNodes%") and qn = "IXMLDOMNode::selectNodes" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "IXMLDOMNode") and
    memberFunc.getName() = "selectNodes" and
    qn = "IXMLDOMNode::selectNodes"
  ) or
  target.getQualifiedName().matches("IXMLDOMNode%::selectSingleNode%") and qn = "IXMLDOMNode::selectSingleNode" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "IXMLDOMNode") and
    memberFunc.getName() = "selectSingleNode" and
    qn = "IXMLDOMNode::selectSingleNode"
  ) or
  target.getQualifiedName().matches("TinyXPath%::evaluateNumber%") and qn = "TinyXPath::evaluateNumber" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "TinyXPath") and
    memberFunc.getName() = "evaluateNumber" and
    qn = "TinyXPath::evaluateNumber"
  ) or
  target.getQualifiedName().matches("TinyXPath%::evaluateString%") and qn = "TinyXPath::evaluateString" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "TinyXPath") and
    memberFunc.getName() = "evaluateString" and
    qn = "TinyXPath::evaluateString"
  ) or
  target.getQualifiedName().matches("TinyXPath%::evaluateBoolean%") and qn = "TinyXPath::evaluateBoolean" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "TinyXPath") and
    memberFunc.getName() = "evaluateBoolean" and
    qn = "TinyXPath::evaluateBoolean"
  ) or
  target.getQualifiedName().matches("TinyXPath%::evaluateNodeSet%") and qn = "TinyXPath::evaluateNodeSet" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "TinyXPath") and
    memberFunc.getName() = "evaluateNodeSet" and
    qn = "TinyXPath::evaluateNodeSet"
  )
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
