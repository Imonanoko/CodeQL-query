import cpp

predicate isTargetApi(Function target, string qn) {
  target.getQualifiedName().matches("std::basic_fstream%::open%") and qn = "normal"
  or
  exists(MemberFunction memberFunc |
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "fstream") and
    memberFunc.getName() = "open" and
    qn = "class"
  )
}

predicate isInSourceCode(FunctionCall call) { call.getLocation().getFile().getRelativePath() != "" }

from FunctionCall call, Function targetFunc, Function enclosingFunc, string qn
where
  targetFunc = call.getTarget() and
  isTargetApi(targetFunc, qn) and
  enclosingFunc = call.getEnclosingFunction() and
  isInSourceCode(call)
select 
// targetFunc.getQualifiedName(), targetFunc, enclosingFunc, call
"Path: " + call.getLocation(),
"Call to " + qn,
"at line " + call.getLocation().getStartLine(),
"inside function " + enclosingFunc.getName() + "@" +
enclosingFunc.getLocation().getStartLine() + ":" +
enclosingFunc.getLocation().getStartColumn()+ "-" +
enclosingFunc.getBlock().getLocation().getEndLine()+ ":" +
enclosingFunc.getBlock().getLocation().getEndColumn()
