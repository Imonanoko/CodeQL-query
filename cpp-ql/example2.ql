import cpp

predicate isTargetApi(Function target, string qn) {
  target.getQualifiedName().matches("EVP_md5%") and qn = "EVP_md5"
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
"Path: " + call.getLocation().getFile(),
"call function: " + call.getLocation().getStartLine()+":"+call.getLocation().getStartColumn()+
"-"+call.getLocation().getEndLine()+":"+call.getLocation().getEndColumn(),
"call in function: " + enclosingFunc.getName() + "@" +
enclosingFunc.getLocation().getStartLine() + "-" +
enclosingFunc.getBlock().getLocation().getEndLine(),
"callee=" + qn,
"basic block: " + call.getBasicBlock().getStart().getLocation().getStartLine() + ":" +call.getBasicBlock().getStart().getLocation().getStartColumn()+
"-"+ call.getBasicBlock().getEnd().getLocation().getEndLine() + ":" + call.getBasicBlock().getEnd().getLocation().getEndColumn()