import cpp

predicate isTargetApi(Function target, string qn) {
  target.getQualifiedName().matches("std::sort%") and qn = target.getQualifiedName() or
  exists(MemberFunction memberFunc |
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "unordered_map") and
    memberFunc.getName() = "begin" and
    qn = memberFunc.getQualifiedName()
  ) or
  exists(MemberFunction memberFunc |
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("MyProject", "DatabaseManager") and

    memberFunc.getName() = "executeQuery" and
    qn = memberFunc.getQualifiedName()
  )
}

from
  FunctionCall call,
  Function targetFunc,
  Function enclosingFunc,
  string qn
where
  targetFunc = call.getTarget() and
  isTargetApi(targetFunc, qn) and
  enclosingFunc = call.getEnclosingFunction()
select call,
    "Path: " + call.getLocation(),
    "Call to " + qn,
    "at line " + call.getLocation().getStartLine(),
    "inside function " + enclosingFunc.getName() + "@" + 
    enclosingFunc.getLocation().getStartLine() + ":" + 
    enclosingFunc.getLocation().getStartColumn()+ "-" +
    enclosingFunc.getBlock().getLocation().getEndLine()+ ":" +
    enclosingFunc.getBlock().getLocation().getEndColumn()