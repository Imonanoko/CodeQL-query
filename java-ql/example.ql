import java
predicate isTargetApi(Callable target, string qn) {
  (
    target.getDeclaringType().hasQualifiedName("java.security", "MessageDigest") and
    target.getName() = "getInstance" and
    qn = "MessageDigest_MD5"
  )
  or
  exists(Constructor constructor |
    constructor = target and
    constructor.getDeclaringType().hasQualifiedName("java.io", "FileInputStream") and
    qn = "FileInputStream_Open"
  )
}

predicate isInSourceCode(Call call) {
    call.getLocation().getFile().getRelativePath() != "" 
}

from Call call, Callable targetFunc, Callable enclosingFunc, string qn, ControlFlowNode node
where
  targetFunc = call.getCallee() and
  isTargetApi(targetFunc, qn) and
  enclosingFunc = call.getEnclosingCallable() and
  isInSourceCode(call) and
  node.asExpr() = call
select 
  "Path: " + call.getLocation().getFile().getAbsolutePath(),
  "call function: " + call.getLocation().getStartLine() + ":" + call.getLocation().getStartColumn() +
  "-" + call.getLocation().getEndLine() + ":" + call.getLocation().getEndColumn(),
  "call in function: " + enclosingFunc.getName() + "@" +
  enclosingFunc.getLocation().getStartLine() + "-" +
  enclosingFunc.getBody().getLocation().getEndLine(),
  "callee=" + qn,
  "basic block: " + node.getBasicBlock().getLocation().getStartLine() + ":" + 
  node.getBasicBlock().getLocation().getStartColumn() + "-" + 
  node.getBasicBlock().getLocation().getEndLine() + ":" + 
  node.getBasicBlock().getLocation().getEndColumn()