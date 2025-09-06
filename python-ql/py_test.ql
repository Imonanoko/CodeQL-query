/**
 * @name Python: find open() calls and their enclosing function
 * @kind select
 */
import python

predicate dotted(Expr e, string s) {
  exists(Name n | e = n and s = n.getId()) or
  exists(Attribute a, string base |
    e = a and dotted(a.getObject(), base) and s = base + "." + a.getAttr()
  )
}
predicate isListMethod(string m) {
  m = "chmod" or m = "open" or m = "readlink" or m = "symlink" or
  m = "link" or m = "remove" or m = "unlink" or m = "rename" or
  m = "join" or m = "normpath" or m = "realpath"
}
from Call c, Function f, Attribute attr, string base
where
  c.getFunc() = attr and
  isListMethod(attr.getAttr()) and
  f.contains(c) and 
  dotted(attr.getObject(), base) and base = "os.path"
select f.getName(), f.getLocation(),f.getLastStatement().getLocation(),"callee=" + base + ".join"
