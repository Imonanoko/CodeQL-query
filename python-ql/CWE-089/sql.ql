import python

from Expr e, string t, int idx, int off
where
  (
    (e instanceof StringLiteral and t = e.(StringLiteral).getText())
    or
    (e instanceof Fstring and t = e.(Fstring).toString())
  )
  and exists(string s |
    s = t.regexpFind("(?i)\\b(SELECT|INSERT|UPDATE|DELETE|REPLACE|WITH|WHERE|FROM|VALUES|INTO|JOIN|GROUP\\s+BY|ORDER\\s+BY|LIMIT|CREATE|ALTER|DROP)\\b",idx,off)
  )
select e, "Contains SQL-like text", t,e.getLocation()