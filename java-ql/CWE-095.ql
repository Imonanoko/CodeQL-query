// Auto-generated; CWE-095; number of APIs 112
import java

predicate isTargetApi(Callable target, string qn) {
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("javax.script", "ScriptEngineManager") and
    qn = "javax.script.ScriptEngineManager.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.script", "ScriptEngineManager") and
    m.getName() = "getEngineByName" and
    qn = "javax.script.ScriptEngineManager.getEngineByName"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.script", "ScriptEngineManager") and
    m.getName() = "getEngineByExtension" and
    qn = "javax.script.ScriptEngineManager.getEngineByExtension"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.script", "ScriptEngineManager") and
    m.getName() = "getEngineByMimeType" and
    qn = "javax.script.ScriptEngineManager.getEngineByMimeType"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.script", "ScriptEngineManager") and
    m.getName() = "getEngineFactories" and
    qn = "javax.script.ScriptEngineManager.getEngineFactories"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.script", "ScriptEngineFactory") and
    m.getName() = "getScriptEngine" and
    qn = "javax.script.ScriptEngineFactory.getScriptEngine"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.script", "ScriptEngine") and
    m.getName() = "eval" and
    qn = "javax.script.ScriptEngine.eval"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.script", "Compilable") and
    m.getName() = "compile" and
    qn = "javax.script.Compilable.compile"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.script", "CompiledScript") and
    m.getName() = "eval" and
    qn = "javax.script.CompiledScript.eval"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.script", "Invocable") and
    m.getName() = "invokeFunction" and
    qn = "javax.script.Invocable.invokeFunction"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.script", "Invocable") and
    m.getName() = "invokeMethod" and
    qn = "javax.script.Invocable.invokeMethod"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.script", "ScriptEngine") and
    m.getName() = "put" and
    qn = "javax.script.ScriptEngine.put"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.script", "ScriptEngine") and
    m.getName() = "setBindings" and
    qn = "javax.script.ScriptEngine.setBindings"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.script", "Bindings") and
    m.getName() = "put" and
    qn = "javax.script.Bindings.put"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.el", "ExpressionFactory") and
    m.getName() = "newInstance" and
    qn = "javax.el.ExpressionFactory.newInstance"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.el", "ExpressionFactory") and
    m.getName() = "createValueExpression" and
    qn = "javax.el.ExpressionFactory.createValueExpression"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.el", "ExpressionFactory") and
    m.getName() = "createMethodExpression" and
    qn = "javax.el.ExpressionFactory.createMethodExpression"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.el", "ValueExpression") and
    m.getName() = "getValue" and
    qn = "javax.el.ValueExpression.getValue"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.el", "ValueExpression") and
    m.getName() = "setValue" and
    qn = "javax.el.ValueExpression.setValue"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.el", "MethodExpression") and
    m.getName() = "invoke" and
    qn = "javax.el.MethodExpression.invoke"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("javax.el", "ELProcessor") and
    qn = "javax.el.ELProcessor.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.el", "ELProcessor") and
    m.getName() = "eval" and
    qn = "javax.el.ELProcessor.eval"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.el", "ELProcessor") and
    m.getName() = "getValue" and
    qn = "javax.el.ELProcessor.getValue"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.el", "ELProcessor") and
    m.getName() = "setValue" and
    qn = "javax.el.ELProcessor.setValue"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.el", "ELProcessor") and
    m.getName() = "defineBean" and
    qn = "javax.el.ELProcessor.defineBean"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.el", "ELProcessor") and
    m.getName() = "defineFunction" and
    qn = "javax.el.ELProcessor.defineFunction"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.el", "ExpressionFactory") and
    m.getName() = "newInstance" and
    qn = "jakarta.el.ExpressionFactory.newInstance"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.el", "ExpressionFactory") and
    m.getName() = "createValueExpression" and
    qn = "jakarta.el.ExpressionFactory.createValueExpression"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.el", "ExpressionFactory") and
    m.getName() = "createMethodExpression" and
    qn = "jakarta.el.ExpressionFactory.createMethodExpression"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.el", "ValueExpression") and
    m.getName() = "getValue" and
    qn = "jakarta.el.ValueExpression.getValue"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.el", "ValueExpression") and
    m.getName() = "setValue" and
    qn = "jakarta.el.ValueExpression.setValue"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.el", "MethodExpression") and
    m.getName() = "invoke" and
    qn = "jakarta.el.MethodExpression.invoke"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("jakarta.el", "ELProcessor") and
    qn = "jakarta.el.ELProcessor.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.el", "ELProcessor") and
    m.getName() = "eval" and
    qn = "jakarta.el.ELProcessor.eval"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.el", "ELProcessor") and
    m.getName() = "getValue" and
    qn = "jakarta.el.ELProcessor.getValue"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.el", "ELProcessor") and
    m.getName() = "setValue" and
    qn = "jakarta.el.ELProcessor.setValue"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.el", "ELProcessor") and
    m.getName() = "defineBean" and
    qn = "jakarta.el.ELProcessor.defineBean"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.el", "ELProcessor") and
    m.getName() = "defineFunction" and
    qn = "jakarta.el.ELProcessor.defineFunction"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.expression", "ExpressionParser") and
    m.getName() = "parseExpression" and
    qn = "org.springframework.expression.ExpressionParser.parseExpression"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.expression", "Expression") and
    m.getName() = "getValue" and
    qn = "org.springframework.expression.Expression.getValue"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.expression", "Expression") and
    m.getName() = "getValueType" and
    qn = "org.springframework.expression.Expression.getValueType"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.expression", "Expression") and
    m.getName() = "setValue" and
    qn = "org.springframework.expression.Expression.setValue"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.springframework.expression.spel.standard", "SpelExpressionParser") and
    qn = "org.springframework.expression.spel.standard.SpelExpressionParser.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.springframework.expression.common", "TemplateParserContext") and
    qn = "org.springframework.expression.common.TemplateParserContext.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.springframework.expression.spel.support", "StandardEvaluationContext") and
    qn = "org.springframework.expression.spel.support.StandardEvaluationContext.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.expression.spel.support", "StandardEvaluationContext") and
    m.getName() = "setVariable" and
    qn = "org.springframework.expression.spel.support.StandardEvaluationContext.setVariable"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.expression.spel.support", "StandardEvaluationContext") and
    m.getName() = "registerFunction" and
    qn = "org.springframework.expression.spel.support.StandardEvaluationContext.registerFunction"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("ognl", "Ognl") and
    m.getName() = "getValue" and
    qn = "ognl.Ognl.getValue"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("ognl", "Ognl") and
    m.getName() = "setValue" and
    qn = "ognl.Ognl.setValue"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("ognl", "Ognl") and
    m.getName() = "parseExpression" and
    qn = "ognl.Ognl.parseExpression"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("ognl", "OgnlContext") and
    qn = "ognl.OgnlContext.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.opensymphony.xwork2.util", "ValueStack") and
    m.getName() = "findValue" and
    qn = "com.opensymphony.xwork2.util.ValueStack.findValue"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.opensymphony.xwork2.util", "ValueStack") and
    m.getName() = "setValue" and
    qn = "com.opensymphony.xwork2.util.ValueStack.setValue"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.mvel2", "MVEL") and
    m.getName() = "eval" and
    qn = "org.mvel2.MVEL.eval"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.mvel2", "MVEL") and
    m.getName() = "evalToString" and
    qn = "org.mvel2.MVEL.evalToString"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.mvel2", "MVEL") and
    m.getName() = "evalToBoolean" and
    qn = "org.mvel2.MVEL.evalToBoolean"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.mvel2", "MVEL") and
    m.getName() = "evalToInteger" and
    qn = "org.mvel2.MVEL.evalToInteger"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.mvel2", "MVEL") and
    m.getName() = "compileExpression" and
    qn = "org.mvel2.MVEL.compileExpression"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.mvel2", "MVEL") and
    m.getName() = "executeExpression" and
    qn = "org.mvel2.MVEL.executeExpression"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.mvel2", "ParserContext") and
    qn = "org.mvel2.ParserContext.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.apache.commons.jexl3", "JexlBuilder") and
    qn = "org.apache.commons.jexl3.JexlBuilder.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.jexl3", "JexlBuilder") and
    m.getName() = "create" and
    qn = "org.apache.commons.jexl3.JexlBuilder.create"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.jexl3", "JexlEngine") and
    m.getName() = "createExpression" and
    qn = "org.apache.commons.jexl3.JexlEngine.createExpression"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.jexl3", "JexlEngine") and
    m.getName() = "createScript" and
    qn = "org.apache.commons.jexl3.JexlEngine.createScript"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.jexl3", "JexlExpression") and
    m.getName() = "evaluate" and
    qn = "org.apache.commons.jexl3.JexlExpression.evaluate"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.jexl3", "JexlScript") and
    m.getName() = "execute" and
    qn = "org.apache.commons.jexl3.JexlScript.execute"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.apache.commons.jexl3", "MapContext") and
    qn = "org.apache.commons.jexl3.MapContext.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.jexl3", "MapContext") and
    m.getName() = "set" and
    qn = "org.apache.commons.jexl3.MapContext.set"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("groovy.lang", "GroovyShell") and
    qn = "groovy.lang.GroovyShell.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("groovy.lang", "GroovyShell") and
    m.getName() = "evaluate" and
    qn = "groovy.lang.GroovyShell.evaluate"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("groovy.lang", "GroovyShell") and
    m.getName() = "parse" and
    qn = "groovy.lang.GroovyShell.parse"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("groovy.lang", "GroovyShell") and
    m.getName() = "run" and
    qn = "groovy.lang.GroovyShell.run"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("groovy.util", "Eval") and
    m.getName() = "me" and
    qn = "groovy.util.Eval.me"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("groovy.util", "Eval") and
    m.getName() = "x" and
    qn = "groovy.util.Eval.x"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("groovy.util", "Eval") and
    m.getName() = "xy" and
    qn = "groovy.util.Eval.xy"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("groovy.util", "Eval") and
    m.getName() = "xyz" and
    qn = "groovy.util.Eval.xyz"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("groovy.lang", "GroovyClassLoader") and
    qn = "groovy.lang.GroovyClassLoader.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("groovy.lang", "GroovyClassLoader") and
    m.getName() = "parseClass" and
    qn = "groovy.lang.GroovyClassLoader.parseClass"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.codehaus.groovy.control", "CompilerConfiguration") and
    qn = "org.codehaus.groovy.control.CompilerConfiguration.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.codehaus.groovy.jsr223", "GroovyScriptEngineImpl") and
    m.getName() = "eval" and
    qn = "org.codehaus.groovy.jsr223.GroovyScriptEngineImpl.eval"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("bsh", "Interpreter") and
    qn = "bsh.Interpreter.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("bsh", "Interpreter") and
    m.getName() = "eval" and
    qn = "bsh.Interpreter.eval"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("bsh", "Interpreter") and
    m.getName() = "set" and
    qn = "bsh.Interpreter.set"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("bsh", "Interpreter") and
    m.getName() = "source" and
    qn = "bsh.Interpreter.source"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.codehaus.janino", "ExpressionEvaluator") and
    qn = "org.codehaus.janino.ExpressionEvaluator.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.codehaus.janino", "ExpressionEvaluator") and
    m.getName() = "cook" and
    qn = "org.codehaus.janino.ExpressionEvaluator.cook"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.codehaus.janino", "ExpressionEvaluator") and
    m.getName() = "evaluate" and
    qn = "org.codehaus.janino.ExpressionEvaluator.evaluate"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.codehaus.janino", "ScriptEvaluator") and
    qn = "org.codehaus.janino.ScriptEvaluator.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.codehaus.janino", "ScriptEvaluator") and
    m.getName() = "cook" and
    qn = "org.codehaus.janino.ScriptEvaluator.cook"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.codehaus.janino", "ScriptEvaluator") and
    m.getName() = "evaluate" and
    qn = "org.codehaus.janino.ScriptEvaluator.evaluate"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.codehaus.janino", "ClassBodyEvaluator") and
    qn = "org.codehaus.janino.ClassBodyEvaluator.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.codehaus.janino", "ClassBodyEvaluator") and
    m.getName() = "cook" and
    qn = "org.codehaus.janino.ClassBodyEvaluator.cook"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.codehaus.janino", "SimpleCompiler") and
    qn = "org.codehaus.janino.SimpleCompiler.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.codehaus.janino", "SimpleCompiler") and
    m.getName() = "cook" and
    qn = "org.codehaus.janino.SimpleCompiler.cook"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.codehaus.janino", "SimpleCompiler") and
    m.getName() = "getClassLoader" and
    qn = "org.codehaus.janino.SimpleCompiler.getClassLoader"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.tools", "ToolProvider") and
    m.getName() = "getSystemJavaCompiler" and
    qn = "javax.tools.ToolProvider.getSystemJavaCompiler"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.tools", "JavaCompiler") and
    m.getName() = "run" and
    qn = "javax.tools.JavaCompiler.run"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.tools", "JavaCompiler") and
    m.getName() = "getTask" and
    qn = "javax.tools.JavaCompiler.getTask"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.tools", "JavaFileManager") and
    m.getName() = "getJavaFileObjects" and
    qn = "javax.tools.JavaFileManager.getJavaFileObjects"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.tools", "StandardJavaFileManager") and
    m.getName() = "getJavaFileObjects" and
    qn = "javax.tools.StandardJavaFileManager.getJavaFileObjects"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("javax.tools", "JavaFileObject") and
    m.getName() = "getCharContent" and
    qn = "javax.tools.JavaFileObject.getCharContent"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.mozilla.javascript", "Context") and
    m.getName() = "enter" and
    qn = "org.mozilla.javascript.Context.enter"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.mozilla.javascript", "Context") and
    m.getName() = "evaluateString" and
    qn = "org.mozilla.javascript.Context.evaluateString"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.mozilla.javascript", "Context") and
    m.getName() = "evaluateReader" and
    qn = "org.mozilla.javascript.Context.evaluateReader"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.mozilla.javascript", "Context") and
    m.getName() = "compileString" and
    qn = "org.mozilla.javascript.Context.compileString"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.mozilla.javascript", "Script") and
    m.getName() = "exec" and
    qn = "org.mozilla.javascript.Script.exec"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.mozilla.javascript", "Function") and
    m.getName() = "call" and
    qn = "org.mozilla.javascript.Function.call"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("jdk.nashorn.api.scripting", "NashornScriptEngineFactory") and
    qn = "jdk.nashorn.api.scripting.NashornScriptEngineFactory.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jdk.nashorn.api.scripting", "NashornScriptEngineFactory") and
    m.getName() = "getScriptEngine" and
    qn = "jdk.nashorn.api.scripting.NashornScriptEngineFactory.getScriptEngine"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jdk.nashorn.api.scripting", "NashornScriptEngine") and
    m.getName() = "eval" and
    qn = "jdk.nashorn.api.scripting.NashornScriptEngine.eval"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jdk.nashorn.api.scripting", "NashornScriptEngine") and
    m.getName() = "invokeFunction" and
    qn = "jdk.nashorn.api.scripting.NashornScriptEngine.invokeFunction"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jdk.nashorn.api.scripting", "NashornScriptEngine") and
    m.getName() = "invokeMethod" and
    qn = "jdk.nashorn.api.scripting.NashornScriptEngine.invokeMethod"
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
