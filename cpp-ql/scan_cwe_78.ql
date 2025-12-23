/**
 * @name Our function parameter used in OS command
 * @description Treat parameters of functions implemented in our code (excluding third-party paths) as untrusted sources,
 *              and report flows into shell commands (e.g., system()).
 * @kind path-problem
 * @problem.severity warning
 * @precision medium
 * @id cpp/our-param-to-os-command
 * @tags security
 *       external/cwe/cwe-078
 */

import cpp
import semmle.code.cpp.security.CommandExecution
import semmle.code.cpp.security.Security
import semmle.code.cpp.ir.dataflow.DataFlow
import semmle.code.cpp.ir.dataflow.TaintTracking

/** Tune these patterns to match your repository layout. */
predicate isThirdPartyFile(File f) {
  exists(string rp |
    rp = f.getRelativePath() and
    (
      rp.regexpMatch("(^|.*/)(third_party|thirdparty|3rd_party|3rd|vendor|external|extern|deps|dep|submodules)/.*") or
      rp.regexpMatch("(^|.*/)(build|out|dist|_build|cmake-build[^/]*)/.*") or
      rp.regexpMatch("(^|.*/)(\\.conan|\\.vcpkg|vcpkg_installed|_deps)/.*")
    )
  )
}

/**
 * "Our function" = has a definition, and the defining file is under the source root and not third-party.
 */
predicate isOurFunction(Function f) {
  f.hasDefinition() and
  exists(FunctionDeclarationEntry def |
    def = f.getDefinition() and
    def.getFile().getRelativePath() != "" and
    not isThirdPartyFile(def.getFile())
  )
}

/** Heuristic: only treat string-like parameters as potentially command-controlling. */
predicate isStringLikeParam(Parameter p) {
  // C-strings (char*, const char*, char[])
  p.getType().toString().matches("%char%*%") or
  p.getType().toString().matches("%char%[%") or
  // std::string / basic_string / string_view (rough; tune if needed)
  p.getType().toString().matches("%std::string%") or
  p.getType().toString().matches("%std::basic_string%") or
  p.getType().toString().matches("%string_view%")
}

predicate isSinkImpl(DataFlow::Node sink, Expr command, string callChain) {
  command = sink.asIndirectArgument() and
  shellCommand(command, callChain)
}

predicate isBarrierImpl(DataFlow::Node node) {
  node.asExpr().getUnspecifiedType() instanceof IntegralType
  or node.asExpr().getUnspecifiedType() instanceof FloatingPointType
}

module ParamToShellConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(Parameter p |
      source = DataFlow::parameterNode(p) and
      isOurFunction(p.getFunction()) and
      isStringLikeParam(p)
    )
  }

  predicate isSink(DataFlow::Node sink) {
    isSinkImpl(sink, _, _)
  }

  predicate isBarrier(DataFlow::Node node) { isBarrierImpl(node) }

  predicate isBarrierOut(DataFlow::Node node) {
    isSink(node) // reduce duplicates along wrapper chains
  }
}

module ParamToShell = TaintTracking::Global<ParamToShellConfig>;
import ParamToShell::PathGraph

from
  ParamToShell::PathNode sourceNode,
  ParamToShell::PathNode sinkNode,
  Parameter p,
  Expr command,
  string callChain
where
  ParamToShell::flowPath(sourceNode, sinkNode) and
  sourceNode.getNode() = DataFlow::parameterNode(p) and
  isSinkImpl(sinkNode.getNode(), command, callChain)
select
  command,
  sourceNode,
  sinkNode,
  "This OS command argument is derived from parameter $@ of function $@ and is passed to " + callChain + ".",
  p, p.getName(),
  p.getFunction(), p.getFunction().getName()
