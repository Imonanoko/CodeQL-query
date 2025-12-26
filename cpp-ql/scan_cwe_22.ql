/**
 * @name Our function parameter used in path expression
 * @description Treat parameters of functions implemented in our code (excluding third-party paths) as untrusted sources,
 *              and report flows into file access functions (e.g., fopen/open/fstream/CreateFile).
 * @kind path-problem
 * @problem.severity warning
 * @precision medium
 * @id cpp/our-param-to-path-expression
 * @tags security
 *       external/cwe/cwe-022
 */

import cpp
import semmle.code.cpp.security.FunctionWithWrappers
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

/** Heuristic: only treat string-like parameters as potentially path-controlling. */
predicate isStringLikeParam(Parameter p) {
  // C-strings (char*, const char*, wchar_t*, etc.) - rough string matching on type spelling
  p.getType().toString().matches("%char%*%") or
  p.getType().toString().matches("%wchar_t%*%") or
  p.getType().toString().matches("%char%[%") or
  p.getType().toString().matches("%wchar_t%[%") or
  // std::string / basic_string / string_view (rough; tune if needed)
  p.getType().toString().matches("%std::string%") or
  p.getType().toString().matches("%std::basic_string%") or
  p.getType().toString().matches("%string_view%")
}

/**
 * A function for opening a file.
 * (Copied from the original CWE-022 query: supports C APIs, Windows CreateFile*, and std::fstream/filebuf.)
 */
class FileFunction extends FunctionWithWrappers {
  FileFunction() {
    exists(string nme | this.hasGlobalName(nme) |
      nme = ["fopen", "_fopen", "_wfopen", "open", "_open", "_wopen"]
      or
      // create file function on windows
      nme.matches("CreateFile%")
    )
    or
    this.hasQualifiedName("std", "fopen")
    or
    // on any of the fstream classes, or filebuf
    exists(string nme | this.getDeclaringType().hasQualifiedName("std", nme) |
      nme = ["basic_fstream", "basic_ifstream", "basic_ofstream", "basic_filebuf"]
    ) and
    // we look for either the open method or the constructor
    (this.getName() = "open" or this instanceof Constructor)
  }

  // conveniently, all of these functions take the path as the first parameter!
  override predicate interestingArg(int arg) { arg = 0 }
}

predicate isSinkImpl(DataFlow::Node sink, Expr pathArg, string callChain) {
  pathArg = sink.asIndirectArgument() and
  exists(FileFunction fileFunction |
    fileFunction.outermostWrapperFunctionCall(pathArg, callChain)
  )
}

predicate isBarrierImpl(DataFlow::Node node) {
  // Similar to your CWE-078 template: cut off numeric-only flows early
  node.asExpr().getUnspecifiedType() instanceof IntegralType
  or node.asExpr().getUnspecifiedType() instanceof FloatingPointType
}

module ParamToPathConfig implements DataFlow::ConfigSig {
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
    // make sinks barriers so that we only report the closest instance
    isSink(node)
  }

  Location getASelectedSinkLocation(DataFlow::Node sink) {
    result = sink.asIndirectArgument().getLocation()
  }
}

module ParamToPath = TaintTracking::Global<ParamToPathConfig>;
import ParamToPath::PathGraph

from
  ParamToPath::PathNode sourceNode,
  ParamToPath::PathNode sinkNode,
  Parameter p,
  Expr pathArg,
  string callChain
where
  ParamToPath::flowPath(sourceNode, sinkNode) and
  sourceNode.getNode() = DataFlow::parameterNode(p) and
  isSinkImpl(sinkNode.getNode(), pathArg, callChain)
select
  pathArg,
  sourceNode,
  sinkNode,
  "This argument to a file access function is derived from parameter $@ of function $@ and then passed to " + callChain + ".",
  p, p.getName(),
  p.getFunction(), p.getFunction().getName()
