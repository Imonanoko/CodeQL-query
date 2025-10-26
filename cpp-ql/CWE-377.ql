// Auto-generated; CWE-377; number of APIs 46
import cpp

predicate isTargetApi(Function target, string qn) {
  target.getQualifiedName().matches("tmpnam%") and qn = "tmpnam" or
  target.getQualifiedName().matches("tmpnam_r%") and qn = "tmpnam_r" or
  target.getQualifiedName().matches("tempnam%") and qn = "tempnam" or
  target.getQualifiedName().matches("mktemp%") and qn = "mktemp" or
  target.getQualifiedName().matches("mkdtemp%") and qn = "mkdtemp" or
  target.getQualifiedName().matches("mkstemp%") and qn = "mkstemp" or
  target.getQualifiedName().matches("tmpfile%") and qn = "tmpfile" or
  target.getQualifiedName().matches("tmpfile64%") and qn = "tmpfile64" or
  target.getQualifiedName().matches("fopen%") and qn = "fopen" or
  target.getQualifiedName().matches("freopen%") and qn = "freopen" or
  target.getQualifiedName().matches("open%") and qn = "open" or
  target.getQualifiedName().matches("creat%") and qn = "creat" or
  target.getQualifiedName().matches("openat%") and qn = "openat" or
  target.getQualifiedName().matches("std%::tmpnam%") and qn = "std::tmpnam" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "std") and
    memberFunc.getName() = "tmpnam" and
    qn = "std::tmpnam"
  ) or
  target.getQualifiedName().matches("std%::tmpfile%") and qn = "std::tmpfile" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "std") and
    memberFunc.getName() = "tmpfile" and
    qn = "std::tmpfile"
  ) or
  target.getQualifiedName().matches("std%::fopen%") and qn = "std::fopen" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "std") and
    memberFunc.getName() = "fopen" and
    qn = "std::fopen"
  ) or
  target.getQualifiedName().matches("std%::freopen%") and qn = "std::freopen" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "std") and
    memberFunc.getName() = "freopen" and
    qn = "std::freopen"
  ) or
  target.getQualifiedName().matches("std%::ifstream%::open%") and qn = "std::ifstream::open" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "ifstream") and
    memberFunc.getName() = "open" and
    qn = "std::ifstream::open"
  ) or
  target.getQualifiedName().matches("std%::ofstream%::open%") and qn = "std::ofstream::open" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "ofstream") and
    memberFunc.getName() = "open" and
    qn = "std::ofstream::open"
  ) or
  target.getQualifiedName().matches("std%::fstream%::open%") and qn = "std::fstream::open" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "fstream") and
    memberFunc.getName() = "open" and
    qn = "std::fstream::open"
  ) or
  target.getQualifiedName().matches("std%::filesystem%::temp_directory_path%") and qn = "std::filesystem::temp_directory_path" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "filesystem") and
    memberFunc.getName() = "temp_directory_path" and
    qn = "std::filesystem::temp_directory_path"
  ) or
  target.getQualifiedName().matches("GetTempFileNameA%") and qn = "GetTempFileNameA" or
  target.getQualifiedName().matches("GetTempFileNameW%") and qn = "GetTempFileNameW" or
  target.getQualifiedName().matches("GetTempPathA%") and qn = "GetTempPathA" or
  target.getQualifiedName().matches("GetTempPathW%") and qn = "GetTempPathW" or
  target.getQualifiedName().matches("_tempnam%") and qn = "_tempnam" or
  target.getQualifiedName().matches("_wtempnam%") and qn = "_wtempnam" or
  target.getQualifiedName().matches("_mktemp%") and qn = "_mktemp" or
  target.getQualifiedName().matches("_wmktemp%") and qn = "_wmktemp" or
  target.getQualifiedName().matches("_mktemp_s%") and qn = "_mktemp_s" or
  target.getQualifiedName().matches("_wmktemp_s%") and qn = "_wmktemp_s" or
  target.getQualifiedName().matches("_tmpnam%") and qn = "_tmpnam" or
  target.getQualifiedName().matches("_wtmpnam%") and qn = "_wtmpnam" or
  target.getQualifiedName().matches("CreateFileA%") and qn = "CreateFileA" or
  target.getQualifiedName().matches("CreateFileW%") and qn = "CreateFileW" or
  target.getQualifiedName().matches("QDir%::tempPath%") and qn = "QDir::tempPath" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QDir") and
    memberFunc.getName() = "tempPath" and
    qn = "QDir::tempPath"
  ) or
  target.getQualifiedName().matches("QTemporaryFile%::QTemporaryFile%") and qn = "QTemporaryFile::QTemporaryFile" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QTemporaryFile") and
    memberFunc.getName() = "QTemporaryFile" and
    qn = "QTemporaryFile::QTemporaryFile"
  ) or
  target.getQualifiedName().matches("QTemporaryFile%::open%") and qn = "QTemporaryFile::open" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QTemporaryFile") and
    memberFunc.getName() = "open" and
    qn = "QTemporaryFile::open"
  ) or
  target.getQualifiedName().matches("boost%::filesystem%::temp_directory_path%") and qn = "boost::filesystem::temp_directory_path" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost", "filesystem") and
    memberFunc.getName() = "temp_directory_path" and
    qn = "boost::filesystem::temp_directory_path"
  ) or
  target.getQualifiedName().matches("g_get_tmp_dir%") and qn = "g_get_tmp_dir" or
  target.getQualifiedName().matches("g_mkstemp%") and qn = "g_mkstemp" or
  target.getQualifiedName().matches("g_mkdtemp%") and qn = "g_mkdtemp" or
  target.getQualifiedName().matches("g_file_open_tmp%") and qn = "g_file_open_tmp" or
  target.getQualifiedName().matches("uv_fs_mkstemp%") and qn = "uv_fs_mkstemp" or
  target.getQualifiedName().matches("apr_temp_dir_get%") and qn = "apr_temp_dir_get" or
  target.getQualifiedName().matches("apr_file_mktemp%") and qn = "apr_file_mktemp"
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
