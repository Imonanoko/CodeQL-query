// Auto-generated; CWE-078; number of APIs 130
import cpp

predicate isTargetApi(Function target, string qn) {
  target.getQualifiedName().matches("system%") and qn = "system" or
  target.getQualifiedName().matches("popen%") and qn = "popen" or
  target.getQualifiedName().matches("pclose%") and qn = "pclose" or
  target.getQualifiedName().matches("execl%") and qn = "execl" or
  target.getQualifiedName().matches("execlp%") and qn = "execlp" or
  target.getQualifiedName().matches("execle%") and qn = "execle" or
  target.getQualifiedName().matches("execv%") and qn = "execv" or
  target.getQualifiedName().matches("execvp%") and qn = "execvp" or
  target.getQualifiedName().matches("execvpe%") and qn = "execvpe" or
  target.getQualifiedName().matches("execve%") and qn = "execve" or
  target.getQualifiedName().matches("posix_spawn%") and qn = "posix_spawn" or
  target.getQualifiedName().matches("posix_spawnp%") and qn = "posix_spawnp" or
  target.getQualifiedName().matches("CreateProcessA%") and qn = "CreateProcessA" or
  target.getQualifiedName().matches("CreateProcessW%") and qn = "CreateProcessW" or
  target.getQualifiedName().matches("ShellExecuteA%") and qn = "ShellExecuteA" or
  target.getQualifiedName().matches("ShellExecuteW%") and qn = "ShellExecuteW" or
  target.getQualifiedName().matches("ShellExecuteExA%") and qn = "ShellExecuteExA" or
  target.getQualifiedName().matches("ShellExecuteExW%") and qn = "ShellExecuteExW" or
  target.getQualifiedName().matches("QProcess%") and qn = "QProcess" or
  target.getQualifiedName().matches("QProcess%::start%") and qn = "QProcess::start" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QProcess") and
    memberFunc.getName() = "start" and
    qn = "QProcess::start"
  ) or
  target.getQualifiedName().matches("QProcess%::startDetached%") and qn = "QProcess::startDetached" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QProcess") and
    memberFunc.getName() = "startDetached" and
    qn = "QProcess::startDetached"
  ) or
  target.getQualifiedName().matches("QProcess%::execute%") and qn = "QProcess::execute" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QProcess") and
    memberFunc.getName() = "execute" and
    qn = "QProcess::execute"
  ) or
  target.getQualifiedName().matches("QProcess%::setProgram%") and qn = "QProcess::setProgram" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QProcess") and
    memberFunc.getName() = "setProgram" and
    qn = "QProcess::setProgram"
  ) or
  target.getQualifiedName().matches("QProcess%::setArguments%") and qn = "QProcess::setArguments" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QProcess") and
    memberFunc.getName() = "setArguments" and
    qn = "QProcess::setArguments"
  ) or
  target.getQualifiedName().matches("boost%::process%::system%") and qn = "boost::process::system" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost", "process") and
    memberFunc.getName() = "system" and
    qn = "boost::process::system"
  ) or
  target.getQualifiedName().matches("boost%::process%::child%") and qn = "boost::process::child" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost", "process") and
    memberFunc.getName() = "child" and
    qn = "boost::process::child"
  ) or
  target.getQualifiedName().matches("boost%::process%::spawn%") and qn = "boost::process::spawn" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost", "process") and
    memberFunc.getName() = "spawn" and
    qn = "boost::process::spawn"
  ) or
  target.getQualifiedName().matches("boost%::process%::search_path%") and qn = "boost::process::search_path" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost", "process") and
    memberFunc.getName() = "search_path" and
    qn = "boost::process::search_path"
  ) or
  target.getQualifiedName().matches("Poco%::Process%") and qn = "Poco::Process" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "Poco") and
    memberFunc.getName() = "Process" and
    qn = "Poco::Process"
  ) or
  target.getQualifiedName().matches("Poco%::Process%::launch%") and qn = "Poco::Process::launch" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Poco", "Process") and
    memberFunc.getName() = "launch" and
    qn = "Poco::Process::launch"
  ) or
  target.getQualifiedName().matches("Poco%::Process%::kill%") and qn = "Poco::Process::kill" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Poco", "Process") and
    memberFunc.getName() = "kill" and
    qn = "Poco::Process::kill"
  ) or
  target.getQualifiedName().matches("ACE_OS%::system%") and qn = "ACE_OS::system" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "ACE_OS") and
    memberFunc.getName() = "system" and
    qn = "ACE_OS::system"
  ) or
  target.getQualifiedName().matches("ACE_Process%") and qn = "ACE_Process" or
  target.getQualifiedName().matches("ACE_Process_Manager%") and qn = "ACE_Process_Manager" or
  target.getQualifiedName().matches("std%::system%") and qn = "std::system" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "std") and
    memberFunc.getName() = "system" and
    qn = "std::system"
  ) or
  target.getQualifiedName().matches("std%::popen%") and qn = "std::popen" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "std") and
    memberFunc.getName() = "popen" and
    qn = "std::popen"
  ) or
  target.getQualifiedName().matches("libuv%::process_spawn%") and qn = "libuv::process_spawn" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "libuv") and
    memberFunc.getName() = "process_spawn" and
    qn = "libuv::process_spawn"
  ) or
  target.getQualifiedName().matches("libuv%::process_kill%") and qn = "libuv::process_kill" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "libuv") and
    memberFunc.getName() = "process_kill" and
    qn = "libuv::process_kill"
  ) or
  target.getQualifiedName().matches("apr_proc_create%") and qn = "apr_proc_create" or
  target.getQualifiedName().matches("apr_procattr_cmdtype_set%") and qn = "apr_procattr_cmdtype_set" or
  target.getQualifiedName().matches("apr_procattr_child_in_set%") and qn = "apr_procattr_child_in_set" or
  target.getQualifiedName().matches("apr_procattr_child_out_set%") and qn = "apr_procattr_child_out_set" or
  target.getQualifiedName().matches("apr_procattr_child_err_set%") and qn = "apr_procattr_child_err_set" or
  target.getQualifiedName().matches("apr_procattr_dir_set%") and qn = "apr_procattr_dir_set" or
  target.getQualifiedName().matches("apr_procattr_detach_set%") and qn = "apr_procattr_detach_set" or
  target.getQualifiedName().matches("apr_procattr_limit_set%") and qn = "apr_procattr_limit_set" or
  target.getQualifiedName().matches("apr_procattr_user_set%") and qn = "apr_procattr_user_set" or
  target.getQualifiedName().matches("apr_procattr_group_set%") and qn = "apr_procattr_group_set" or
  target.getQualifiedName().matches("glib%::g_spawn_async%") and qn = "glib::g_spawn_async" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "glib") and
    memberFunc.getName() = "g_spawn_async" and
    qn = "glib::g_spawn_async"
  ) or
  target.getQualifiedName().matches("glib%::g_spawn_sync%") and qn = "glib::g_spawn_sync" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "glib") and
    memberFunc.getName() = "g_spawn_sync" and
    qn = "glib::g_spawn_sync"
  ) or
  target.getQualifiedName().matches("glib%::g_spawn_command_line_async%") and qn = "glib::g_spawn_command_line_async" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "glib") and
    memberFunc.getName() = "g_spawn_command_line_async" and
    qn = "glib::g_spawn_command_line_async"
  ) or
  target.getQualifiedName().matches("glib%::g_spawn_command_line_sync%") and qn = "glib::g_spawn_command_line_sync" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "glib") and
    memberFunc.getName() = "g_spawn_command_line_sync" and
    qn = "glib::g_spawn_command_line_sync"
  ) or
  target.getQualifiedName().matches("WinExec%") and qn = "WinExec" or
  target.getQualifiedName().matches("System%") and qn = "System" or
  target.getQualifiedName().matches("_popen%") and qn = "_popen" or
  target.getQualifiedName().matches("_wpopen%") and qn = "_wpopen" or
  target.getQualifiedName().matches("_pclose%") and qn = "_pclose" or
  target.getQualifiedName().matches("_spawnl%") and qn = "_spawnl" or
  target.getQualifiedName().matches("_spawnlp%") and qn = "_spawnlp" or
  target.getQualifiedName().matches("_spawnv%") and qn = "_spawnv" or
  target.getQualifiedName().matches("_spawnvp%") and qn = "_spawnvp" or
  target.getQualifiedName().matches("_spawnle%") and qn = "_spawnle" or
  target.getQualifiedName().matches("_spawnve%") and qn = "_spawnve" or
  target.getQualifiedName().matches("_wsystem%") and qn = "_wsystem" or
  target.getQualifiedName().matches("os%::system%") and qn = "os::system" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "os") and
    memberFunc.getName() = "system" and
    qn = "os::system"
  ) or
  target.getQualifiedName().matches("os%::execv%") and qn = "os::execv" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "os") and
    memberFunc.getName() = "execv" and
    qn = "os::execv"
  ) or
  target.getQualifiedName().matches("os%::execvp%") and qn = "os::execvp" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "os") and
    memberFunc.getName() = "execvp" and
    qn = "os::execvp"
  ) or
  target.getQualifiedName().matches("os%::popen%") and qn = "os::popen" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "os") and
    memberFunc.getName() = "popen" and
    qn = "os::popen"
  ) or
  target.getQualifiedName().matches("core%::exec%") and qn = "core::exec" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "core") and
    memberFunc.getName() = "exec" and
    qn = "core::exec"
  ) or
  target.getQualifiedName().matches("core%::run_shell_command%") and qn = "core::run_shell_command" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "core") and
    memberFunc.getName() = "run_shell_command" and
    qn = "core::run_shell_command"
  ) or
  target.getQualifiedName().matches("core%::execute%") and qn = "core::execute" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "core") and
    memberFunc.getName() = "execute" and
    qn = "core::execute"
  ) or
  target.getQualifiedName().matches("cpp-httplib%::detail%::run_command%") and qn = "cpp-httplib::detail::run_command" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("cpp-httplib", "detail") and
    memberFunc.getName() = "run_command" and
    qn = "cpp-httplib::detail::run_command"
  ) or
  target.getQualifiedName().matches("cpp-httplib%::detail%::popen_wrapper%") and qn = "cpp-httplib::detail::popen_wrapper" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("cpp-httplib", "detail") and
    memberFunc.getName() = "popen_wrapper" and
    qn = "cpp-httplib::detail::popen_wrapper"
  ) or
  target.getQualifiedName().matches("mongoose%::mg_exec%") and qn = "mongoose::mg_exec" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "mongoose") and
    memberFunc.getName() = "mg_exec" and
    qn = "mongoose::mg_exec"
  ) or
  target.getQualifiedName().matches("mongoose%::mg_system%") and qn = "mongoose::mg_system" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "mongoose") and
    memberFunc.getName() = "mg_system" and
    qn = "mongoose::mg_system"
  ) or
  target.getQualifiedName().matches("crow%::system_exec%") and qn = "crow::system_exec" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "crow") and
    memberFunc.getName() = "system_exec" and
    qn = "crow::system_exec"
  ) or
  target.getQualifiedName().matches("crow%::run_command%") and qn = "crow::run_command" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "crow") and
    memberFunc.getName() = "run_command" and
    qn = "crow::run_command"
  ) or
  target.getQualifiedName().matches("apache%::exec%") and qn = "apache::exec" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "apache") and
    memberFunc.getName() = "exec" and
    qn = "apache::exec"
  ) or
  target.getQualifiedName().matches("nginx_module_exec%") and qn = "nginx_module_exec" or
  target.getQualifiedName().matches("sqlite3_shell_exec%") and qn = "sqlite3_shell_exec" or
  target.getQualifiedName().matches("rocksdb%::SystemCommand%") and qn = "rocksdb::SystemCommand" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "rocksdb") and
    memberFunc.getName() = "SystemCommand" and
    qn = "rocksdb::SystemCommand"
  ) or
  target.getQualifiedName().matches("Poco%::Pipe%") and qn = "Poco::Pipe" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "Poco") and
    memberFunc.getName() = "Pipe" and
    qn = "Poco::Pipe"
  ) or
  target.getQualifiedName().matches("Poco%::PipeOutputStream%") and qn = "Poco::PipeOutputStream" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "Poco") and
    memberFunc.getName() = "PipeOutputStream" and
    qn = "Poco::PipeOutputStream"
  ) or
  target.getQualifiedName().matches("Poco%::PipeInputStream%") and qn = "Poco::PipeInputStream" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "Poco") and
    memberFunc.getName() = "PipeInputStream" and
    qn = "Poco::PipeInputStream"
  ) or
  target.getQualifiedName().matches("boost%::asio%::async_system%") and qn = "boost::asio::async_system" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost", "asio") and
    memberFunc.getName() = "async_system" and
    qn = "boost::asio::async_system"
  ) or
  target.getQualifiedName().matches("boost%::asio%::spawn_process%") and qn = "boost::asio::spawn_process" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost", "asio") and
    memberFunc.getName() = "spawn_process" and
    qn = "boost::asio::spawn_process"
  ) or
  target.getQualifiedName().matches("tbb%::flow%::external_process_node%") and qn = "tbb::flow::external_process_node" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("tbb", "flow") and
    memberFunc.getName() = "external_process_node" and
    qn = "tbb::flow::external_process_node"
  ) or
  target.getQualifiedName().matches("ACE%::Exec%") and qn = "ACE::Exec" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "ACE") and
    memberFunc.getName() = "Exec" and
    qn = "ACE::Exec"
  ) or
  target.getQualifiedName().matches("ACE_OS%::execv%") and qn = "ACE_OS::execv" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "ACE_OS") and
    memberFunc.getName() = "execv" and
    qn = "ACE_OS::execv"
  ) or
  target.getQualifiedName().matches("ACE_OS%::spawn%") and qn = "ACE_OS::spawn" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "ACE_OS") and
    memberFunc.getName() = "spawn" and
    qn = "ACE_OS::spawn"
  ) or
  target.getQualifiedName().matches("ACE_OS%::execl%") and qn = "ACE_OS::execl" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "ACE_OS") and
    memberFunc.getName() = "execl" and
    qn = "ACE_OS::execl"
  ) or
  target.getQualifiedName().matches("ACE_OS%::popen%") and qn = "ACE_OS::popen" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "ACE_OS") and
    memberFunc.getName() = "popen" and
    qn = "ACE_OS::popen"
  ) or
  target.getQualifiedName().matches("execvP%") and qn = "execvP" or
  target.getQualifiedName().matches("execlP%") and qn = "execlP" or
  target.getQualifiedName().matches("posix_spawn_file_actions_addopen%") and qn = "posix_spawn_file_actions_addopen" or
  target.getQualifiedName().matches("posix_spawn_file_actions_addclose%") and qn = "posix_spawn_file_actions_addclose" or
  target.getQualifiedName().matches("posix_spawn_file_actions_adddup2%") and qn = "posix_spawn_file_actions_adddup2" or
  target.getQualifiedName().matches("CreateProcessAsUserA%") and qn = "CreateProcessAsUserA" or
  target.getQualifiedName().matches("CreateProcessAsUserW%") and qn = "CreateProcessAsUserW" or
  target.getQualifiedName().matches("CreateProcessWithLogonW%") and qn = "CreateProcessWithLogonW" or
  target.getQualifiedName().matches("CreateProcessWithTokenW%") and qn = "CreateProcessWithTokenW" or
  target.getQualifiedName().matches("CreateProcessInternalW%") and qn = "CreateProcessInternalW" or
  target.getQualifiedName().matches("wxExecute%") and qn = "wxExecute" or
  target.getQualifiedName().matches("wxShell%") and qn = "wxShell" or
  target.getQualifiedName().matches("wxProcess%") and qn = "wxProcess" or
  target.getQualifiedName().matches("wxProcess%::Open%") and qn = "wxProcess::Open" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "wxProcess") and
    memberFunc.getName() = "Open" and
    qn = "wxProcess::Open"
  ) or
  target.getQualifiedName().matches("wxProcess%::Kill%") and qn = "wxProcess::Kill" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "wxProcess") and
    memberFunc.getName() = "Kill" and
    qn = "wxProcess::Kill"
  ) or
  target.getQualifiedName().matches("wxProcess%::Redirect%") and qn = "wxProcess::Redirect" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "wxProcess") and
    memberFunc.getName() = "Redirect" and
    qn = "wxProcess::Redirect"
  ) or
  target.getQualifiedName().matches("libcurl%::easy%::setopt_customrequest%") and qn = "libcurl::easy::setopt_customrequest" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("libcurl", "easy") and
    memberFunc.getName() = "setopt_customrequest" and
    qn = "libcurl::easy::setopt_customrequest"
  ) or
  target.getQualifiedName().matches("libcurl%::easy%::setopt_prequote%") and qn = "libcurl::easy::setopt_prequote" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("libcurl", "easy") and
    memberFunc.getName() = "setopt_prequote" and
    qn = "libcurl::easy::setopt_prequote"
  ) or
  target.getQualifiedName().matches("libcurl%::easy%::setopt_postquote%") and qn = "libcurl::easy::setopt_postquote" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("libcurl", "easy") and
    memberFunc.getName() = "setopt_postquote" and
    qn = "libcurl::easy::setopt_postquote"
  ) or
  target.getQualifiedName().matches("libcurl%::easy%::setopt_ssh_command%") and qn = "libcurl::easy::setopt_ssh_command" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("libcurl", "easy") and
    memberFunc.getName() = "setopt_ssh_command" and
    qn = "libcurl::easy::setopt_ssh_command"
  ) or
  target.getQualifiedName().matches("mongoose%::mg_spawn%") and qn = "mongoose::mg_spawn" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "mongoose") and
    memberFunc.getName() = "mg_spawn" and
    qn = "mongoose::mg_spawn"
  ) or
  target.getQualifiedName().matches("cpp-httplib%::detail%::exec_command%") and qn = "cpp-httplib::detail::exec_command" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("cpp-httplib", "detail") and
    memberFunc.getName() = "exec_command" and
    qn = "cpp-httplib::detail::exec_command"
  ) or
  target.getQualifiedName().matches("cpp-httplib%::detail%::shell_execute%") and qn = "cpp-httplib::detail::shell_execute" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("cpp-httplib", "detail") and
    memberFunc.getName() = "shell_execute" and
    qn = "cpp-httplib::detail::shell_execute"
  ) or
  target.getQualifiedName().matches("Crow%::system_exec%") and qn = "Crow::system_exec" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "Crow") and
    memberFunc.getName() = "system_exec" and
    qn = "Crow::system_exec"
  ) or
  target.getQualifiedName().matches("Crow%::utility%::execute%") and qn = "Crow::utility::execute" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Crow", "utility") and
    memberFunc.getName() = "execute" and
    qn = "Crow::utility::execute"
  ) or
  target.getQualifiedName().matches("FastCGI%::ProcessManager%::spawnWorker%") and qn = "FastCGI::ProcessManager::spawnWorker" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("FastCGI", "ProcessManager") and
    memberFunc.getName() = "spawnWorker" and
    qn = "FastCGI::ProcessManager::spawnWorker"
  ) or
  target.getQualifiedName().matches("apache%::mod_cgi%::run%") and qn = "apache::mod_cgi::run" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("apache", "mod_cgi") and
    memberFunc.getName() = "run" and
    qn = "apache::mod_cgi::run"
  ) or
  target.getQualifiedName().matches("apache%::mod_cgid%::spawn_process%") and qn = "apache::mod_cgid::spawn_process" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("apache", "mod_cgid") and
    memberFunc.getName() = "spawn_process" and
    qn = "apache::mod_cgid::spawn_process"
  ) or
  target.getQualifiedName().matches("rocksdb%::Env%::ExecuteShellCommand%") and qn = "rocksdb::Env::ExecuteShellCommand" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("rocksdb", "Env") and
    memberFunc.getName() = "ExecuteShellCommand" and
    qn = "rocksdb::Env::ExecuteShellCommand"
  ) or
  target.getQualifiedName().matches("leveldb%::Env%::ExecuteCommand%") and qn = "leveldb::Env::ExecuteCommand" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("leveldb", "Env") and
    memberFunc.getName() = "ExecuteCommand" and
    qn = "leveldb::Env::ExecuteCommand"
  ) or
  target.getQualifiedName().matches("Python%::PyRun_SimpleString%") and qn = "Python::PyRun_SimpleString" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "Python") and
    memberFunc.getName() = "PyRun_SimpleString" and
    qn = "Python::PyRun_SimpleString"
  ) or
  target.getQualifiedName().matches("Lua%::luaL_dofile%") and qn = "Lua::luaL_dofile" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "Lua") and
    memberFunc.getName() = "luaL_dofile" and
    qn = "Lua::luaL_dofile"
  ) or
  target.getQualifiedName().matches("Lua%::luaL_dostring%") and qn = "Lua::luaL_dostring" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "Lua") and
    memberFunc.getName() = "luaL_dostring" and
    qn = "Lua::luaL_dostring"
  ) or
  target.getQualifiedName().matches("Perl%::perl_eval_pv%") and qn = "Perl::perl_eval_pv" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "Perl") and
    memberFunc.getName() = "perl_eval_pv" and
    qn = "Perl::perl_eval_pv"
  ) or
  target.getQualifiedName().matches("Ruby%::rb_eval_string%") and qn = "Ruby::rb_eval_string" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "Ruby") and
    memberFunc.getName() = "rb_eval_string" and
    qn = "Ruby::rb_eval_string"
  )
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
