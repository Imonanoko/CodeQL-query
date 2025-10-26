// Auto-generated; CWE-095; number of APIs 135
import cpp

predicate isTargetApi(Function target, string qn) {
  target.getQualifiedName().matches("system%") and qn = "system" or
  target.getQualifiedName().matches("popen%") and qn = "popen" or
  target.getQualifiedName().matches("execv%") and qn = "execv" or
  target.getQualifiedName().matches("execl%") and qn = "execl" or
  target.getQualifiedName().matches("execvp%") and qn = "execvp" or
  target.getQualifiedName().matches("execve%") and qn = "execve" or
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
  target.getQualifiedName().matches("QProcess%") and qn = "QProcess" or
  target.getQualifiedName().matches("QProcess%::start%") and qn = "QProcess::start" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QProcess") and
    memberFunc.getName() = "start" and
    qn = "QProcess::start"
  ) or
  target.getQualifiedName().matches("QProcess%::execute%") and qn = "QProcess::execute" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QProcess") and
    memberFunc.getName() = "execute" and
    qn = "QProcess::execute"
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
  target.getQualifiedName().matches("ACE_OS%::execv%") and qn = "ACE_OS::execv" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "ACE_OS") and
    memberFunc.getName() = "execv" and
    qn = "ACE_OS::execv"
  ) or
  target.getQualifiedName().matches("ACE_OS%::execl%") and qn = "ACE_OS::execl" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "ACE_OS") and
    memberFunc.getName() = "execl" and
    qn = "ACE_OS::execl"
  ) or
  target.getQualifiedName().matches("ACE_OS%::spawn%") and qn = "ACE_OS::spawn" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "ACE_OS") and
    memberFunc.getName() = "spawn" and
    qn = "ACE_OS::spawn"
  ) or
  target.getQualifiedName().matches("libuv%::process_spawn%") and qn = "libuv::process_spawn" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "libuv") and
    memberFunc.getName() = "process_spawn" and
    qn = "libuv::process_spawn"
  ) or
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
  target.getQualifiedName().matches("CreateProcessA%") and qn = "CreateProcessA" or
  target.getQualifiedName().matches("CreateProcessW%") and qn = "CreateProcessW" or
  target.getQualifiedName().matches("ShellExecuteA%") and qn = "ShellExecuteA" or
  target.getQualifiedName().matches("ShellExecuteW%") and qn = "ShellExecuteW" or
  target.getQualifiedName().matches("ShellExecuteExA%") and qn = "ShellExecuteExA" or
  target.getQualifiedName().matches("ShellExecuteExW%") and qn = "ShellExecuteExW" or
  target.getQualifiedName().matches("_popen%") and qn = "_popen" or
  target.getQualifiedName().matches("_wpopen%") and qn = "_wpopen" or
  target.getQualifiedName().matches("WinExec%") and qn = "WinExec" or
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
  target.getQualifiedName().matches("ngx_http_script_compile%") and qn = "ngx_http_script_compile" or
  target.getQualifiedName().matches("ngx_http_script_execute%") and qn = "ngx_http_script_execute" or
  target.getQualifiedName().matches("nginx_module_exec%") and qn = "nginx_module_exec" or
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
  target.getQualifiedName().matches("sqlite3_exec%") and qn = "sqlite3_exec" or
  target.getQualifiedName().matches("sqlite3_prepare_v2%") and qn = "sqlite3_prepare_v2" or
  target.getQualifiedName().matches("sqlite3_prepare%") and qn = "sqlite3_prepare" or
  target.getQualifiedName().matches("sqlite3_prepare16_v2%") and qn = "sqlite3_prepare16_v2" or
  target.getQualifiedName().matches("sqlite3_prepare16%") and qn = "sqlite3_prepare16" or
  target.getQualifiedName().matches("sqlite3_step%") and qn = "sqlite3_step" or
  target.getQualifiedName().matches("sqlite3_bind_text%") and qn = "sqlite3_bind_text" or
  target.getQualifiedName().matches("sqlite3_bind_blob%") and qn = "sqlite3_bind_blob" or
  target.getQualifiedName().matches("sqlite3_bind_parameter_index%") and qn = "sqlite3_bind_parameter_index" or
  target.getQualifiedName().matches("sqlite3_exec_system%") and qn = "sqlite3_exec_system" or
  target.getQualifiedName().matches("mysql_query%") and qn = "mysql_query" or
  target.getQualifiedName().matches("mysql_real_query%") and qn = "mysql_real_query" or
  target.getQualifiedName().matches("mysql_send_query%") and qn = "mysql_send_query" or
  target.getQualifiedName().matches("mysql_stmt_execute%") and qn = "mysql_stmt_execute" or
  target.getQualifiedName().matches("pg_query%") and qn = "pg_query" or
  target.getQualifiedName().matches("PQexec%") and qn = "PQexec" or
  target.getQualifiedName().matches("PQexecParams%") and qn = "PQexecParams" or
  target.getQualifiedName().matches("PQprepare%") and qn = "PQprepare" or
  target.getQualifiedName().matches("PQexecPrepared%") and qn = "PQexecPrepared" or
  target.getQualifiedName().matches("PQsendQuery%") and qn = "PQsendQuery" or
  target.getQualifiedName().matches("PQsendQueryParams%") and qn = "PQsendQueryParams" or
  target.getQualifiedName().matches("odbc%::SQLExecDirect%") and qn = "odbc::SQLExecDirect" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "odbc") and
    memberFunc.getName() = "SQLExecDirect" and
    qn = "odbc::SQLExecDirect"
  ) or
  target.getQualifiedName().matches("odbc%::SQLPrepare%") and qn = "odbc::SQLPrepare" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "odbc") and
    memberFunc.getName() = "SQLPrepare" and
    qn = "odbc::SQLPrepare"
  ) or
  target.getQualifiedName().matches("odbc%::SQLExecute%") and qn = "odbc::SQLExecute" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "odbc") and
    memberFunc.getName() = "SQLExecute" and
    qn = "odbc::SQLExecute"
  ) or
  target.getQualifiedName().matches("odbc%::SQLExecDirectW%") and qn = "odbc::SQLExecDirectW" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "odbc") and
    memberFunc.getName() = "SQLExecDirectW" and
    qn = "odbc::SQLExecDirectW"
  ) or
  target.getQualifiedName().matches("odbc%::SQLExecDirectA%") and qn = "odbc::SQLExecDirectA" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "odbc") and
    memberFunc.getName() = "SQLExecDirectA" and
    qn = "odbc::SQLExecDirectA"
  ) or
  target.getQualifiedName().matches("odbc%::SQLPrepareA%") and qn = "odbc::SQLPrepareA" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "odbc") and
    memberFunc.getName() = "SQLPrepareA" and
    qn = "odbc::SQLPrepareA"
  ) or
  target.getQualifiedName().matches("odbc%::SQLPrepareW%") and qn = "odbc::SQLPrepareW" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "odbc") and
    memberFunc.getName() = "SQLPrepareW" and
    qn = "odbc::SQLPrepareW"
  ) or
  target.getQualifiedName().matches("rocksdb%::DB%::Execute%") and qn = "rocksdb::DB::Execute" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("rocksdb", "DB") and
    memberFunc.getName() = "Execute" and
    qn = "rocksdb::DB::Execute"
  ) or
  target.getQualifiedName().matches("rocksdb%::DB%::Query%") and qn = "rocksdb::DB::Query" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("rocksdb", "DB") and
    memberFunc.getName() = "Query" and
    qn = "rocksdb::DB::Query"
  ) or
  target.getQualifiedName().matches("leveldb%::DB%::Execute%") and qn = "leveldb::DB::Execute" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("leveldb", "DB") and
    memberFunc.getName() = "Execute" and
    qn = "leveldb::DB::Execute"
  ) or
  target.getQualifiedName().matches("leveldb%::DB%::Query%") and qn = "leveldb::DB::Query" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("leveldb", "DB") and
    memberFunc.getName() = "Query" and
    qn = "leveldb::DB::Query"
  ) or
  target.getQualifiedName().matches("cpp-httplib%::detail%::eval_script%") and qn = "cpp-httplib::detail::eval_script" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("cpp-httplib", "detail") and
    memberFunc.getName() = "eval_script" and
    qn = "cpp-httplib::detail::eval_script"
  ) or
  target.getQualifiedName().matches("cpp-httplib%::detail%::eval_expression%") and qn = "cpp-httplib::detail::eval_expression" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("cpp-httplib", "detail") and
    memberFunc.getName() = "eval_expression" and
    qn = "cpp-httplib::detail::eval_expression"
  ) or
  target.getQualifiedName().matches("cpp-httplib%::detail%::render_template%") and qn = "cpp-httplib::detail::render_template" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("cpp-httplib", "detail") and
    memberFunc.getName() = "render_template" and
    qn = "cpp-httplib::detail::render_template"
  ) or
  target.getQualifiedName().matches("cppcms%::template%::render%") and qn = "cppcms::template::render" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("cppcms", "template") and
    memberFunc.getName() = "render" and
    qn = "cppcms::template::render"
  ) or
  target.getQualifiedName().matches("cppcms%::template%::render_to_string%") and qn = "cppcms::template::render_to_string" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("cppcms", "template") and
    memberFunc.getName() = "render_to_string" and
    qn = "cppcms::template::render_to_string"
  ) or
  target.getQualifiedName().matches("crow%::mustache%::render%") and qn = "crow::mustache::render" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("crow", "mustache") and
    memberFunc.getName() = "render" and
    qn = "crow::mustache::render"
  ) or
  target.getQualifiedName().matches("crow%::mustache%::load%") and qn = "crow::mustache::load" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("crow", "mustache") and
    memberFunc.getName() = "load" and
    qn = "crow::mustache::load"
  ) or
  target.getQualifiedName().matches("mongoose%::mg_eval_js%") and qn = "mongoose::mg_eval_js" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "mongoose") and
    memberFunc.getName() = "mg_eval_js" and
    qn = "mongoose::mg_eval_js"
  ) or
  target.getQualifiedName().matches("mongoose%::mg_process_script%") and qn = "mongoose::mg_process_script" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "mongoose") and
    memberFunc.getName() = "mg_process_script" and
    qn = "mongoose::mg_process_script"
  ) or
  target.getQualifiedName().matches("drogon%::HttpViewData%::insert%") and qn = "drogon::HttpViewData::insert" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("drogon", "HttpViewData") and
    memberFunc.getName() = "insert" and
    qn = "drogon::HttpViewData::insert"
  ) or
  target.getQualifiedName().matches("drogon%::HttpViewData%::get%") and qn = "drogon::HttpViewData::get" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("drogon", "HttpViewData") and
    memberFunc.getName() = "get" and
    qn = "drogon::HttpViewData::get"
  ) or
  target.getQualifiedName().matches("drogon%::DrTemplateBase%::render%") and qn = "drogon::DrTemplateBase::render" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("drogon", "DrTemplateBase") and
    memberFunc.getName() = "render" and
    qn = "drogon::DrTemplateBase::render"
  ) or
  target.getQualifiedName().matches("Wt%::WTemplate%::render%") and qn = "Wt::WTemplate::render" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Wt", "WTemplate") and
    memberFunc.getName() = "render" and
    qn = "Wt::WTemplate::render"
  ) or
  target.getQualifiedName().matches("Wt%::WTemplate%::bindString%") and qn = "Wt::WTemplate::bindString" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Wt", "WTemplate") and
    memberFunc.getName() = "bindString" and
    qn = "Wt::WTemplate::bindString"
  ) or
  target.getQualifiedName().matches("Wt%::WTemplate%::bindWidget%") and qn = "Wt::WTemplate::bindWidget" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Wt", "WTemplate") and
    memberFunc.getName() = "bindWidget" and
    qn = "Wt::WTemplate::bindWidget"
  ) or
  target.getQualifiedName().matches("Wt%::WTemplate%::setTemplateText%") and qn = "Wt::WTemplate::setTemplateText" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Wt", "WTemplate") and
    memberFunc.getName() = "setTemplateText" and
    qn = "Wt::WTemplate::setTemplateText"
  ) or
  target.getQualifiedName().matches("Wt%::WTemplate%::resolveString%") and qn = "Wt::WTemplate::resolveString" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Wt", "WTemplate") and
    memberFunc.getName() = "resolveString" and
    qn = "Wt::WTemplate::resolveString"
  ) or
  target.getQualifiedName().matches("oatpp%::parser%::Caret%::parseTextTemplate%") and qn = "oatpp::parser::Caret::parseTextTemplate" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("oatpp::parser", "Caret") and
    memberFunc.getName() = "parseTextTemplate" and
    qn = "oatpp::parser::Caret::parseTextTemplate"
  ) or
  target.getQualifiedName().matches("oatpp%::web%::protocol%::http%::outgoing%::ResponseFactory%::createTemplateResponse%") and qn = "oatpp::web::protocol::http::outgoing::ResponseFactory::createTemplateResponse" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("oatpp::web::protocol::http::outgoing", "ResponseFactory") and
    memberFunc.getName() = "createTemplateResponse" and
    qn = "oatpp::web::protocol::http::outgoing::ResponseFactory::createTemplateResponse"
  ) or
  target.getQualifiedName().matches("ctemplate%::Template%::Expand%") and qn = "ctemplate::Template::Expand" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("ctemplate", "Template") and
    memberFunc.getName() = "Expand" and
    qn = "ctemplate::Template::Expand"
  ) or
  target.getQualifiedName().matches("ctemplate%::TemplateDictionary%::SetValue%") and qn = "ctemplate::TemplateDictionary::SetValue" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("ctemplate", "TemplateDictionary") and
    memberFunc.getName() = "SetValue" and
    qn = "ctemplate::TemplateDictionary::SetValue"
  ) or
  target.getQualifiedName().matches("inja%::Environment%::render%") and qn = "inja::Environment::render" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("inja", "Environment") and
    memberFunc.getName() = "render" and
    qn = "inja::Environment::render"
  ) or
  target.getQualifiedName().matches("inja%::Template%::render%") and qn = "inja::Template::render" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("inja", "Template") and
    memberFunc.getName() = "render" and
    qn = "inja::Template::render"
  ) or
  target.getQualifiedName().matches("inja%::Environment%::parse_template%") and qn = "inja::Environment::parse_template" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("inja", "Environment") and
    memberFunc.getName() = "parse_template" and
    qn = "inja::Environment::parse_template"
  ) or
  target.getQualifiedName().matches("inja%::render%") and qn = "inja::render" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "inja") and
    memberFunc.getName() = "render" and
    qn = "inja::render"
  ) or
  target.getQualifiedName().matches("inja%::render_to%") and qn = "inja::render_to" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "inja") and
    memberFunc.getName() = "render_to" and
    qn = "inja::render_to"
  ) or
  target.getQualifiedName().matches("inja%::load_template%") and qn = "inja::load_template" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "inja") and
    memberFunc.getName() = "load_template" and
    qn = "inja::load_template"
  ) or
  target.getQualifiedName().matches("inja%::Environment%::load_template%") and qn = "inja::Environment::load_template" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("inja", "Environment") and
    memberFunc.getName() = "load_template" and
    qn = "inja::Environment::load_template"
  ) or
  target.getQualifiedName().matches("inja%::Environment%::render_template%") and qn = "inja::Environment::render_template" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("inja", "Environment") and
    memberFunc.getName() = "render_template" and
    qn = "inja::Environment::render_template"
  ) or
  target.getQualifiedName().matches("inja%::Environment%::evaluate_expression%") and qn = "inja::Environment::evaluate_expression" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("inja", "Environment") and
    memberFunc.getName() = "evaluate_expression" and
    qn = "inja::Environment::evaluate_expression"
  ) or
  target.getQualifiedName().matches("inja%::Environment%::parse_expression%") and qn = "inja::Environment::parse_expression" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("inja", "Environment") and
    memberFunc.getName() = "parse_expression" and
    qn = "inja::Environment::parse_expression"
  ) or
  target.getQualifiedName().matches("inja%::Parser%::parse_expression%") and qn = "inja::Parser::parse_expression" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("inja", "Parser") and
    memberFunc.getName() = "parse_expression" and
    qn = "inja::Parser::parse_expression"
  ) or
  target.getQualifiedName().matches("inja%::Parser%::parse_statement%") and qn = "inja::Parser::parse_statement" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("inja", "Parser") and
    memberFunc.getName() = "parse_statement" and
    qn = "inja::Parser::parse_statement"
  ) or
  target.getQualifiedName().matches("inja%::Renderer%::render_expression%") and qn = "inja::Renderer::render_expression" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("inja", "Renderer") and
    memberFunc.getName() = "render_expression" and
    qn = "inja::Renderer::render_expression"
  ) or
  target.getQualifiedName().matches("inja%::Renderer%::render_statement%") and qn = "inja::Renderer::render_statement" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("inja", "Renderer") and
    memberFunc.getName() = "render_statement" and
    qn = "inja::Renderer::render_statement"
  ) or
  target.getQualifiedName().matches("inja%::Renderer%::render_template%") and qn = "inja::Renderer::render_template" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("inja", "Renderer") and
    memberFunc.getName() = "render_template" and
    qn = "inja::Renderer::render_template"
  ) or
  target.getQualifiedName().matches("inja%::Renderer%::render_block%") and qn = "inja::Renderer::render_block" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("inja", "Renderer") and
    memberFunc.getName() = "render_block" and
    qn = "inja::Renderer::render_block"
  ) or
  target.getQualifiedName().matches("inja%::Renderer%::render_function_call%") and qn = "inja::Renderer::render_function_call" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("inja", "Renderer") and
    memberFunc.getName() = "render_function_call" and
    qn = "inja::Renderer::render_function_call"
  ) or
  target.getQualifiedName().matches("inja%::Renderer%::render_variable%") and qn = "inja::Renderer::render_variable" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("inja", "Renderer") and
    memberFunc.getName() = "render_variable" and
    qn = "inja::Renderer::render_variable"
  ) or
  target.getQualifiedName().matches("inja%::Renderer%::render_eval%") and qn = "inja::Renderer::render_eval" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("inja", "Renderer") and
    memberFunc.getName() = "render_eval" and
    qn = "inja::Renderer::render_eval"
  ) or
  target.getQualifiedName().matches("inja%::Environment%::eval_expression%") and qn = "inja::Environment::eval_expression" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("inja", "Environment") and
    memberFunc.getName() = "eval_expression" and
    qn = "inja::Environment::eval_expression"
  ) or
  target.getQualifiedName().matches("inja%::FunctionStorage%::add_builtin%") and qn = "inja::FunctionStorage::add_builtin" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("inja", "FunctionStorage") and
    memberFunc.getName() = "add_builtin" and
    qn = "inja::FunctionStorage::add_builtin"
  ) or
  target.getQualifiedName().matches("inja%::FunctionStorage%::add_callback%") and qn = "inja::FunctionStorage::add_callback" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("inja", "FunctionStorage") and
    memberFunc.getName() = "add_callback" and
    qn = "inja::FunctionStorage::add_callback"
  ) or
  target.getQualifiedName().matches("inja%::Environment%::register_callback%") and qn = "inja::Environment::register_callback" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("inja", "Environment") and
    memberFunc.getName() = "register_callback" and
    qn = "inja::Environment::register_callback"
  ) or
  target.getQualifiedName().matches("inja%::Environment%::add_callback%") and qn = "inja::Environment::add_callback" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("inja", "Environment") and
    memberFunc.getName() = "add_callback" and
    qn = "inja::Environment::add_callback"
  ) or
  target.getQualifiedName().matches("inja%::Environment%::add_expression_callback%") and qn = "inja::Environment::add_expression_callback" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("inja", "Environment") and
    memberFunc.getName() = "add_expression_callback" and
    qn = "inja::Environment::add_expression_callback"
  ) or
  target.getQualifiedName().matches("inja%::Environment%::add_statement_callback%") and qn = "inja::Environment::add_statement_callback" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("inja", "Environment") and
    memberFunc.getName() = "add_statement_callback" and
    qn = "inja::Environment::add_statement_callback"
  ) or
  target.getQualifiedName().matches("inja%::Environment%::register_expression%") and qn = "inja::Environment::register_expression" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("inja", "Environment") and
    memberFunc.getName() = "register_expression" and
    qn = "inja::Environment::register_expression"
  ) or
  target.getQualifiedName().matches("inja%::Environment%::register_statement%") and qn = "inja::Environment::register_statement" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("inja", "Environment") and
    memberFunc.getName() = "register_statement" and
    qn = "inja::Environment::register_statement"
  ) or
  target.getQualifiedName().matches("inja%::Environment%::register_filter%") and qn = "inja::Environment::register_filter" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("inja", "Environment") and
    memberFunc.getName() = "register_filter" and
    qn = "inja::Environment::register_filter"
  ) or
  target.getQualifiedName().matches("inja%::Environment%::add_filter%") and qn = "inja::Environment::add_filter" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("inja", "Environment") and
    memberFunc.getName() = "add_filter" and
    qn = "inja::Environment::add_filter"
  ) or
  target.getQualifiedName().matches("inja%::Environment%::add_template%") and qn = "inja::Environment::add_template" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("inja", "Environment") and
    memberFunc.getName() = "add_template" and
    qn = "inja::Environment::add_template"
  ) or
  target.getQualifiedName().matches("inja%::Environment%::load%") and qn = "inja::Environment::load" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("inja", "Environment") and
    memberFunc.getName() = "load" and
    qn = "inja::Environment::load"
  ) or
  target.getQualifiedName().matches("inja%::Environment%::load_from_string%") and qn = "inja::Environment::load_from_string" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("inja", "Environment") and
    memberFunc.getName() = "load_from_string" and
    qn = "inja::Environment::load_from_string"
  ) or
  target.getQualifiedName().matches("inja%::Environment%::load_from_file%") and qn = "inja::Environment::load_from_file" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("inja", "Environment") and
    memberFunc.getName() = "load_from_file" and
    qn = "inja::Environment::load_from_file"
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
