// Auto-generated; CWE-113; number of APIs 148
import cpp

predicate isTargetApi(Function target, string qn) {
  target.getQualifiedName().matches("printf%") and qn = "printf" or
  target.getQualifiedName().matches("fprintf%") and qn = "fprintf" or
  target.getQualifiedName().matches("sprintf%") and qn = "sprintf" or
  target.getQualifiedName().matches("snprintf%") and qn = "snprintf" or
  target.getQualifiedName().matches("vprintf%") and qn = "vprintf" or
  target.getQualifiedName().matches("vfprintf%") and qn = "vfprintf" or
  target.getQualifiedName().matches("vsprintf%") and qn = "vsprintf" or
  target.getQualifiedName().matches("vsnprintf%") and qn = "vsnprintf" or
  target.getQualifiedName().matches("puts%") and qn = "puts" or
  target.getQualifiedName().matches("fputs%") and qn = "fputs" or
  target.getQualifiedName().matches("std%::cout%") and qn = "std::cout" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "std") and
    memberFunc.getName() = "cout" and
    qn = "std::cout"
  ) or
  target.getQualifiedName().matches("std%::cerr%") and qn = "std::cerr" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "std") and
    memberFunc.getName() = "cerr" and
    qn = "std::cerr"
  ) or
  target.getQualifiedName().matches("std%::ostream%::operator<<%") and qn = "std::ostream::operator<<" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "ostream") and
    memberFunc.getName() = "operator<<" and
    qn = "std::ostream::operator<<"
  ) or
  target.getQualifiedName().matches("std%::ostringstream%::operator<<%") and qn = "std::ostringstream::operator<<" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "ostringstream") and
    memberFunc.getName() = "operator<<" and
    qn = "std::ostringstream::operator<<"
  ) or
  target.getQualifiedName().matches("std%::stringstream%::operator<<%") and qn = "std::stringstream::operator<<" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "stringstream") and
    memberFunc.getName() = "operator<<" and
    qn = "std::stringstream::operator<<"
  ) or
  target.getQualifiedName().matches("std%::ofstream%::operator<<%") and qn = "std::ofstream::operator<<" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "ofstream") and
    memberFunc.getName() = "operator<<" and
    qn = "std::ofstream::operator<<"
  ) or
  target.getQualifiedName().matches("std%::ostream%::write%") and qn = "std::ostream::write" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "ostream") and
    memberFunc.getName() = "write" and
    qn = "std::ostream::write"
  ) or
  target.getQualifiedName().matches("std%::ofstream%::write%") and qn = "std::ofstream::write" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "ofstream") and
    memberFunc.getName() = "write" and
    qn = "std::ofstream::write"
  ) or
  target.getQualifiedName().matches("std%::ostringstream%::write%") and qn = "std::ostringstream::write" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "ostringstream") and
    memberFunc.getName() = "write" and
    qn = "std::ostringstream::write"
  ) or
  target.getQualifiedName().matches("std%::stringstream%::write%") and qn = "std::stringstream::write" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "stringstream") and
    memberFunc.getName() = "write" and
    qn = "std::stringstream::write"
  ) or
  target.getQualifiedName().matches("std%::ostringstream%::str%") and qn = "std::ostringstream::str" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "ostringstream") and
    memberFunc.getName() = "str" and
    qn = "std::ostringstream::str"
  ) or
  target.getQualifiedName().matches("std%::stringstream%::str%") and qn = "std::stringstream::str" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "stringstream") and
    memberFunc.getName() = "str" and
    qn = "std::stringstream::str"
  ) or
  target.getQualifiedName().matches("boost%::format%") and qn = "boost::format" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "boost") and
    memberFunc.getName() = "format" and
    qn = "boost::format"
  ) or
  target.getQualifiedName().matches("fmt%::format%") and qn = "fmt::format" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "fmt") and
    memberFunc.getName() = "format" and
    qn = "fmt::format"
  ) or
  target.getQualifiedName().matches("fmt%::print%") and qn = "fmt::print" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "fmt") and
    memberFunc.getName() = "print" and
    qn = "fmt::print"
  ) or
  target.getQualifiedName().matches("fmt%::vprint%") and qn = "fmt::vprint" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "fmt") and
    memberFunc.getName() = "vprint" and
    qn = "fmt::vprint"
  ) or
  target.getQualifiedName().matches("fmt%::format_to%") and qn = "fmt::format_to" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "fmt") and
    memberFunc.getName() = "format_to" and
    qn = "fmt::format_to"
  ) or
  target.getQualifiedName().matches("fmt%::vformat%") and qn = "fmt::vformat" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "fmt") and
    memberFunc.getName() = "vformat" and
    qn = "fmt::vformat"
  ) or
  target.getQualifiedName().matches("spdlog%::info%") and qn = "spdlog::info" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "spdlog") and
    memberFunc.getName() = "info" and
    qn = "spdlog::info"
  ) or
  target.getQualifiedName().matches("spdlog%::warn%") and qn = "spdlog::warn" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "spdlog") and
    memberFunc.getName() = "warn" and
    qn = "spdlog::warn"
  ) or
  target.getQualifiedName().matches("spdlog%::error%") and qn = "spdlog::error" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "spdlog") and
    memberFunc.getName() = "error" and
    qn = "spdlog::error"
  ) or
  target.getQualifiedName().matches("spdlog%::debug%") and qn = "spdlog::debug" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "spdlog") and
    memberFunc.getName() = "debug" and
    qn = "spdlog::debug"
  ) or
  target.getQualifiedName().matches("spdlog%::trace%") and qn = "spdlog::trace" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "spdlog") and
    memberFunc.getName() = "trace" and
    qn = "spdlog::trace"
  ) or
  target.getQualifiedName().matches("Poco%::Logger%::information%") and qn = "Poco::Logger::information" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Poco", "Logger") and
    memberFunc.getName() = "information" and
    qn = "Poco::Logger::information"
  ) or
  target.getQualifiedName().matches("Poco%::Logger%::warning%") and qn = "Poco::Logger::warning" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Poco", "Logger") and
    memberFunc.getName() = "warning" and
    qn = "Poco::Logger::warning"
  ) or
  target.getQualifiedName().matches("Poco%::Logger%::error%") and qn = "Poco::Logger::error" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Poco", "Logger") and
    memberFunc.getName() = "error" and
    qn = "Poco::Logger::error"
  ) or
  target.getQualifiedName().matches("Poco%::Logger%::debug%") and qn = "Poco::Logger::debug" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Poco", "Logger") and
    memberFunc.getName() = "debug" and
    qn = "Poco::Logger::debug"
  ) or
  target.getQualifiedName().matches("Poco%::Logger%::trace%") and qn = "Poco::Logger::trace" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Poco", "Logger") and
    memberFunc.getName() = "trace" and
    qn = "Poco::Logger::trace"
  ) or
  target.getQualifiedName().matches("Poco%::Logger%::critical%") and qn = "Poco::Logger::critical" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Poco", "Logger") and
    memberFunc.getName() = "critical" and
    qn = "Poco::Logger::critical"
  ) or
  target.getQualifiedName().matches("Poco%::Logger%::fatal%") and qn = "Poco::Logger::fatal" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Poco", "Logger") and
    memberFunc.getName() = "fatal" and
    qn = "Poco::Logger::fatal"
  ) or
  target.getQualifiedName().matches("syslog%") and qn = "syslog" or
  target.getQualifiedName().matches("vsyslog%") and qn = "vsyslog" or
  target.getQualifiedName().matches("cpp-httplib%::Response%::set_header%") and qn = "cpp-httplib::Response::set_header" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("cpp-httplib", "Response") and
    memberFunc.getName() = "set_header" and
    qn = "cpp-httplib::Response::set_header"
  ) or
  target.getQualifiedName().matches("cpp-httplib%::Response%::set_content%") and qn = "cpp-httplib::Response::set_content" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("cpp-httplib", "Response") and
    memberFunc.getName() = "set_content" and
    qn = "cpp-httplib::Response::set_content"
  ) or
  target.getQualifiedName().matches("cpp-httplib%::Response%::operator<<%") and qn = "cpp-httplib::Response::operator<<" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("cpp-httplib", "Response") and
    memberFunc.getName() = "operator<<" and
    qn = "cpp-httplib::Response::operator<<"
  ) or
  target.getQualifiedName().matches("cpp-httplib%::Response%::write%") and qn = "cpp-httplib::Response::write" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("cpp-httplib", "Response") and
    memberFunc.getName() = "write" and
    qn = "cpp-httplib::Response::write"
  ) or
  target.getQualifiedName().matches("cpp-httplib%::Response%::set_redirect%") and qn = "cpp-httplib::Response::set_redirect" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("cpp-httplib", "Response") and
    memberFunc.getName() = "set_redirect" and
    qn = "cpp-httplib::Response::set_redirect"
  ) or
  target.getQualifiedName().matches("cpp-httplib%::detail%::write_response%") and qn = "cpp-httplib::detail::write_response" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("cpp-httplib", "detail") and
    memberFunc.getName() = "write_response" and
    qn = "cpp-httplib::detail::write_response"
  ) or
  target.getQualifiedName().matches("crow%::response%::add_header%") and qn = "crow::response::add_header" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("crow", "response") and
    memberFunc.getName() = "add_header" and
    qn = "crow::response::add_header"
  ) or
  target.getQualifiedName().matches("crow%::response%::set_header%") and qn = "crow::response::set_header" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("crow", "response") and
    memberFunc.getName() = "set_header" and
    qn = "crow::response::set_header"
  ) or
  target.getQualifiedName().matches("crow%::response%::write%") and qn = "crow::response::write" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("crow", "response") and
    memberFunc.getName() = "write" and
    qn = "crow::response::write"
  ) or
  target.getQualifiedName().matches("crow%::response%::end%") and qn = "crow::response::end" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("crow", "response") and
    memberFunc.getName() = "end" and
    qn = "crow::response::end"
  ) or
  target.getQualifiedName().matches("crow%::response%::operator<<%") and qn = "crow::response::operator<<" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("crow", "response") and
    memberFunc.getName() = "operator<<" and
    qn = "crow::response::operator<<"
  ) or
  target.getQualifiedName().matches("Crow%::response%::add_header%") and qn = "Crow::response::add_header" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Crow", "response") and
    memberFunc.getName() = "add_header" and
    qn = "Crow::response::add_header"
  ) or
  target.getQualifiedName().matches("Crow%::response%::set_header%") and qn = "Crow::response::set_header" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Crow", "response") and
    memberFunc.getName() = "set_header" and
    qn = "Crow::response::set_header"
  ) or
  target.getQualifiedName().matches("Crow%::response%::write%") and qn = "Crow::response::write" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Crow", "response") and
    memberFunc.getName() = "write" and
    qn = "Crow::response::write"
  ) or
  target.getQualifiedName().matches("mongoose%::mg_printf%") and qn = "mongoose::mg_printf" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "mongoose") and
    memberFunc.getName() = "mg_printf" and
    qn = "mongoose::mg_printf"
  ) or
  target.getQualifiedName().matches("mongoose%::mg_http_reply%") and qn = "mongoose::mg_http_reply" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "mongoose") and
    memberFunc.getName() = "mg_http_reply" and
    qn = "mongoose::mg_http_reply"
  ) or
  target.getQualifiedName().matches("mongoose%::mg_http_printf_chunk%") and qn = "mongoose::mg_http_printf_chunk" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "mongoose") and
    memberFunc.getName() = "mg_http_printf_chunk" and
    qn = "mongoose::mg_http_printf_chunk"
  ) or
  target.getQualifiedName().matches("mongoose%::mg_send_http_chunk%") and qn = "mongoose::mg_send_http_chunk" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "mongoose") and
    memberFunc.getName() = "mg_send_http_chunk" and
    qn = "mongoose::mg_send_http_chunk"
  ) or
  target.getQualifiedName().matches("mongoose%::mg_http_write_chunk%") and qn = "mongoose::mg_http_write_chunk" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "mongoose") and
    memberFunc.getName() = "mg_http_write_chunk" and
    qn = "mongoose::mg_http_write_chunk"
  ) or
  target.getQualifiedName().matches("mongoose%::mg_send_head%") and qn = "mongoose::mg_send_head" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "mongoose") and
    memberFunc.getName() = "mg_send_head" and
    qn = "mongoose::mg_send_head"
  ) or
  target.getQualifiedName().matches("CivetServer%::mg_printf%") and qn = "CivetServer::mg_printf" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "CivetServer") and
    memberFunc.getName() = "mg_printf" and
    qn = "CivetServer::mg_printf"
  ) or
  target.getQualifiedName().matches("CivetServer%::mg_vprintf%") and qn = "CivetServer::mg_vprintf" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "CivetServer") and
    memberFunc.getName() = "mg_vprintf" and
    qn = "CivetServer::mg_vprintf"
  ) or
  target.getQualifiedName().matches("CivetServer%::mg_write%") and qn = "CivetServer::mg_write" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "CivetServer") and
    memberFunc.getName() = "mg_write" and
    qn = "CivetServer::mg_write"
  ) or
  target.getQualifiedName().matches("cppcms%::http%::response%::set_header%") and qn = "cppcms::http::response::set_header" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("cppcms::http", "response") and
    memberFunc.getName() = "set_header" and
    qn = "cppcms::http::response::set_header"
  ) or
  target.getQualifiedName().matches("cppcms%::http%::response%::add_header%") and qn = "cppcms::http::response::add_header" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("cppcms::http", "response") and
    memberFunc.getName() = "add_header" and
    qn = "cppcms::http::response::add_header"
  ) or
  target.getQualifiedName().matches("cppcms%::http%::response%::out%") and qn = "cppcms::http::response::out" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("cppcms::http", "response") and
    memberFunc.getName() = "out" and
    qn = "cppcms::http::response::out"
  ) or
  target.getQualifiedName().matches("cppcms%::http%::response%::operator<<%") and qn = "cppcms::http::response::operator<<" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("cppcms::http", "response") and
    memberFunc.getName() = "operator<<" and
    qn = "cppcms::http::response::operator<<"
  ) or
  target.getQualifiedName().matches("cppcms%::http%::response%::write%") and qn = "cppcms::http::response::write" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("cppcms::http", "response") and
    memberFunc.getName() = "write" and
    qn = "cppcms::http::response::write"
  ) or
  target.getQualifiedName().matches("cppcms%::http%::context%::response%") and qn = "cppcms::http::context::response" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("cppcms::http", "context") and
    memberFunc.getName() = "response" and
    qn = "cppcms::http::context::response"
  ) or
  target.getQualifiedName().matches("cppcms%::http%::context%::write%") and qn = "cppcms::http::context::write" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("cppcms::http", "context") and
    memberFunc.getName() = "write" and
    qn = "cppcms::http::context::write"
  ) or
  target.getQualifiedName().matches("cppcms%::http%::context%::operator<<%") and qn = "cppcms::http::context::operator<<" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("cppcms::http", "context") and
    memberFunc.getName() = "operator<<" and
    qn = "cppcms::http::context::operator<<"
  ) or
  target.getQualifiedName().matches("cppcms%::application%::response%") and qn = "cppcms::application::response" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("cppcms", "application") and
    memberFunc.getName() = "response" and
    qn = "cppcms::application::response"
  ) or
  target.getQualifiedName().matches("cppcms%::application%::write%") and qn = "cppcms::application::write" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("cppcms", "application") and
    memberFunc.getName() = "write" and
    qn = "cppcms::application::write"
  ) or
  target.getQualifiedName().matches("cppcms%::application%::operator<<%") and qn = "cppcms::application::operator<<" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("cppcms", "application") and
    memberFunc.getName() = "operator<<" and
    qn = "cppcms::application::operator<<"
  ) or
  target.getQualifiedName().matches("cppcms%::application%::out%") and qn = "cppcms::application::out" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("cppcms", "application") and
    memberFunc.getName() = "out" and
    qn = "cppcms::application::out"
  ) or
  target.getQualifiedName().matches("served%::response%::set_header%") and qn = "served::response::set_header" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("served", "response") and
    memberFunc.getName() = "set_header" and
    qn = "served::response::set_header"
  ) or
  target.getQualifiedName().matches("served%::response%::set_status%") and qn = "served::response::set_status" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("served", "response") and
    memberFunc.getName() = "set_status" and
    qn = "served::response::set_status"
  ) or
  target.getQualifiedName().matches("served%::response%::redirect%") and qn = "served::response::redirect" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("served", "response") and
    memberFunc.getName() = "redirect" and
    qn = "served::response::redirect"
  ) or
  target.getQualifiedName().matches("served%::response%::write%") and qn = "served::response::write" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("served", "response") and
    memberFunc.getName() = "write" and
    qn = "served::response::write"
  ) or
  target.getQualifiedName().matches("served%::response%::flush%") and qn = "served::response::flush" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("served", "response") and
    memberFunc.getName() = "flush" and
    qn = "served::response::flush"
  ) or
  target.getQualifiedName().matches("served%::response%::operator<<%") and qn = "served::response::operator<<" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("served", "response") and
    memberFunc.getName() = "operator<<" and
    qn = "served::response::operator<<"
  ) or
  target.getQualifiedName().matches("served%::response%::set_body%") and qn = "served::response::set_body" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("served", "response") and
    memberFunc.getName() = "set_body" and
    qn = "served::response::set_body"
  ) or
  target.getQualifiedName().matches("restinio%::response_builder_t%::append_header%") and qn = "restinio::response_builder_t::append_header" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("restinio", "response_builder_t") and
    memberFunc.getName() = "append_header" and
    qn = "restinio::response_builder_t::append_header"
  ) or
  target.getQualifiedName().matches("restinio%::response_builder_t%::append_body%") and qn = "restinio::response_builder_t::append_body" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("restinio", "response_builder_t") and
    memberFunc.getName() = "append_body" and
    qn = "restinio::response_builder_t::append_body"
  ) or
  target.getQualifiedName().matches("restinio%::response_builder_t%::set_body%") and qn = "restinio::response_builder_t::set_body" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("restinio", "response_builder_t") and
    memberFunc.getName() = "set_body" and
    qn = "restinio::response_builder_t::set_body"
  ) or
  target.getQualifiedName().matches("restinio%::response_builder_t%::done%") and qn = "restinio::response_builder_t::done" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("restinio", "response_builder_t") and
    memberFunc.getName() = "done" and
    qn = "restinio::response_builder_t::done"
  ) or
  target.getQualifiedName().matches("drogon%::HttpResponse%::setHeader%") and qn = "drogon::HttpResponse::setHeader" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("drogon", "HttpResponse") and
    memberFunc.getName() = "setHeader" and
    qn = "drogon::HttpResponse::setHeader"
  ) or
  target.getQualifiedName().matches("drogon%::HttpResponse%::setStatusCode%") and qn = "drogon::HttpResponse::setStatusCode" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("drogon", "HttpResponse") and
    memberFunc.getName() = "setStatusCode" and
    qn = "drogon::HttpResponse::setStatusCode"
  ) or
  target.getQualifiedName().matches("drogon%::HttpResponse%::setContentTypeCode%") and qn = "drogon::HttpResponse::setContentTypeCode" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("drogon", "HttpResponse") and
    memberFunc.getName() = "setContentTypeCode" and
    qn = "drogon::HttpResponse::setContentTypeCode"
  ) or
  target.getQualifiedName().matches("drogon%::HttpResponse%::setBody%") and qn = "drogon::HttpResponse::setBody" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("drogon", "HttpResponse") and
    memberFunc.getName() = "setBody" and
    qn = "drogon::HttpResponse::setBody"
  ) or
  target.getQualifiedName().matches("drogon%::HttpResponse%::redirect%") and qn = "drogon::HttpResponse::redirect" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("drogon", "HttpResponse") and
    memberFunc.getName() = "redirect" and
    qn = "drogon::HttpResponse::redirect"
  ) or
  target.getQualifiedName().matches("drogon%::HttpResponse%::newHttpResponse%") and qn = "drogon::HttpResponse::newHttpResponse" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("drogon", "HttpResponse") and
    memberFunc.getName() = "newHttpResponse" and
    qn = "drogon::HttpResponse::newHttpResponse"
  ) or
  target.getQualifiedName().matches("drogon%::HttpResponse%::newHttpViewResponse%") and qn = "drogon::HttpResponse::newHttpViewResponse" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("drogon", "HttpResponse") and
    memberFunc.getName() = "newHttpViewResponse" and
    qn = "drogon::HttpResponse::newHttpViewResponse"
  ) or
  target.getQualifiedName().matches("oatpp%::web%::protocol%::http%::outgoing%::Response%::putHeader%") and qn = "oatpp::web::protocol::http::outgoing::Response::putHeader" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("oatpp::web::protocol::http::outgoing", "Response") and
    memberFunc.getName() = "putHeader" and
    qn = "oatpp::web::protocol::http::outgoing::Response::putHeader"
  ) or
  target.getQualifiedName().matches("oatpp%::web%::protocol%::http%::outgoing%::Response%::writeBody%") and qn = "oatpp::web::protocol::http::outgoing::Response::writeBody" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("oatpp::web::protocol::http::outgoing", "Response") and
    memberFunc.getName() = "writeBody" and
    qn = "oatpp::web::protocol::http::outgoing::Response::writeBody"
  ) or
  target.getQualifiedName().matches("oatpp%::web%::protocol%::http%::outgoing%::ResponseFactory%::createResponse%") and qn = "oatpp::web::protocol::http::outgoing::ResponseFactory::createResponse" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("oatpp::web::protocol::http::outgoing", "ResponseFactory") and
    memberFunc.getName() = "createResponse" and
    qn = "oatpp::web::protocol::http::outgoing::ResponseFactory::createResponse"
  ) or
  target.getQualifiedName().matches("cpprestsdk%::http_response%::set_header%") and qn = "cpprestsdk::http_response::set_header" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("cpprestsdk", "http_response") and
    memberFunc.getName() = "set_header" and
    qn = "cpprestsdk::http_response::set_header"
  ) or
  target.getQualifiedName().matches("cpprestsdk%::http_response%::set_status_code%") and qn = "cpprestsdk::http_response::set_status_code" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("cpprestsdk", "http_response") and
    memberFunc.getName() = "set_status_code" and
    qn = "cpprestsdk::http_response::set_status_code"
  ) or
  target.getQualifiedName().matches("cpprestsdk%::http_response%::set_reason_phrase%") and qn = "cpprestsdk::http_response::set_reason_phrase" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("cpprestsdk", "http_response") and
    memberFunc.getName() = "set_reason_phrase" and
    qn = "cpprestsdk::http_response::set_reason_phrase"
  ) or
  target.getQualifiedName().matches("cpprestsdk%::http_response%::set_content_type%") and qn = "cpprestsdk::http_response::set_content_type" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("cpprestsdk", "http_response") and
    memberFunc.getName() = "set_content_type" and
    qn = "cpprestsdk::http_response::set_content_type"
  ) or
  target.getQualifiedName().matches("cpprestsdk%::http_response%::set_body%") and qn = "cpprestsdk::http_response::set_body" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("cpprestsdk", "http_response") and
    memberFunc.getName() = "set_body" and
    qn = "cpprestsdk::http_response::set_body"
  ) or
  target.getQualifiedName().matches("cpprestsdk%::http_response%::operator<<%") and qn = "cpprestsdk::http_response::operator<<" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("cpprestsdk", "http_response") and
    memberFunc.getName() = "operator<<" and
    qn = "cpprestsdk::http_response::operator<<"
  ) or
  target.getQualifiedName().matches("fcgi%::FCGX_FPrintF%") and qn = "fcgi::FCGX_FPrintF" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "fcgi") and
    memberFunc.getName() = "FCGX_FPrintF" and
    qn = "fcgi::FCGX_FPrintF"
  ) or
  target.getQualifiedName().matches("fcgi%::FCGX_VFPrintF%") and qn = "fcgi::FCGX_VFPrintF" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "fcgi") and
    memberFunc.getName() = "FCGX_VFPrintF" and
    qn = "fcgi::FCGX_VFPrintF"
  ) or
  target.getQualifiedName().matches("fcgi%::FCGX_PutStr%") and qn = "fcgi::FCGX_PutStr" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "fcgi") and
    memberFunc.getName() = "FCGX_PutStr" and
    qn = "fcgi::FCGX_PutStr"
  ) or
  target.getQualifiedName().matches("fcgi%::FCGX_PutS%") and qn = "fcgi::FCGX_PutS" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "fcgi") and
    memberFunc.getName() = "FCGX_PutS" and
    qn = "fcgi::FCGX_PutS"
  ) or
  target.getQualifiedName().matches("Wt%::Http%::Response%::addHeader%") and qn = "Wt::Http::Response::addHeader" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Wt::Http", "Response") and
    memberFunc.getName() = "addHeader" and
    qn = "Wt::Http::Response::addHeader"
  ) or
  target.getQualifiedName().matches("Wt%::Http%::Response%::setHeader%") and qn = "Wt::Http::Response::setHeader" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Wt::Http", "Response") and
    memberFunc.getName() = "setHeader" and
    qn = "Wt::Http::Response::setHeader"
  ) or
  target.getQualifiedName().matches("Wt%::Http%::Response%::setStatus%") and qn = "Wt::Http::Response::setStatus" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Wt::Http", "Response") and
    memberFunc.getName() = "setStatus" and
    qn = "Wt::Http::Response::setStatus"
  ) or
  target.getQualifiedName().matches("Wt%::Http%::Response%::setMimeType%") and qn = "Wt::Http::Response::setMimeType" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Wt::Http", "Response") and
    memberFunc.getName() = "setMimeType" and
    qn = "Wt::Http::Response::setMimeType"
  ) or
  target.getQualifiedName().matches("Wt%::Http%::Response%::setContentType%") and qn = "Wt::Http::Response::setContentType" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Wt::Http", "Response") and
    memberFunc.getName() = "setContentType" and
    qn = "Wt::Http::Response::setContentType"
  ) or
  target.getQualifiedName().matches("Wt%::Http%::Response%::setContentLength%") and qn = "Wt::Http::Response::setContentLength" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Wt::Http", "Response") and
    memberFunc.getName() = "setContentLength" and
    qn = "Wt::Http::Response::setContentLength"
  ) or
  target.getQualifiedName().matches("Wt%::Http%::Response%::out%") and qn = "Wt::Http::Response::out" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Wt::Http", "Response") and
    memberFunc.getName() = "out" and
    qn = "Wt::Http::Response::out"
  ) or
  target.getQualifiedName().matches("Wt%::Http%::Response%::outstream%") and qn = "Wt::Http::Response::outstream" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Wt::Http", "Response") and
    memberFunc.getName() = "outstream" and
    qn = "Wt::Http::Response::outstream"
  ) or
  target.getQualifiedName().matches("Wt%::Http%::Response%::redirect%") and qn = "Wt::Http::Response::redirect" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Wt::Http", "Response") and
    memberFunc.getName() = "redirect" and
    qn = "Wt::Http::Response::redirect"
  ) or
  target.getQualifiedName().matches("Wt%::Http%::Response%::setRedirect%") and qn = "Wt::Http::Response::setRedirect" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Wt::Http", "Response") and
    memberFunc.getName() = "setRedirect" and
    qn = "Wt::Http::Response::setRedirect"
  ) or
  target.getQualifiedName().matches("Wt%::WApplication%::doJavaScript%") and qn = "Wt::WApplication::doJavaScript" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Wt", "WApplication") and
    memberFunc.getName() = "doJavaScript" and
    qn = "Wt::WApplication::doJavaScript"
  ) or
  target.getQualifiedName().matches("Wt%::WApplication%::setTitle%") and qn = "Wt::WApplication::setTitle" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Wt", "WApplication") and
    memberFunc.getName() = "setTitle" and
    qn = "Wt::WApplication::setTitle"
  ) or
  target.getQualifiedName().matches("Wt%::WTemplate%::bindString%") and qn = "Wt::WTemplate::bindString" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Wt", "WTemplate") and
    memberFunc.getName() = "bindString" and
    qn = "Wt::WTemplate::bindString"
  ) or
  target.getQualifiedName().matches("Wt%::WTemplate%::render%") and qn = "Wt::WTemplate::render" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Wt", "WTemplate") and
    memberFunc.getName() = "render" and
    qn = "Wt::WTemplate::render"
  ) or
  target.getQualifiedName().matches("Wt%::WTemplate%::setTemplateText%") and qn = "Wt::WTemplate::setTemplateText" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Wt", "WTemplate") and
    memberFunc.getName() = "setTemplateText" and
    qn = "Wt::WTemplate::setTemplateText"
  ) or
  target.getQualifiedName().matches("Wt%::WTemplate%::bindWidget%") and qn = "Wt::WTemplate::bindWidget" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Wt", "WTemplate") and
    memberFunc.getName() = "bindWidget" and
    qn = "Wt::WTemplate::bindWidget"
  ) or
  target.getQualifiedName().matches("Wt%::WContainerWidget%::addNew%") and qn = "Wt::WContainerWidget::addNew" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Wt", "WContainerWidget") and
    memberFunc.getName() = "addNew" and
    qn = "Wt::WContainerWidget::addNew"
  ) or
  target.getQualifiedName().matches("Wt%::WContainerWidget%::addWidget%") and qn = "Wt::WContainerWidget::addWidget" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Wt", "WContainerWidget") and
    memberFunc.getName() = "addWidget" and
    qn = "Wt::WContainerWidget::addWidget"
  ) or
  target.getQualifiedName().matches("Wt%::WLabel%::setText%") and qn = "Wt::WLabel::setText" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Wt", "WLabel") and
    memberFunc.getName() = "setText" and
    qn = "Wt::WLabel::setText"
  ) or
  target.getQualifiedName().matches("Wt%::WText%::setText%") and qn = "Wt::WText::setText" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Wt", "WText") and
    memberFunc.getName() = "setText" and
    qn = "Wt::WText::setText"
  ) or
  target.getQualifiedName().matches("Wt%::WTextArea%::setText%") and qn = "Wt::WTextArea::setText" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Wt", "WTextArea") and
    memberFunc.getName() = "setText" and
    qn = "Wt::WTextArea::setText"
  ) or
  target.getQualifiedName().matches("QNetworkReply%::setRawHeader%") and qn = "QNetworkReply::setRawHeader" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QNetworkReply") and
    memberFunc.getName() = "setRawHeader" and
    qn = "QNetworkReply::setRawHeader"
  ) or
  target.getQualifiedName().matches("QNetworkReply%::write%") and qn = "QNetworkReply::write" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QNetworkReply") and
    memberFunc.getName() = "write" and
    qn = "QNetworkReply::write"
  ) or
  target.getQualifiedName().matches("QNetworkAccessManager%::post%") and qn = "QNetworkAccessManager::post" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QNetworkAccessManager") and
    memberFunc.getName() = "post" and
    qn = "QNetworkAccessManager::post"
  ) or
  target.getQualifiedName().matches("QNetworkAccessManager%::put%") and qn = "QNetworkAccessManager::put" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QNetworkAccessManager") and
    memberFunc.getName() = "put" and
    qn = "QNetworkAccessManager::put"
  ) or
  target.getQualifiedName().matches("QNetworkAccessManager%::sendCustomRequest%") and qn = "QNetworkAccessManager::sendCustomRequest" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QNetworkAccessManager") and
    memberFunc.getName() = "sendCustomRequest" and
    qn = "QNetworkAccessManager::sendCustomRequest"
  ) or
  target.getQualifiedName().matches("QHttpResponseHeader%::setValue%") and qn = "QHttpResponseHeader::setValue" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QHttpResponseHeader") and
    memberFunc.getName() = "setValue" and
    qn = "QHttpResponseHeader::setValue"
  ) or
  target.getQualifiedName().matches("QHttpResponseHeader%::toString%") and qn = "QHttpResponseHeader::toString" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QHttpResponseHeader") and
    memberFunc.getName() = "toString" and
    qn = "QHttpResponseHeader::toString"
  ) or
  target.getQualifiedName().matches("QHttpResponseHeader%::addValue%") and qn = "QHttpResponseHeader::addValue" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QHttpResponseHeader") and
    memberFunc.getName() = "addValue" and
    qn = "QHttpResponseHeader::addValue"
  ) or
  target.getQualifiedName().matches("QWebEngineView%::setHtml%") and qn = "QWebEngineView::setHtml" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QWebEngineView") and
    memberFunc.getName() = "setHtml" and
    qn = "QWebEngineView::setHtml"
  ) or
  target.getQualifiedName().matches("QWebEnginePage%::setContent%") and qn = "QWebEnginePage::setContent" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QWebEnginePage") and
    memberFunc.getName() = "setContent" and
    qn = "QWebEnginePage::setContent"
  ) or
  target.getQualifiedName().matches("QWebEnginePage%::setHtml%") and qn = "QWebEnginePage::setHtml" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QWebEnginePage") and
    memberFunc.getName() = "setHtml" and
    qn = "QWebEnginePage::setHtml"
  ) or
  target.getQualifiedName().matches("QWebView%::setHtml%") and qn = "QWebView::setHtml" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QWebView") and
    memberFunc.getName() = "setHtml" and
    qn = "QWebView::setHtml"
  ) or
  target.getQualifiedName().matches("QWebView%::setContent%") and qn = "QWebView::setContent" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QWebView") and
    memberFunc.getName() = "setContent" and
    qn = "QWebView::setContent"
  ) or
  target.getQualifiedName().matches("QWebFrame%::setHtml%") and qn = "QWebFrame::setHtml" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QWebFrame") and
    memberFunc.getName() = "setHtml" and
    qn = "QWebFrame::setHtml"
  ) or
  target.getQualifiedName().matches("QWebFrame%::setContent%") and qn = "QWebFrame::setContent" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QWebFrame") and
    memberFunc.getName() = "setContent" and
    qn = "QWebFrame::setContent"
  ) or
  target.getQualifiedName().matches("Wt%::WWebWidget%::setAttributeValue%") and qn = "Wt::WWebWidget::setAttributeValue" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Wt", "WWebWidget") and
    memberFunc.getName() = "setAttributeValue" and
    qn = "Wt::WWebWidget::setAttributeValue"
  ) or
  target.getQualifiedName().matches("Wt%::WWebWidget%::setAttribute%") and qn = "Wt::WWebWidget::setAttribute" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Wt", "WWebWidget") and
    memberFunc.getName() = "setAttribute" and
    qn = "Wt::WWebWidget::setAttribute"
  ) or
  target.getQualifiedName().matches("Wt%::WWidget%::setToolTip%") and qn = "Wt::WWidget::setToolTip" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Wt", "WWidget") and
    memberFunc.getName() = "setToolTip" and
    qn = "Wt::WWidget::setToolTip"
  ) or
  target.getQualifiedName().matches("Wt%::WWidget%::setStyleClass%") and qn = "Wt::WWidget::setStyleClass" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Wt", "WWidget") and
    memberFunc.getName() = "setStyleClass" and
    qn = "Wt::WWidget::setStyleClass"
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
