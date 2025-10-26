// Auto-generated; CWE-117; number of APIs 115
import cpp

predicate isTargetApi(Function target, string qn) {
  target.getQualifiedName().matches("syslog%") and qn = "syslog" or
  target.getQualifiedName().matches("vsyslog%") and qn = "vsyslog" or
  target.getQualifiedName().matches("openlog%") and qn = "openlog" or
  target.getQualifiedName().matches("closelog%") and qn = "closelog" or
  target.getQualifiedName().matches("setlogmask%") and qn = "setlogmask" or
  target.getQualifiedName().matches("journal_send%") and qn = "journal_send" or
  target.getQualifiedName().matches("sd_journal_send%") and qn = "sd_journal_send" or
  target.getQualifiedName().matches("__android_log_print%") and qn = "__android_log_print" or
  target.getQualifiedName().matches("__android_log_write%") and qn = "__android_log_write" or
  target.getQualifiedName().matches("android_log_vprint%") and qn = "android_log_vprint" or
  target.getQualifiedName().matches("ReportEventA%") and qn = "ReportEventA" or
  target.getQualifiedName().matches("ReportEventW%") and qn = "ReportEventW" or
  target.getQualifiedName().matches("EventWrite%") and qn = "EventWrite" or
  target.getQualifiedName().matches("EventRegister%") and qn = "EventRegister" or
  target.getQualifiedName().matches("OutputDebugStringA%") and qn = "OutputDebugStringA" or
  target.getQualifiedName().matches("OutputDebugStringW%") and qn = "OutputDebugStringW" or
  target.getQualifiedName().matches("ap_log_error%") and qn = "ap_log_error" or
  target.getQualifiedName().matches("ap_log_rerror%") and qn = "ap_log_rerror" or
  target.getQualifiedName().matches("ngx_log_error%") and qn = "ngx_log_error" or
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
  target.getQualifiedName().matches("spdlog%::critical%") and qn = "spdlog::critical" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "spdlog") and
    memberFunc.getName() = "critical" and
    qn = "spdlog::critical"
  ) or
  target.getQualifiedName().matches("spdlog%::trace%") and qn = "spdlog::trace" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "spdlog") and
    memberFunc.getName() = "trace" and
    qn = "spdlog::trace"
  ) or
  target.getQualifiedName().matches("glog%::LOG%") and qn = "glog::LOG" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "glog") and
    memberFunc.getName() = "LOG" and
    qn = "glog::LOG"
  ) or
  target.getQualifiedName().matches("glog%::LOG_IF%") and qn = "glog::LOG_IF" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "glog") and
    memberFunc.getName() = "LOG_IF" and
    qn = "glog::LOG_IF"
  ) or
  target.getQualifiedName().matches("glog%::DLOG%") and qn = "glog::DLOG" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "glog") and
    memberFunc.getName() = "DLOG" and
    qn = "glog::DLOG"
  ) or
  target.getQualifiedName().matches("boost%::log%::trivial%::trace%") and qn = "boost::log::trivial::trace" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost::log", "trivial") and
    memberFunc.getName() = "trace" and
    qn = "boost::log::trivial::trace"
  ) or
  target.getQualifiedName().matches("boost%::log%::trivial%::debug%") and qn = "boost::log::trivial::debug" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost::log", "trivial") and
    memberFunc.getName() = "debug" and
    qn = "boost::log::trivial::debug"
  ) or
  target.getQualifiedName().matches("boost%::log%::trivial%::info%") and qn = "boost::log::trivial::info" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost::log", "trivial") and
    memberFunc.getName() = "info" and
    qn = "boost::log::trivial::info"
  ) or
  target.getQualifiedName().matches("boost%::log%::trivial%::warning%") and qn = "boost::log::trivial::warning" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost::log", "trivial") and
    memberFunc.getName() = "warning" and
    qn = "boost::log::trivial::warning"
  ) or
  target.getQualifiedName().matches("boost%::log%::trivial%::error%") and qn = "boost::log::trivial::error" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost::log", "trivial") and
    memberFunc.getName() = "error" and
    qn = "boost::log::trivial::error"
  ) or
  target.getQualifiedName().matches("boost%::log%::trivial%::fatal%") and qn = "boost::log::trivial::fatal" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost::log", "trivial") and
    memberFunc.getName() = "fatal" and
    qn = "boost::log::trivial::fatal"
  ) or
  target.getQualifiedName().matches("boost%::log%::core%::get%") and qn = "boost::log::core::get" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost::log", "core") and
    memberFunc.getName() = "get" and
    qn = "boost::log::core::get"
  ) or
  target.getQualifiedName().matches("boost%::log%::expressions%::format%") and qn = "boost::log::expressions::format" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost::log", "expressions") and
    memberFunc.getName() = "format" and
    qn = "boost::log::expressions::format"
  ) or
  target.getQualifiedName().matches("log4cplus%::Logger%::trace%") and qn = "log4cplus::Logger::trace" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("log4cplus", "Logger") and
    memberFunc.getName() = "trace" and
    qn = "log4cplus::Logger::trace"
  ) or
  target.getQualifiedName().matches("log4cplus%::Logger%::debug%") and qn = "log4cplus::Logger::debug" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("log4cplus", "Logger") and
    memberFunc.getName() = "debug" and
    qn = "log4cplus::Logger::debug"
  ) or
  target.getQualifiedName().matches("log4cplus%::Logger%::info%") and qn = "log4cplus::Logger::info" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("log4cplus", "Logger") and
    memberFunc.getName() = "info" and
    qn = "log4cplus::Logger::info"
  ) or
  target.getQualifiedName().matches("log4cplus%::Logger%::warn%") and qn = "log4cplus::Logger::warn" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("log4cplus", "Logger") and
    memberFunc.getName() = "warn" and
    qn = "log4cplus::Logger::warn"
  ) or
  target.getQualifiedName().matches("log4cplus%::Logger%::error%") and qn = "log4cplus::Logger::error" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("log4cplus", "Logger") and
    memberFunc.getName() = "error" and
    qn = "log4cplus::Logger::error"
  ) or
  target.getQualifiedName().matches("log4cplus%::Logger%::fatal%") and qn = "log4cplus::Logger::fatal" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("log4cplus", "Logger") and
    memberFunc.getName() = "fatal" and
    qn = "log4cplus::Logger::fatal"
  ) or
  target.getQualifiedName().matches("log4cpp%::Category%::trace%") and qn = "log4cpp::Category::trace" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("log4cpp", "Category") and
    memberFunc.getName() = "trace" and
    qn = "log4cpp::Category::trace"
  ) or
  target.getQualifiedName().matches("log4cpp%::Category%::debug%") and qn = "log4cpp::Category::debug" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("log4cpp", "Category") and
    memberFunc.getName() = "debug" and
    qn = "log4cpp::Category::debug"
  ) or
  target.getQualifiedName().matches("log4cpp%::Category%::info%") and qn = "log4cpp::Category::info" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("log4cpp", "Category") and
    memberFunc.getName() = "info" and
    qn = "log4cpp::Category::info"
  ) or
  target.getQualifiedName().matches("log4cpp%::Category%::warn%") and qn = "log4cpp::Category::warn" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("log4cpp", "Category") and
    memberFunc.getName() = "warn" and
    qn = "log4cpp::Category::warn"
  ) or
  target.getQualifiedName().matches("log4cpp%::Category%::error%") and qn = "log4cpp::Category::error" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("log4cpp", "Category") and
    memberFunc.getName() = "error" and
    qn = "log4cpp::Category::error"
  ) or
  target.getQualifiedName().matches("log4cpp%::Category%::fatal%") and qn = "log4cpp::Category::fatal" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("log4cpp", "Category") and
    memberFunc.getName() = "fatal" and
    qn = "log4cpp::Category::fatal"
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
  target.getQualifiedName().matches("Poco%::Logger%::critical%") and qn = "Poco::Logger::critical" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Poco", "Logger") and
    memberFunc.getName() = "critical" and
    qn = "Poco::Logger::critical"
  ) or
  target.getQualifiedName().matches("syslog%::log%") and qn = "syslog::log" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "syslog") and
    memberFunc.getName() = "log" and
    qn = "syslog::log"
  ) or
  target.getQualifiedName().matches("spdlog%::logger%::log%") and qn = "spdlog::logger::log" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("spdlog", "logger") and
    memberFunc.getName() = "log" and
    qn = "spdlog::logger::log"
  ) or
  target.getQualifiedName().matches("boost%::log%::sources%::severity_logger%") and qn = "boost::log::sources::severity_logger" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost::log", "sources") and
    memberFunc.getName() = "severity_logger" and
    qn = "boost::log::sources::severity_logger"
  ) or
  target.getQualifiedName().matches("boost%::log%::sources%::logger%") and qn = "boost::log::sources::logger" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost::log", "sources") and
    memberFunc.getName() = "logger" and
    qn = "boost::log::sources::logger"
  ) or
  target.getQualifiedName().matches("g_log%") and qn = "g_log" or
  target.getQualifiedName().matches("g_logv%") and qn = "g_logv" or
  target.getQualifiedName().matches("g_set_prgname%") and qn = "g_set_prgname" or
  target.getQualifiedName().matches("g_set_print_handler%") and qn = "g_set_print_handler" or
  target.getQualifiedName().matches("wxLog%::Message%") and qn = "wxLog::Message" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "wxLog") and
    memberFunc.getName() = "Message" and
    qn = "wxLog::Message"
  ) or
  target.getQualifiedName().matches("wxLogError%") and qn = "wxLogError" or
  target.getQualifiedName().matches("wxLogWarning%") and qn = "wxLogWarning" or
  target.getQualifiedName().matches("wxLogInfo%") and qn = "wxLogInfo" or
  target.getQualifiedName().matches("QLoggingCategory%::debug%") and qn = "QLoggingCategory::debug" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QLoggingCategory") and
    memberFunc.getName() = "debug" and
    qn = "QLoggingCategory::debug"
  ) or
  target.getQualifiedName().matches("QLoggingCategory%::warning%") and qn = "QLoggingCategory::warning" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QLoggingCategory") and
    memberFunc.getName() = "warning" and
    qn = "QLoggingCategory::warning"
  ) or
  target.getQualifiedName().matches("QLoggingCategory%::critical%") and qn = "QLoggingCategory::critical" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QLoggingCategory") and
    memberFunc.getName() = "critical" and
    qn = "QLoggingCategory::critical"
  ) or
  target.getQualifiedName().matches("QDebug%::nospace%") and qn = "QDebug::nospace" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QDebug") and
    memberFunc.getName() = "nospace" and
    qn = "QDebug::nospace"
  ) or
  target.getQualifiedName().matches("QDebug%::space%") and qn = "QDebug::space" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QDebug") and
    memberFunc.getName() = "space" and
    qn = "QDebug::space"
  ) or
  target.getQualifiedName().matches("QDebug%::operator<<%") and qn = "QDebug::operator<<" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QDebug") and
    memberFunc.getName() = "operator<<" and
    qn = "QDebug::operator<<"
  ) or
  target.getQualifiedName().matches("std%::clog%") and qn = "std::clog" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "std") and
    memberFunc.getName() = "clog" and
    qn = "std::clog"
  ) or
  target.getQualifiedName().matches("std%::cerr%") and qn = "std::cerr" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "std") and
    memberFunc.getName() = "cerr" and
    qn = "std::cerr"
  ) or
  target.getQualifiedName().matches("std%::cout%") and qn = "std::cout" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "std") and
    memberFunc.getName() = "cout" and
    qn = "std::cout"
  ) or
  target.getQualifiedName().matches("std%::ostringstream%::str%") and qn = "std::ostringstream::str" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "ostringstream") and
    memberFunc.getName() = "str" and
    qn = "std::ostringstream::str"
  ) or
  target.getQualifiedName().matches("std%::ostringstream%::operator<<%") and qn = "std::ostringstream::operator<<" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "ostringstream") and
    memberFunc.getName() = "operator<<" and
    qn = "std::ostringstream::operator<<"
  ) or
  target.getQualifiedName().matches("std%::ofstream%::write%") and qn = "std::ofstream::write" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "ofstream") and
    memberFunc.getName() = "write" and
    qn = "std::ofstream::write"
  ) or
  target.getQualifiedName().matches("std%::ofstream%::operator<<%") and qn = "std::ofstream::operator<<" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "ofstream") and
    memberFunc.getName() = "operator<<" and
    qn = "std::ofstream::operator<<"
  ) or
  target.getQualifiedName().matches("fprintf%") and qn = "fprintf" or
  target.getQualifiedName().matches("vfprintf%") and qn = "vfprintf" or
  target.getQualifiedName().matches("fwrite%") and qn = "fwrite" or
  target.getQualifiedName().matches("fputs%") and qn = "fputs" or
  target.getQualifiedName().matches("puts%") and qn = "puts" or
  target.getQualifiedName().matches("write%") and qn = "write" or
  target.getQualifiedName().matches("dprintf%") and qn = "dprintf" or
  target.getQualifiedName().matches("vsnprintf%") and qn = "vsnprintf" or
  target.getQualifiedName().matches("snprintf%") and qn = "snprintf" or
  target.getQualifiedName().matches("vsprintf%") and qn = "vsprintf" or
  target.getQualifiedName().matches("sprintf%") and qn = "sprintf" or
  target.getQualifiedName().matches("syslog%::openlog%") and qn = "syslog::openlog" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "syslog") and
    memberFunc.getName() = "openlog" and
    qn = "syslog::openlog"
  ) or
  target.getQualifiedName().matches("android%::base%::LogMessage%") and qn = "android::base::LogMessage" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("android", "base") and
    memberFunc.getName() = "LogMessage" and
    qn = "android::base::LogMessage"
  ) or
  target.getQualifiedName().matches("android%::base%::Logd%") and qn = "android::base::Logd" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("android", "base") and
    memberFunc.getName() = "Logd" and
    qn = "android::base::Logd"
  ) or
  target.getQualifiedName().matches("apache%::log_error%") and qn = "apache::log_error" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "apache") and
    memberFunc.getName() = "log_error" and
    qn = "apache::log_error"
  ) or
  target.getQualifiedName().matches("apache%::ap_log_error%") and qn = "apache::ap_log_error" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "apache") and
    memberFunc.getName() = "ap_log_error" and
    qn = "apache::ap_log_error"
  ) or
  target.getQualifiedName().matches("nginx%::ngx_log_error%") and qn = "nginx::ngx_log_error" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "nginx") and
    memberFunc.getName() = "ngx_log_error" and
    qn = "nginx::ngx_log_error"
  ) or
  target.getQualifiedName().matches("mongrel2_log%") and qn = "mongrel2_log" or
  target.getQualifiedName().matches("uwsgi_log%") and qn = "uwsgi_log" or
  target.getQualifiedName().matches("rsyslog_send%") and qn = "rsyslog_send" or
  target.getQualifiedName().matches("journald_send%") and qn = "journald_send" or
  target.getQualifiedName().matches("spdlog%::sinks%::sink%::log%") and qn = "spdlog::sinks::sink::log" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("spdlog::sinks", "sink") and
    memberFunc.getName() = "log" and
    qn = "spdlog::sinks::sink::log"
  ) or
  target.getQualifiedName().matches("boost%::log%::sinks%::text_ostream_backend%::consume%") and qn = "boost::log::sinks::text_ostream_backend::consume" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost::log::sinks", "text_ostream_backend") and
    memberFunc.getName() = "consume" and
    qn = "boost::log::sinks::text_ostream_backend::consume"
  ) or
  target.getQualifiedName().matches("boost%::log%::sinks%::syslog_backend%::consume%") and qn = "boost::log::sinks::syslog_backend::consume" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost::log::sinks", "syslog_backend") and
    memberFunc.getName() = "consume" and
    qn = "boost::log::sinks::syslog_backend::consume"
  ) or
  target.getQualifiedName().matches("log4cplus%::helpers%::LogLog%::debug%") and qn = "log4cplus::helpers::LogLog::debug" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("log4cplus::helpers", "LogLog") and
    memberFunc.getName() = "debug" and
    qn = "log4cplus::helpers::LogLog::debug"
  ) or
  target.getQualifiedName().matches("log4cplus%::Hierarchy%::log%") and qn = "log4cplus::Hierarchy::log" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("log4cplus", "Hierarchy") and
    memberFunc.getName() = "log" and
    qn = "log4cplus::Hierarchy::log"
  ) or
  target.getQualifiedName().matches("log4cpp%::Appender%::doAppend%") and qn = "log4cpp::Appender::doAppend" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("log4cpp", "Appender") and
    memberFunc.getName() = "doAppend" and
    qn = "log4cpp::Appender::doAppend"
  ) or
  target.getQualifiedName().matches("Poco%::Logging%::Channel%::log%") and qn = "Poco::Logging::Channel::log" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Poco::Logging", "Channel") and
    memberFunc.getName() = "log" and
    qn = "Poco::Logging::Channel::log"
  ) or
  target.getQualifiedName().matches("Poco%::Message%::setText%") and qn = "Poco::Message::setText" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Poco", "Message") and
    memberFunc.getName() = "setText" and
    qn = "Poco::Message::setText"
  ) or
  target.getQualifiedName().matches("Poco%::Logger%::log%") and qn = "Poco::Logger::log" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Poco", "Logger") and
    memberFunc.getName() = "log" and
    qn = "Poco::Logger::log"
  ) or
  target.getQualifiedName().matches("apache_request_log_error%") and qn = "apache_request_log_error" or
  target.getQualifiedName().matches("nginx_error_log%") and qn = "nginx_error_log" or
  target.getQualifiedName().matches("sqlite3_log%") and qn = "sqlite3_log" or
  target.getQualifiedName().matches("spdlog%::sinks%::rotating_file_sink_mt%::sink_it%") and qn = "spdlog::sinks::rotating_file_sink_mt::sink_it" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("spdlog::sinks", "rotating_file_sink_mt") and
    memberFunc.getName() = "sink_it" and
    qn = "spdlog::sinks::rotating_file_sink_mt::sink_it"
  ) or
  target.getQualifiedName().matches("spdlog%::sinks%::daily_file_sink_mt%::sink_it%") and qn = "spdlog::sinks::daily_file_sink_mt::sink_it" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("spdlog::sinks", "daily_file_sink_mt") and
    memberFunc.getName() = "sink_it" and
    qn = "spdlog::sinks::daily_file_sink_mt::sink_it"
  ) or
  target.getQualifiedName().matches("boost%::log%::sinks%::text_file_backend%::consume%") and qn = "boost::log::sinks::text_file_backend::consume" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost::log::sinks", "text_file_backend") and
    memberFunc.getName() = "consume" and
    qn = "boost::log::sinks::text_file_backend::consume"
  ) or
  target.getQualifiedName().matches("boost%::log%::sinks%::asynchronous_sink%::consume%") and qn = "boost::log::sinks::asynchronous_sink::consume" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost::log::sinks", "asynchronous_sink") and
    memberFunc.getName() = "consume" and
    qn = "boost::log::sinks::asynchronous_sink::consume"
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
