// Auto-generated; CWE-943; number of APIs 119
import cpp

predicate isTargetApi(Function target, string qn) {
  target.getQualifiedName().matches("mysql_init%") and qn = "mysql_init" or
  target.getQualifiedName().matches("mysql_real_connect%") and qn = "mysql_real_connect" or
  target.getQualifiedName().matches("mysql_query%") and qn = "mysql_query" or
  target.getQualifiedName().matches("mysql_real_query%") and qn = "mysql_real_query" or
  target.getQualifiedName().matches("mysql_stmt_init%") and qn = "mysql_stmt_init" or
  target.getQualifiedName().matches("mysql_stmt_prepare%") and qn = "mysql_stmt_prepare" or
  target.getQualifiedName().matches("mysql_stmt_bind_param%") and qn = "mysql_stmt_bind_param" or
  target.getQualifiedName().matches("mysql_stmt_bind_result%") and qn = "mysql_stmt_bind_result" or
  target.getQualifiedName().matches("mysql_stmt_execute%") and qn = "mysql_stmt_execute" or
  target.getQualifiedName().matches("mysql_real_escape_string%") and qn = "mysql_real_escape_string" or
  target.getQualifiedName().matches("PQconnectdb%") and qn = "PQconnectdb" or
  target.getQualifiedName().matches("PQexec%") and qn = "PQexec" or
  target.getQualifiedName().matches("PQexecParams%") and qn = "PQexecParams" or
  target.getQualifiedName().matches("PQprepare%") and qn = "PQprepare" or
  target.getQualifiedName().matches("PQexecPrepared%") and qn = "PQexecPrepared" or
  target.getQualifiedName().matches("PQescapeStringConn%") and qn = "PQescapeStringConn" or
  target.getQualifiedName().matches("sqlite3_open%") and qn = "sqlite3_open" or
  target.getQualifiedName().matches("sqlite3_open_v2%") and qn = "sqlite3_open_v2" or
  target.getQualifiedName().matches("sqlite3_exec%") and qn = "sqlite3_exec" or
  target.getQualifiedName().matches("sqlite3_prepare%") and qn = "sqlite3_prepare" or
  target.getQualifiedName().matches("sqlite3_prepare_v2%") and qn = "sqlite3_prepare_v2" or
  target.getQualifiedName().matches("sqlite3_prepare_v3%") and qn = "sqlite3_prepare_v3" or
  target.getQualifiedName().matches("sqlite3_step%") and qn = "sqlite3_step" or
  target.getQualifiedName().matches("sqlite3_finalize%") and qn = "sqlite3_finalize" or
  target.getQualifiedName().matches("sqlite3_bind_parameter_count%") and qn = "sqlite3_bind_parameter_count" or
  target.getQualifiedName().matches("sqlite3_bind_null%") and qn = "sqlite3_bind_null" or
  target.getQualifiedName().matches("sqlite3_bind_int%") and qn = "sqlite3_bind_int" or
  target.getQualifiedName().matches("sqlite3_bind_int64%") and qn = "sqlite3_bind_int64" or
  target.getQualifiedName().matches("sqlite3_bind_double%") and qn = "sqlite3_bind_double" or
  target.getQualifiedName().matches("sqlite3_bind_text%") and qn = "sqlite3_bind_text" or
  target.getQualifiedName().matches("sqlite3_bind_blob%") and qn = "sqlite3_bind_blob" or
  target.getQualifiedName().matches("sqlite3_bind_zeroblob%") and qn = "sqlite3_bind_zeroblob" or
  target.getQualifiedName().matches("SQLAllocHandle%") and qn = "SQLAllocHandle" or
  target.getQualifiedName().matches("SQLDriverConnect%") and qn = "SQLDriverConnect" or
  target.getQualifiedName().matches("SQLConnect%") and qn = "SQLConnect" or
  target.getQualifiedName().matches("SQLPrepare%") and qn = "SQLPrepare" or
  target.getQualifiedName().matches("SQLExecDirect%") and qn = "SQLExecDirect" or
  target.getQualifiedName().matches("SQLExecute%") and qn = "SQLExecute" or
  target.getQualifiedName().matches("SQLBindParameter%") and qn = "SQLBindParameter" or
  target.getQualifiedName().matches("SQLBindCol%") and qn = "SQLBindCol" or
  target.getQualifiedName().matches("SQLSetConnectAttr%") and qn = "SQLSetConnectAttr" or
  target.getQualifiedName().matches("SQLSetStmtAttr%") and qn = "SQLSetStmtAttr" or
  target.getQualifiedName().matches("nanodbc%::execute%") and qn = "nanodbc::execute" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "nanodbc") and
    memberFunc.getName() = "execute" and
    qn = "nanodbc::execute"
  ) or
  target.getQualifiedName().matches("nanodbc%::prepare%") and qn = "nanodbc::prepare" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "nanodbc") and
    memberFunc.getName() = "prepare" and
    qn = "nanodbc::prepare"
  ) or
  target.getQualifiedName().matches("nanodbc%::statement%::execute%") and qn = "nanodbc::statement::execute" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("nanodbc", "statement") and
    memberFunc.getName() = "execute" and
    qn = "nanodbc::statement::execute"
  ) or
  target.getQualifiedName().matches("nanodbc%::statement%::bind%") and qn = "nanodbc::statement::bind" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("nanodbc", "statement") and
    memberFunc.getName() = "bind" and
    qn = "nanodbc::statement::bind"
  ) or
  target.getQualifiedName().matches("nanodbc%::statement%::prepare%") and qn = "nanodbc::statement::prepare" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("nanodbc", "statement") and
    memberFunc.getName() = "prepare" and
    qn = "nanodbc::statement::prepare"
  ) or
  target.getQualifiedName().matches("soci%::session%::operator<<%") and qn = "soci::session::operator<<" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("soci", "session") and
    memberFunc.getName() = "operator<<" and
    qn = "soci::session::operator<<"
  ) or
  target.getQualifiedName().matches("soci%::statement%::operator<<%") and qn = "soci::statement::operator<<" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("soci", "statement") and
    memberFunc.getName() = "operator<<" and
    qn = "soci::statement::operator<<"
  ) or
  target.getQualifiedName().matches("soci%::statement%::prepare%") and qn = "soci::statement::prepare" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("soci", "statement") and
    memberFunc.getName() = "prepare" and
    qn = "soci::statement::prepare"
  ) or
  target.getQualifiedName().matches("soci%::use%") and qn = "soci::use" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "soci") and
    memberFunc.getName() = "use" and
    qn = "soci::use"
  ) or
  target.getQualifiedName().matches("soci%::into%") and qn = "soci::into" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "soci") and
    memberFunc.getName() = "into" and
    qn = "soci::into"
  ) or
  target.getQualifiedName().matches("QSqlDatabase%::addDatabase%") and qn = "QSqlDatabase::addDatabase" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QSqlDatabase") and
    memberFunc.getName() = "addDatabase" and
    qn = "QSqlDatabase::addDatabase"
  ) or
  target.getQualifiedName().matches("QSqlDatabase%::open%") and qn = "QSqlDatabase::open" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QSqlDatabase") and
    memberFunc.getName() = "open" and
    qn = "QSqlDatabase::open"
  ) or
  target.getQualifiedName().matches("QSqlQuery%::exec%") and qn = "QSqlQuery::exec" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QSqlQuery") and
    memberFunc.getName() = "exec" and
    qn = "QSqlQuery::exec"
  ) or
  target.getQualifiedName().matches("QSqlQuery%::prepare%") and qn = "QSqlQuery::prepare" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QSqlQuery") and
    memberFunc.getName() = "prepare" and
    qn = "QSqlQuery::prepare"
  ) or
  target.getQualifiedName().matches("QSqlQuery%::addBindValue%") and qn = "QSqlQuery::addBindValue" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QSqlQuery") and
    memberFunc.getName() = "addBindValue" and
    qn = "QSqlQuery::addBindValue"
  ) or
  target.getQualifiedName().matches("QSqlQuery%::bindValue%") and qn = "QSqlQuery::bindValue" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QSqlQuery") and
    memberFunc.getName() = "bindValue" and
    qn = "QSqlQuery::bindValue"
  ) or
  target.getQualifiedName().matches("QSqlQuery%::execBatch%") and qn = "QSqlQuery::execBatch" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QSqlQuery") and
    memberFunc.getName() = "execBatch" and
    qn = "QSqlQuery::execBatch"
  ) or
  target.getQualifiedName().matches("cppdb%::session%::operator<<%") and qn = "cppdb::session::operator<<" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("cppdb", "session") and
    memberFunc.getName() = "operator<<" and
    qn = "cppdb::session::operator<<"
  ) or
  target.getQualifiedName().matches("cppdb%::statement%::bind%") and qn = "cppdb::statement::bind" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("cppdb", "statement") and
    memberFunc.getName() = "bind" and
    qn = "cppdb::statement::bind"
  ) or
  target.getQualifiedName().matches("cppdb%::statement%::exec%") and qn = "cppdb::statement::exec" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("cppdb", "statement") and
    memberFunc.getName() = "exec" and
    qn = "cppdb::statement::exec"
  ) or
  target.getQualifiedName().matches("cppdb%::statement%::query%") and qn = "cppdb::statement::query" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("cppdb", "statement") and
    memberFunc.getName() = "query" and
    qn = "cppdb::statement::query"
  ) or
  target.getQualifiedName().matches("otl_connect%::rlogon%") and qn = "otl_connect::rlogon" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "otl_connect") and
    memberFunc.getName() = "rlogon" and
    qn = "otl_connect::rlogon"
  ) or
  target.getQualifiedName().matches("otl_stream%::operator<<%") and qn = "otl_stream::operator<<" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "otl_stream") and
    memberFunc.getName() = "operator<<" and
    qn = "otl_stream::operator<<"
  ) or
  target.getQualifiedName().matches("otl_stream%::operator>>%") and qn = "otl_stream::operator>>" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "otl_stream") and
    memberFunc.getName() = "operator>>" and
    qn = "otl_stream::operator>>"
  ) or
  target.getQualifiedName().matches("otl_stream%::open%") and qn = "otl_stream::open" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "otl_stream") and
    memberFunc.getName() = "open" and
    qn = "otl_stream::open"
  ) or
  target.getQualifiedName().matches("otl_stream%::flush%") and qn = "otl_stream::flush" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "otl_stream") and
    memberFunc.getName() = "flush" and
    qn = "otl_stream::flush"
  ) or
  target.getQualifiedName().matches("OCIEnvCreate%") and qn = "OCIEnvCreate" or
  target.getQualifiedName().matches("OCIServerAttach%") and qn = "OCIServerAttach" or
  target.getQualifiedName().matches("OCISvcCtx%") and qn = "OCISvcCtx" or
  target.getQualifiedName().matches("OCIStmtPrepare%") and qn = "OCIStmtPrepare" or
  target.getQualifiedName().matches("OCIStmtExecute%") and qn = "OCIStmtExecute" or
  target.getQualifiedName().matches("OCIBindByName%") and qn = "OCIBindByName" or
  target.getQualifiedName().matches("OCIBindByPos%") and qn = "OCIBindByPos" or
  target.getQualifiedName().matches("SQLITE_OK%") and qn = "SQLITE_OK" or
  target.getQualifiedName().matches("SQLITE_PREPARE%") and qn = "SQLITE_PREPARE" or
  target.getQualifiedName().matches("SQLITE_BIND%") and qn = "SQLITE_BIND" or
  target.getQualifiedName().matches("mongoc_client_new%") and qn = "mongoc_client_new" or
  target.getQualifiedName().matches("mongoc_collection_find%") and qn = "mongoc_collection_find" or
  target.getQualifiedName().matches("mongoc_collection_find_with_opts%") and qn = "mongoc_collection_find_with_opts" or
  target.getQualifiedName().matches("mongoc_collection_update%") and qn = "mongoc_collection_update" or
  target.getQualifiedName().matches("mongoc_collection_update_one%") and qn = "mongoc_collection_update_one" or
  target.getQualifiedName().matches("mongoc_collection_update_many%") and qn = "mongoc_collection_update_many" or
  target.getQualifiedName().matches("mongoc_collection_insert_one%") and qn = "mongoc_collection_insert_one" or
  target.getQualifiedName().matches("mongoc_collection_delete_one%") and qn = "mongoc_collection_delete_one" or
  target.getQualifiedName().matches("mongoc_collection_delete_many%") and qn = "mongoc_collection_delete_many" or
  target.getQualifiedName().matches("bson_new_from_json%") and qn = "bson_new_from_json" or
  target.getQualifiedName().matches("bson_as_canonical_extended_json%") and qn = "bson_as_canonical_extended_json" or
  target.getQualifiedName().matches("mongocxx%::client%::client%") and qn = "mongocxx::client::client" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("mongocxx", "client") and
    memberFunc.getName() = "client" and
    qn = "mongocxx::client::client"
  ) or
  target.getQualifiedName().matches("mongocxx%::collection%::find%") and qn = "mongocxx::collection::find" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("mongocxx", "collection") and
    memberFunc.getName() = "find" and
    qn = "mongocxx::collection::find"
  ) or
  target.getQualifiedName().matches("mongocxx%::collection%::insert_one%") and qn = "mongocxx::collection::insert_one" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("mongocxx", "collection") and
    memberFunc.getName() = "insert_one" and
    qn = "mongocxx::collection::insert_one"
  ) or
  target.getQualifiedName().matches("mongocxx%::collection%::update_one%") and qn = "mongocxx::collection::update_one" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("mongocxx", "collection") and
    memberFunc.getName() = "update_one" and
    qn = "mongocxx::collection::update_one"
  ) or
  target.getQualifiedName().matches("mongocxx%::collection%::delete_one%") and qn = "mongocxx::collection::delete_one" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("mongocxx", "collection") and
    memberFunc.getName() = "delete_one" and
    qn = "mongocxx::collection::delete_one"
  ) or
  target.getQualifiedName().matches("bsoncxx%::from_json%") and qn = "bsoncxx::from_json" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "bsoncxx") and
    memberFunc.getName() = "from_json" and
    qn = "bsoncxx::from_json"
  ) or
  target.getQualifiedName().matches("bsoncxx%::to_json%") and qn = "bsoncxx::to_json" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "bsoncxx") and
    memberFunc.getName() = "to_json" and
    qn = "bsoncxx::to_json"
  ) or
  target.getQualifiedName().matches("bsoncxx%::builder%::basic%::make_document%") and qn = "bsoncxx::builder::basic::make_document" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("bsoncxx::builder", "basic") and
    memberFunc.getName() = "make_document" and
    qn = "bsoncxx::builder::basic::make_document"
  ) or
  target.getQualifiedName().matches("redisCommand%") and qn = "redisCommand" or
  target.getQualifiedName().matches("redisCommandArgv%") and qn = "redisCommandArgv" or
  target.getQualifiedName().matches("hiredis%::redisCommand%") and qn = "hiredis::redisCommand" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "hiredis") and
    memberFunc.getName() = "redisCommand" and
    qn = "hiredis::redisCommand"
  ) or
  target.getQualifiedName().matches("elasticsearch%::RestClient%::performRequest%") and qn = "elasticsearch::RestClient::performRequest" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("elasticsearch", "RestClient") and
    memberFunc.getName() = "performRequest" and
    qn = "elasticsearch::RestClient::performRequest"
  ) or
  target.getQualifiedName().matches("opensearch%::RestClient%::performRequest%") and qn = "opensearch::RestClient::performRequest" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("opensearch", "RestClient") and
    memberFunc.getName() = "performRequest" and
    qn = "opensearch::RestClient::performRequest"
  ) or
  target.getQualifiedName().matches("nlohmann%::json%::parse%") and qn = "nlohmann::json::parse" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("nlohmann", "json") and
    memberFunc.getName() = "parse" and
    qn = "nlohmann::json::parse"
  ) or
  target.getQualifiedName().matches("rapidjson%::Document%::Parse%") and qn = "rapidjson::Document::Parse" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("rapidjson", "Document") and
    memberFunc.getName() = "Parse" and
    qn = "rapidjson::Document::Parse"
  ) or
  target.getQualifiedName().matches("rapidjson%::Document%::ParseInsitu%") and qn = "rapidjson::Document::ParseInsitu" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("rapidjson", "Document") and
    memberFunc.getName() = "ParseInsitu" and
    qn = "rapidjson::Document::ParseInsitu"
  ) or
  target.getQualifiedName().matches("Json%::Reader%::parse%") and qn = "Json::Reader::parse" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Json", "Reader") and
    memberFunc.getName() = "parse" and
    qn = "Json::Reader::parse"
  ) or
  target.getQualifiedName().matches("Json%::CharReader%::parse%") and qn = "Json::CharReader::parse" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Json", "CharReader") and
    memberFunc.getName() = "parse" and
    qn = "Json::CharReader::parse"
  ) or
  target.getQualifiedName().matches("Poco%::Data%::Session%::operator<<%") and qn = "Poco::Data::Session::operator<<" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Poco::Data", "Session") and
    memberFunc.getName() = "operator<<" and
    qn = "Poco::Data::Session::operator<<"
  ) or
  target.getQualifiedName().matches("Poco%::Data%::Statement%::operator<<%") and qn = "Poco::Data::Statement::operator<<" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Poco::Data", "Statement") and
    memberFunc.getName() = "operator<<" and
    qn = "Poco::Data::Statement::operator<<"
  ) or
  target.getQualifiedName().matches("Poco%::Data%::Statement%::execute%") and qn = "Poco::Data::Statement::execute" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Poco::Data", "Statement") and
    memberFunc.getName() = "execute" and
    qn = "Poco::Data::Statement::execute"
  ) or
  target.getQualifiedName().matches("Poco%::Data%::Statement%::executeAsync%") and qn = "Poco::Data::Statement::executeAsync" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Poco::Data", "Statement") and
    memberFunc.getName() = "executeAsync" and
    qn = "Poco::Data::Statement::executeAsync"
  ) or
  target.getQualifiedName().matches("leveldb%::DB%::Get%") and qn = "leveldb::DB::Get" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("leveldb", "DB") and
    memberFunc.getName() = "Get" and
    qn = "leveldb::DB::Get"
  ) or
  target.getQualifiedName().matches("leveldb%::DB%::Put%") and qn = "leveldb::DB::Put" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("leveldb", "DB") and
    memberFunc.getName() = "Put" and
    qn = "leveldb::DB::Put"
  ) or
  target.getQualifiedName().matches("rocksdb%::DB%::Get%") and qn = "rocksdb::DB::Get" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("rocksdb", "DB") and
    memberFunc.getName() = "Get" and
    qn = "rocksdb::DB::Get"
  ) or
  target.getQualifiedName().matches("rocksdb%::DB%::Put%") and qn = "rocksdb::DB::Put" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("rocksdb", "DB") and
    memberFunc.getName() = "Put" and
    qn = "rocksdb::DB::Put"
  ) or
  target.getQualifiedName().matches("taos_query%") and qn = "taos_query" or
  target.getQualifiedName().matches("taos_stmt_prepare%") and qn = "taos_stmt_prepare" or
  target.getQualifiedName().matches("taos_stmt_bind_param%") and qn = "taos_stmt_bind_param" or
  target.getQualifiedName().matches("taos_stmt_execute%") and qn = "taos_stmt_execute"
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
