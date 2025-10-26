// Auto-generated; CWE-918; number of APIs 100
import cpp

predicate isTargetApi(Function target, string qn) {
  target.getQualifiedName().matches("curl_easy_init%") and qn = "curl_easy_init" or
  target.getQualifiedName().matches("curl_easy_setopt%") and qn = "curl_easy_setopt" or
  target.getQualifiedName().matches("curl_easy_perform%") and qn = "curl_easy_perform" or
  target.getQualifiedName().matches("curl_easy_cleanup%") and qn = "curl_easy_cleanup" or
  target.getQualifiedName().matches("curl_multi_add_handle%") and qn = "curl_multi_add_handle" or
  target.getQualifiedName().matches("curl_multi_perform%") and qn = "curl_multi_perform" or
  target.getQualifiedName().matches("curl_url%") and qn = "curl_url" or
  target.getQualifiedName().matches("curl_url_set%") and qn = "curl_url_set" or
  target.getQualifiedName().matches("curl_url_get%") and qn = "curl_url_get" or
  target.getQualifiedName().matches("CURLOPT_URL%") and qn = "CURLOPT_URL" or
  target.getQualifiedName().matches("CURLOPT_PROXY%") and qn = "CURLOPT_PROXY" or
  target.getQualifiedName().matches("CURLOPT_CONNECT_TO%") and qn = "CURLOPT_CONNECT_TO" or
  target.getQualifiedName().matches("CURLOPT_RESOLVE%") and qn = "CURLOPT_RESOLVE" or
  target.getQualifiedName().matches("CURLOPT_INTERFACE%") and qn = "CURLOPT_INTERFACE" or
  target.getQualifiedName().matches("CURLOPT_FOLLOWLOCATION%") and qn = "CURLOPT_FOLLOWLOCATION" or
  target.getQualifiedName().matches("CURLOPT_MAXREDIRS%") and qn = "CURLOPT_MAXREDIRS" or
  target.getQualifiedName().matches("CURLOPT_PROTOCOLS%") and qn = "CURLOPT_PROTOCOLS" or
  target.getQualifiedName().matches("CURLOPT_REDIR_PROTOCOLS%") and qn = "CURLOPT_REDIR_PROTOCOLS" or
  target.getQualifiedName().matches("CURLOPT_USERPWD%") and qn = "CURLOPT_USERPWD" or
  target.getQualifiedName().matches("CURLOPT_PROXYUSERPWD%") and qn = "CURLOPT_PROXYUSERPWD" or
  target.getQualifiedName().matches("CURLOPT_HTTPHEADER%") and qn = "CURLOPT_HTTPHEADER" or
  target.getQualifiedName().matches("CURLOPT_POSTFIELDS%") and qn = "CURLOPT_POSTFIELDS" or
  target.getQualifiedName().matches("CURLOPT_UPLOAD%") and qn = "CURLOPT_UPLOAD" or
  target.getQualifiedName().matches("CURLOPT_SSH_PUBLIC_KEYFILE%") and qn = "CURLOPT_SSH_PUBLIC_KEYFILE" or
  target.getQualifiedName().matches("CURLOPT_SSH_PRIVATE_KEYFILE%") and qn = "CURLOPT_SSH_PRIVATE_KEYFILE" or
  target.getQualifiedName().matches("boost%::asio%::ip%::tcp%::resolver%::resolve%") and qn = "boost::asio::ip::tcp::resolver::resolve" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost::asio::ip::tcp", "resolver") and
    memberFunc.getName() = "resolve" and
    qn = "boost::asio::ip::tcp::resolver::resolve"
  ) or
  target.getQualifiedName().matches("boost%::asio%::connect%") and qn = "boost::asio::connect" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost", "asio") and
    memberFunc.getName() = "connect" and
    qn = "boost::asio::connect"
  ) or
  target.getQualifiedName().matches("boost%::asio%::async_connect%") and qn = "boost::asio::async_connect" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost", "asio") and
    memberFunc.getName() = "async_connect" and
    qn = "boost::asio::async_connect"
  ) or
  target.getQualifiedName().matches("boost%::asio%::ip%::tcp%::socket%::connect%") and qn = "boost::asio::ip::tcp::socket::connect" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost::asio::ip::tcp", "socket") and
    memberFunc.getName() = "connect" and
    qn = "boost::asio::ip::tcp::socket::connect"
  ) or
  target.getQualifiedName().matches("boost%::asio%::ip%::tcp%::socket%::async_connect%") and qn = "boost::asio::ip::tcp::socket::async_connect" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost::asio::ip::tcp", "socket") and
    memberFunc.getName() = "async_connect" and
    qn = "boost::asio::ip::tcp::socket::async_connect"
  ) or
  target.getQualifiedName().matches("boost%::beast%::http%::async_write%") and qn = "boost::beast::http::async_write" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost::beast", "http") and
    memberFunc.getName() = "async_write" and
    qn = "boost::beast::http::async_write"
  ) or
  target.getQualifiedName().matches("boost%::beast%::http%::async_read%") and qn = "boost::beast::http::async_read" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost::beast", "http") and
    memberFunc.getName() = "async_read" and
    qn = "boost::beast::http::async_read"
  ) or
  target.getQualifiedName().matches("boost%::beast%::http%::write%") and qn = "boost::beast::http::write" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost::beast", "http") and
    memberFunc.getName() = "write" and
    qn = "boost::beast::http::write"
  ) or
  target.getQualifiedName().matches("boost%::beast%::http%::read%") and qn = "boost::beast::http::read" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost::beast", "http") and
    memberFunc.getName() = "read" and
    qn = "boost::beast::http::read"
  ) or
  target.getQualifiedName().matches("web%::http%::client%::http_client%::request%") and qn = "web::http::client::http_client::request" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("web::http::client", "http_client") and
    memberFunc.getName() = "request" and
    qn = "web::http::client::http_client::request"
  ) or
  target.getQualifiedName().matches("web%::http%::client%::http_client%::request_async%") and qn = "web::http::client::http_client::request_async" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("web::http::client", "http_client") and
    memberFunc.getName() = "request_async" and
    qn = "web::http::client::http_client::request_async"
  ) or
  target.getQualifiedName().matches("web%::http%::client%::http_client%::extract_string%") and qn = "web::http::client::http_client::extract_string" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("web::http::client", "http_client") and
    memberFunc.getName() = "extract_string" and
    qn = "web::http::client::http_client::extract_string"
  ) or
  target.getQualifiedName().matches("web%::http%::client%::http_client%::extract_json%") and qn = "web::http::client::http_client::extract_json" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("web::http::client", "http_client") and
    memberFunc.getName() = "extract_json" and
    qn = "web::http::client::http_client::extract_json"
  ) or
  target.getQualifiedName().matches("QNetworkAccessManager%::get%") and qn = "QNetworkAccessManager::get" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QNetworkAccessManager") and
    memberFunc.getName() = "get" and
    qn = "QNetworkAccessManager::get"
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
  target.getQualifiedName().matches("QNetworkAccessManager%::deleteResource%") and qn = "QNetworkAccessManager::deleteResource" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QNetworkAccessManager") and
    memberFunc.getName() = "deleteResource" and
    qn = "QNetworkAccessManager::deleteResource"
  ) or
  target.getQualifiedName().matches("QNetworkAccessManager%::sendCustomRequest%") and qn = "QNetworkAccessManager::sendCustomRequest" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QNetworkAccessManager") and
    memberFunc.getName() = "sendCustomRequest" and
    qn = "QNetworkAccessManager::sendCustomRequest"
  ) or
  target.getQualifiedName().matches("QNetworkRequest%::setUrl%") and qn = "QNetworkRequest::setUrl" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QNetworkRequest") and
    memberFunc.getName() = "setUrl" and
    qn = "QNetworkRequest::setUrl"
  ) or
  target.getQualifiedName().matches("QNetworkRequest%::setRawHeader%") and qn = "QNetworkRequest::setRawHeader" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QNetworkRequest") and
    memberFunc.getName() = "setRawHeader" and
    qn = "QNetworkRequest::setRawHeader"
  ) or
  target.getQualifiedName().matches("QUrl%::fromUserInput%") and qn = "QUrl::fromUserInput" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QUrl") and
    memberFunc.getName() = "fromUserInput" and
    qn = "QUrl::fromUserInput"
  ) or
  target.getQualifiedName().matches("QUrl%::setUrl%") and qn = "QUrl::setUrl" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QUrl") and
    memberFunc.getName() = "setUrl" and
    qn = "QUrl::setUrl"
  ) or
  target.getQualifiedName().matches("Poco%::Net%::HTTPClientSession%::HTTPClientSession%") and qn = "Poco::Net::HTTPClientSession::HTTPClientSession" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Poco::Net", "HTTPClientSession") and
    memberFunc.getName() = "HTTPClientSession" and
    qn = "Poco::Net::HTTPClientSession::HTTPClientSession"
  ) or
  target.getQualifiedName().matches("Poco%::Net%::HTTPSClientSession%::HTTPSClientSession%") and qn = "Poco::Net::HTTPSClientSession::HTTPSClientSession" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Poco::Net", "HTTPSClientSession") and
    memberFunc.getName() = "HTTPSClientSession" and
    qn = "Poco::Net::HTTPSClientSession::HTTPSClientSession"
  ) or
  target.getQualifiedName().matches("Poco%::Net%::HTTPClientSession%::sendRequest%") and qn = "Poco::Net::HTTPClientSession::sendRequest" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Poco::Net", "HTTPClientSession") and
    memberFunc.getName() = "sendRequest" and
    qn = "Poco::Net::HTTPClientSession::sendRequest"
  ) or
  target.getQualifiedName().matches("Poco%::Net%::HTTPClientSession%::receiveResponse%") and qn = "Poco::Net::HTTPClientSession::receiveResponse" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Poco::Net", "HTTPClientSession") and
    memberFunc.getName() = "receiveResponse" and
    qn = "Poco::Net::HTTPClientSession::receiveResponse"
  ) or
  target.getQualifiedName().matches("Poco%::Net%::HTTPRequest%::setURI%") and qn = "Poco::Net::HTTPRequest::setURI" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Poco::Net", "HTTPRequest") and
    memberFunc.getName() = "setURI" and
    qn = "Poco::Net::HTTPRequest::setURI"
  ) or
  target.getQualifiedName().matches("Poco%::URI%::URI%") and qn = "Poco::URI::URI" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Poco", "URI") and
    memberFunc.getName() = "URI" and
    qn = "Poco::URI::URI"
  ) or
  target.getQualifiedName().matches("evhttp_request_new%") and qn = "evhttp_request_new" or
  target.getQualifiedName().matches("evhttp_make_request%") and qn = "evhttp_make_request" or
  target.getQualifiedName().matches("evhttp_connection_base_new%") and qn = "evhttp_connection_base_new" or
  target.getQualifiedName().matches("evhttp_uri_parse%") and qn = "evhttp_uri_parse" or
  target.getQualifiedName().matches("evhttp_uri_parse_with_flags%") and qn = "evhttp_uri_parse_with_flags" or
  target.getQualifiedName().matches("WinHttpOpen%") and qn = "WinHttpOpen" or
  target.getQualifiedName().matches("WinHttpConnect%") and qn = "WinHttpConnect" or
  target.getQualifiedName().matches("WinHttpOpenRequest%") and qn = "WinHttpOpenRequest" or
  target.getQualifiedName().matches("WinHttpSendRequest%") and qn = "WinHttpSendRequest" or
  target.getQualifiedName().matches("WinHttpReceiveResponse%") and qn = "WinHttpReceiveResponse" or
  target.getQualifiedName().matches("WinHttpReadData%") and qn = "WinHttpReadData" or
  target.getQualifiedName().matches("WinHttpSetOption%") and qn = "WinHttpSetOption" or
  target.getQualifiedName().matches("WinHttpSetTimeouts%") and qn = "WinHttpSetTimeouts" or
  target.getQualifiedName().matches("InternetOpenA%") and qn = "InternetOpenA" or
  target.getQualifiedName().matches("InternetOpenW%") and qn = "InternetOpenW" or
  target.getQualifiedName().matches("InternetOpenUrlA%") and qn = "InternetOpenUrlA" or
  target.getQualifiedName().matches("InternetOpenUrlW%") and qn = "InternetOpenUrlW" or
  target.getQualifiedName().matches("HttpOpenRequestA%") and qn = "HttpOpenRequestA" or
  target.getQualifiedName().matches("HttpOpenRequestW%") and qn = "HttpOpenRequestW" or
  target.getQualifiedName().matches("HttpSendRequestA%") and qn = "HttpSendRequestA" or
  target.getQualifiedName().matches("HttpSendRequestW%") and qn = "HttpSendRequestW" or
  target.getQualifiedName().matches("InternetReadFile%") and qn = "InternetReadFile" or
  target.getQualifiedName().matches("InternetSetOptionA%") and qn = "InternetSetOptionA" or
  target.getQualifiedName().matches("InternetSetOptionW%") and qn = "InternetSetOptionW" or
  target.getQualifiedName().matches("URLDownloadToFileA%") and qn = "URLDownloadToFileA" or
  target.getQualifiedName().matches("URLDownloadToFileW%") and qn = "URLDownloadToFileW" or
  target.getQualifiedName().matches("URLOpenBlockingStreamA%") and qn = "URLOpenBlockingStreamA" or
  target.getQualifiedName().matches("URLOpenBlockingStreamW%") and qn = "URLOpenBlockingStreamW" or
  target.getQualifiedName().matches("httplib%::Client%::Get%") and qn = "httplib::Client::Get" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("httplib", "Client") and
    memberFunc.getName() = "Get" and
    qn = "httplib::Client::Get"
  ) or
  target.getQualifiedName().matches("httplib%::Client%::Post%") and qn = "httplib::Client::Post" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("httplib", "Client") and
    memberFunc.getName() = "Post" and
    qn = "httplib::Client::Post"
  ) or
  target.getQualifiedName().matches("httplib%::Client%::Put%") and qn = "httplib::Client::Put" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("httplib", "Client") and
    memberFunc.getName() = "Put" and
    qn = "httplib::Client::Put"
  ) or
  target.getQualifiedName().matches("httplib%::Client%::Delete%") and qn = "httplib::Client::Delete" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("httplib", "Client") and
    memberFunc.getName() = "Delete" and
    qn = "httplib::Client::Delete"
  ) or
  target.getQualifiedName().matches("httplib%::SSLClient%::Get%") and qn = "httplib::SSLClient::Get" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("httplib", "SSLClient") and
    memberFunc.getName() = "Get" and
    qn = "httplib::SSLClient::Get"
  ) or
  target.getQualifiedName().matches("httplib%::SSLClient%::Post%") and qn = "httplib::SSLClient::Post" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("httplib", "SSLClient") and
    memberFunc.getName() = "Post" and
    qn = "httplib::SSLClient::Post"
  ) or
  target.getQualifiedName().matches("grpc%::CreateChannel%") and qn = "grpc::CreateChannel" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "grpc") and
    memberFunc.getName() = "CreateChannel" and
    qn = "grpc::CreateChannel"
  ) or
  target.getQualifiedName().matches("grpc%::Channel%::CreateCall%") and qn = "grpc::Channel::CreateCall" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("grpc", "Channel") and
    memberFunc.getName() = "CreateCall" and
    qn = "grpc::Channel::CreateCall"
  ) or
  target.getQualifiedName().matches("grpc%::ClientContext%::set_authority%") and qn = "grpc::ClientContext::set_authority" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("grpc", "ClientContext") and
    memberFunc.getName() = "set_authority" and
    qn = "grpc::ClientContext::set_authority"
  ) or
  target.getQualifiedName().matches("asio%::ip%::tcp%::resolver%::resolve%") and qn = "asio::ip::tcp::resolver::resolve" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("asio::ip::tcp", "resolver") and
    memberFunc.getName() = "resolve" and
    qn = "asio::ip::tcp::resolver::resolve"
  ) or
  target.getQualifiedName().matches("asio%::connect%") and qn = "asio::connect" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "asio") and
    memberFunc.getName() = "connect" and
    qn = "asio::connect"
  ) or
  target.getQualifiedName().matches("asio%::ip%::tcp%::socket%::connect%") and qn = "asio::ip::tcp::socket::connect" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("asio::ip::tcp", "socket") and
    memberFunc.getName() = "connect" and
    qn = "asio::ip::tcp::socket::connect"
  ) or
  target.getQualifiedName().matches("CURLINFO_REDIRECT_URL%") and qn = "CURLINFO_REDIRECT_URL" or
  target.getQualifiedName().matches("curl_easy_getinfo%") and qn = "curl_easy_getinfo" or
  target.getQualifiedName().matches("libssh2_session_handshake%") and qn = "libssh2_session_handshake" or
  target.getQualifiedName().matches("libssh2_userauth_password%") and qn = "libssh2_userauth_password" or
  target.getQualifiedName().matches("libssh2_userauth_publickey_fromfile%") and qn = "libssh2_userauth_publickey_fromfile" or
  target.getQualifiedName().matches("libssh2_scp_recv%") and qn = "libssh2_scp_recv" or
  target.getQualifiedName().matches("libssh2_scp_send%") and qn = "libssh2_scp_send"
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
