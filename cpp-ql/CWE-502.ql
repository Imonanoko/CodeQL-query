// Auto-generated; CWE-502; number of APIs 130
import cpp

predicate isTargetApi(Function target, string qn) {
  target.getQualifiedName().matches("boost%::archive%::text_iarchive%") and qn = "boost::archive::text_iarchive" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost", "archive") and
    memberFunc.getName() = "text_iarchive" and
    qn = "boost::archive::text_iarchive"
  ) or
  target.getQualifiedName().matches("boost%::archive%::binary_iarchive%") and qn = "boost::archive::binary_iarchive" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost", "archive") and
    memberFunc.getName() = "binary_iarchive" and
    qn = "boost::archive::binary_iarchive"
  ) or
  target.getQualifiedName().matches("boost%::archive%::xml_iarchive%") and qn = "boost::archive::xml_iarchive" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost", "archive") and
    memberFunc.getName() = "xml_iarchive" and
    qn = "boost::archive::xml_iarchive"
  ) or
  target.getQualifiedName().matches("boost%::archive%::polymorphic_iarchive%") and qn = "boost::archive::polymorphic_iarchive" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost", "archive") and
    memberFunc.getName() = "polymorphic_iarchive" and
    qn = "boost::archive::polymorphic_iarchive"
  ) or
  target.getQualifiedName().matches("boost%::archive%::text_oarchive%") and qn = "boost::archive::text_oarchive" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost", "archive") and
    memberFunc.getName() = "text_oarchive" and
    qn = "boost::archive::text_oarchive"
  ) or
  target.getQualifiedName().matches("boost%::archive%::binary_oarchive%") and qn = "boost::archive::binary_oarchive" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost", "archive") and
    memberFunc.getName() = "binary_oarchive" and
    qn = "boost::archive::binary_oarchive"
  ) or
  target.getQualifiedName().matches("boost%::archive%::xml_oarchive%") and qn = "boost::archive::xml_oarchive" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost", "archive") and
    memberFunc.getName() = "xml_oarchive" and
    qn = "boost::archive::xml_oarchive"
  ) or
  target.getQualifiedName().matches("boost%::archive%::polymorphic_oarchive%") and qn = "boost::archive::polymorphic_oarchive" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost", "archive") and
    memberFunc.getName() = "polymorphic_oarchive" and
    qn = "boost::archive::polymorphic_oarchive"
  ) or
  target.getQualifiedName().matches("boost%::serialization%::load%") and qn = "boost::serialization::load" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost", "serialization") and
    memberFunc.getName() = "load" and
    qn = "boost::serialization::load"
  ) or
  target.getQualifiedName().matches("boost%::serialization%::load_override%") and qn = "boost::serialization::load_override" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost", "serialization") and
    memberFunc.getName() = "load_override" and
    qn = "boost::serialization::load_override"
  ) or
  target.getQualifiedName().matches("boost%::serialization%::serialize%") and qn = "boost::serialization::serialize" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost", "serialization") and
    memberFunc.getName() = "serialize" and
    qn = "boost::serialization::serialize"
  ) or
  target.getQualifiedName().matches("boost%::serialization%::access%::serialize%") and qn = "boost::serialization::access::serialize" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost::serialization", "access") and
    memberFunc.getName() = "serialize" and
    qn = "boost::serialization::access::serialize"
  ) or
  target.getQualifiedName().matches("boost%::archive%::detail%::common_iarchive%") and qn = "boost::archive::detail::common_iarchive" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost::archive", "detail") and
    memberFunc.getName() = "common_iarchive" and
    qn = "boost::archive::detail::common_iarchive"
  ) or
  target.getQualifiedName().matches("boost%::archive%::detail%::iserializer%") and qn = "boost::archive::detail::iserializer" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost::archive", "detail") and
    memberFunc.getName() = "iserializer" and
    qn = "boost::archive::detail::iserializer"
  ) or
  target.getQualifiedName().matches("std%::istream%::operator>>%") and qn = "std::istream::operator>>" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "istream") and
    memberFunc.getName() = "operator>>" and
    qn = "std::istream::operator>>"
  ) or
  target.getQualifiedName().matches("std%::ifstream%::operator>>%") and qn = "std::ifstream::operator>>" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "ifstream") and
    memberFunc.getName() = "operator>>" and
    qn = "std::ifstream::operator>>"
  ) or
  target.getQualifiedName().matches("std%::wistream%::operator>>%") and qn = "std::wistream::operator>>" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "wistream") and
    memberFunc.getName() = "operator>>" and
    qn = "std::wistream::operator>>"
  ) or
  target.getQualifiedName().matches("std%::basic_istream%::operator>>%") and qn = "std::basic_istream::operator>>" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "basic_istream") and
    memberFunc.getName() = "operator>>" and
    qn = "std::basic_istream::operator>>"
  ) or
  target.getQualifiedName().matches("std%::basic_iostream%::read%") and qn = "std::basic_iostream::read" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "basic_iostream") and
    memberFunc.getName() = "read" and
    qn = "std::basic_iostream::read"
  ) or
  target.getQualifiedName().matches("std%::istream%::read%") and qn = "std::istream::read" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "istream") and
    memberFunc.getName() = "read" and
    qn = "std::istream::read"
  ) or
  target.getQualifiedName().matches("std%::ifstream%::read%") and qn = "std::ifstream::read" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "ifstream") and
    memberFunc.getName() = "read" and
    qn = "std::ifstream::read"
  ) or
  target.getQualifiedName().matches("std%::getline%") and qn = "std::getline" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "std") and
    memberFunc.getName() = "getline" and
    qn = "std::getline"
  ) or
  target.getQualifiedName().matches("std%::wgetline%") and qn = "std::wgetline" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "std") and
    memberFunc.getName() = "wgetline" and
    qn = "std::wgetline"
  ) or
  target.getQualifiedName().matches("std%::basic_iarchive%::load%") and qn = "std::basic_iarchive::load" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "basic_iarchive") and
    memberFunc.getName() = "load" and
    qn = "std::basic_iarchive::load"
  ) or
  target.getQualifiedName().matches("std%::basic_iarchive%::load_override%") and qn = "std::basic_iarchive::load_override" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "basic_iarchive") and
    memberFunc.getName() = "load_override" and
    qn = "std::basic_iarchive::load_override"
  ) or
  target.getQualifiedName().matches("std%::basic_iarchive%::operator>>%") and qn = "std::basic_iarchive::operator>>" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "basic_iarchive") and
    memberFunc.getName() = "operator>>" and
    qn = "std::basic_iarchive::operator>>"
  ) or
  target.getQualifiedName().matches("yaml_parser_load%") and qn = "yaml_parser_load" or
  target.getQualifiedName().matches("yaml_parser_load_file%") and qn = "yaml_parser_load_file" or
  target.getQualifiedName().matches("yaml_parser_load_stream%") and qn = "yaml_parser_load_stream" or
  target.getQualifiedName().matches("yaml_parser_parse%") and qn = "yaml_parser_parse" or
  target.getQualifiedName().matches("yaml_load%") and qn = "yaml_load" or
  target.getQualifiedName().matches("yaml_load_file%") and qn = "yaml_load_file" or
  target.getQualifiedName().matches("yaml_load_stream%") and qn = "yaml_load_stream" or
  target.getQualifiedName().matches("yaml_document_load%") and qn = "yaml_document_load" or
  target.getQualifiedName().matches("yaml_document_parse%") and qn = "yaml_document_parse" or
  target.getQualifiedName().matches("json_load%") and qn = "json_load" or
  target.getQualifiedName().matches("json_load_file%") and qn = "json_load_file" or
  target.getQualifiedName().matches("json_loadf%") and qn = "json_loadf" or
  target.getQualifiedName().matches("json_loads%") and qn = "json_loads" or
  target.getQualifiedName().matches("json_parse%") and qn = "json_parse" or
  target.getQualifiedName().matches("json_parse_file%") and qn = "json_parse_file" or
  target.getQualifiedName().matches("json_parse_ex%") and qn = "json_parse_ex" or
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
  target.getQualifiedName().matches("rapidjson%::Document%::ParseStream%") and qn = "rapidjson::Document::ParseStream" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("rapidjson", "Document") and
    memberFunc.getName() = "ParseStream" and
    qn = "rapidjson::Document::ParseStream"
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
  target.getQualifiedName().matches("JsonCpp%::Reader%::parse%") and qn = "JsonCpp::Reader::parse" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("JsonCpp", "Reader") and
    memberFunc.getName() = "parse" and
    qn = "JsonCpp::Reader::parse"
  ) or
  target.getQualifiedName().matches("cJSON_Parse%") and qn = "cJSON_Parse" or
  target.getQualifiedName().matches("cJSON_ParseWithOpts%") and qn = "cJSON_ParseWithOpts" or
  target.getQualifiedName().matches("cJSON_ParseWithLength%") and qn = "cJSON_ParseWithLength" or
  target.getQualifiedName().matches("QDataStream%::operator>>%") and qn = "QDataStream::operator>>" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QDataStream") and
    memberFunc.getName() = "operator>>" and
    qn = "QDataStream::operator>>"
  ) or
  target.getQualifiedName().matches("QVariant%::load%") and qn = "QVariant::load" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QVariant") and
    memberFunc.getName() = "load" and
    qn = "QVariant::load"
  ) or
  target.getQualifiedName().matches("QJsonDocument%::fromJson%") and qn = "QJsonDocument::fromJson" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QJsonDocument") and
    memberFunc.getName() = "fromJson" and
    qn = "QJsonDocument::fromJson"
  ) or
  target.getQualifiedName().matches("QXmlStreamReader%::readElementText%") and qn = "QXmlStreamReader::readElementText" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "QXmlStreamReader") and
    memberFunc.getName() = "readElementText" and
    qn = "QXmlStreamReader::readElementText"
  ) or
  target.getQualifiedName().matches("xercesc%::DOMDocument%::load%") and qn = "xercesc::DOMDocument::load" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("xercesc", "DOMDocument") and
    memberFunc.getName() = "load" and
    qn = "xercesc::DOMDocument::load"
  ) or
  target.getQualifiedName().matches("xercesc%::XercesDOMParser%::parse%") and qn = "xercesc::XercesDOMParser::parse" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("xercesc", "XercesDOMParser") and
    memberFunc.getName() = "parse" and
    qn = "xercesc::XercesDOMParser::parse"
  ) or
  target.getQualifiedName().matches("xercesc%::SAXParser%::parse%") and qn = "xercesc::SAXParser::parse" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("xercesc", "SAXParser") and
    memberFunc.getName() = "parse" and
    qn = "xercesc::SAXParser::parse"
  ) or
  target.getQualifiedName().matches("xercesc%::MemBufInputSource%") and qn = "xercesc::MemBufInputSource" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "xercesc") and
    memberFunc.getName() = "MemBufInputSource" and
    qn = "xercesc::MemBufInputSource"
  ) or
  target.getQualifiedName().matches("tinyxml2%::XMLDocument%::Parse%") and qn = "tinyxml2::XMLDocument::Parse" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("tinyxml2", "XMLDocument") and
    memberFunc.getName() = "Parse" and
    qn = "tinyxml2::XMLDocument::Parse"
  ) or
  target.getQualifiedName().matches("tinyxml2%::XMLDocument%::LoadFile%") and qn = "tinyxml2::XMLDocument::LoadFile" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("tinyxml2", "XMLDocument") and
    memberFunc.getName() = "LoadFile" and
    qn = "tinyxml2::XMLDocument::LoadFile"
  ) or
  target.getQualifiedName().matches("pugixml%::xml_document%::load%") and qn = "pugixml::xml_document::load" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("pugixml", "xml_document") and
    memberFunc.getName() = "load" and
    qn = "pugixml::xml_document::load"
  ) or
  target.getQualifiedName().matches("pugixml%::xml_document%::load_file%") and qn = "pugixml::xml_document::load_file" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("pugixml", "xml_document") and
    memberFunc.getName() = "load_file" and
    qn = "pugixml::xml_document::load_file"
  ) or
  target.getQualifiedName().matches("pugixml%::xml_document%::load_buffer%") and qn = "pugixml::xml_document::load_buffer" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("pugixml", "xml_document") and
    memberFunc.getName() = "load_buffer" and
    qn = "pugixml::xml_document::load_buffer"
  ) or
  target.getQualifiedName().matches("ObjectInputStream%::readObject%") and qn = "ObjectInputStream::readObject" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "ObjectInputStream") and
    memberFunc.getName() = "readObject" and
    qn = "ObjectInputStream::readObject"
  ) or
  target.getQualifiedName().matches("boost%::python%::object%::attr%") and qn = "boost::python::object::attr" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost::python", "object") and
    memberFunc.getName() = "attr" and
    qn = "boost::python::object::attr"
  ) or
  target.getQualifiedName().matches("boost%::python%::extract%") and qn = "boost::python::extract" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost", "python") and
    memberFunc.getName() = "extract" and
    qn = "boost::python::extract"
  ) or
  target.getQualifiedName().matches("pickle_load%") and qn = "pickle_load" or
  target.getQualifiedName().matches("pickle_loads%") and qn = "pickle_loads" or
  target.getQualifiedName().matches("pickle_Unpickler_load%") and qn = "pickle_Unpickler_load" or
  target.getQualifiedName().matches("PyMarshal_ReadObjectFromString%") and qn = "PyMarshal_ReadObjectFromString" or
  target.getQualifiedName().matches("PyMarshal_ReadObjectFromFile%") and qn = "PyMarshal_ReadObjectFromFile" or
  target.getQualifiedName().matches("PyMarshal_ReadLastObjectFromFile%") and qn = "PyMarshal_ReadLastObjectFromFile" or
  target.getQualifiedName().matches("PyObject_Unpickle%") and qn = "PyObject_Unpickle" or
  target.getQualifiedName().matches("PyObject_Unserialize%") and qn = "PyObject_Unserialize" or
  target.getQualifiedName().matches("protobuf%::MessageLite%::ParseFromString%") and qn = "protobuf::MessageLite::ParseFromString" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("protobuf", "MessageLite") and
    memberFunc.getName() = "ParseFromString" and
    qn = "protobuf::MessageLite::ParseFromString"
  ) or
  target.getQualifiedName().matches("protobuf%::MessageLite%::ParseFromIstream%") and qn = "protobuf::MessageLite::ParseFromIstream" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("protobuf", "MessageLite") and
    memberFunc.getName() = "ParseFromIstream" and
    qn = "protobuf::MessageLite::ParseFromIstream"
  ) or
  target.getQualifiedName().matches("protobuf%::MessageLite%::ParseFromFileDescriptor%") and qn = "protobuf::MessageLite::ParseFromFileDescriptor" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("protobuf", "MessageLite") and
    memberFunc.getName() = "ParseFromFileDescriptor" and
    qn = "protobuf::MessageLite::ParseFromFileDescriptor"
  ) or
  target.getQualifiedName().matches("protobuf%::MessageLite%::MergeFromString%") and qn = "protobuf::MessageLite::MergeFromString" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("protobuf", "MessageLite") and
    memberFunc.getName() = "MergeFromString" and
    qn = "protobuf::MessageLite::MergeFromString"
  ) or
  target.getQualifiedName().matches("protobuf%::MessageLite%::MergeFromCodedStream%") and qn = "protobuf::MessageLite::MergeFromCodedStream" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("protobuf", "MessageLite") and
    memberFunc.getName() = "MergeFromCodedStream" and
    qn = "protobuf::MessageLite::MergeFromCodedStream"
  ) or
  target.getQualifiedName().matches("cereal%::BinaryInputArchive%") and qn = "cereal::BinaryInputArchive" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "cereal") and
    memberFunc.getName() = "BinaryInputArchive" and
    qn = "cereal::BinaryInputArchive"
  ) or
  target.getQualifiedName().matches("cereal%::XMLInputArchive%") and qn = "cereal::XMLInputArchive" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "cereal") and
    memberFunc.getName() = "XMLInputArchive" and
    qn = "cereal::XMLInputArchive"
  ) or
  target.getQualifiedName().matches("cereal%::JSONInputArchive%") and qn = "cereal::JSONInputArchive" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "cereal") and
    memberFunc.getName() = "JSONInputArchive" and
    qn = "cereal::JSONInputArchive"
  ) or
  target.getQualifiedName().matches("cereal%::PortableBinaryInputArchive%") and qn = "cereal::PortableBinaryInputArchive" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "cereal") and
    memberFunc.getName() = "PortableBinaryInputArchive" and
    qn = "cereal::PortableBinaryInputArchive"
  ) or
  target.getQualifiedName().matches("cereal%::load%") and qn = "cereal::load" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "cereal") and
    memberFunc.getName() = "load" and
    qn = "cereal::load"
  ) or
  target.getQualifiedName().matches("cereal%::deserialize%") and qn = "cereal::deserialize" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "cereal") and
    memberFunc.getName() = "deserialize" and
    qn = "cereal::deserialize"
  ) or
  target.getQualifiedName().matches("cereal%::make_nvp%") and qn = "cereal::make_nvp" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "cereal") and
    memberFunc.getName() = "make_nvp" and
    qn = "cereal::make_nvp"
  ) or
  target.getQualifiedName().matches("boost%::python%::import%") and qn = "boost::python::import" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost", "python") and
    memberFunc.getName() = "import" and
    qn = "boost::python::import"
  ) or
  target.getQualifiedName().matches("luaL_loadfile%") and qn = "luaL_loadfile" or
  target.getQualifiedName().matches("luaL_dofile%") and qn = "luaL_dofile" or
  target.getQualifiedName().matches("luaL_loadstring%") and qn = "luaL_loadstring" or
  target.getQualifiedName().matches("lua_load%") and qn = "lua_load" or
  target.getQualifiedName().matches("lua_pcall%") and qn = "lua_pcall" or
  target.getQualifiedName().matches("Tcl_EvalFile%") and qn = "Tcl_EvalFile" or
  target.getQualifiedName().matches("Tcl_Eval%") and qn = "Tcl_Eval" or
  target.getQualifiedName().matches("wxFileInputStream%::wxFileInputStream%") and qn = "wxFileInputStream::wxFileInputStream" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "wxFileInputStream") and
    memberFunc.getName() = "wxFileInputStream" and
    qn = "wxFileInputStream::wxFileInputStream"
  ) or
  target.getQualifiedName().matches("wxXmlDocument%::Load%") and qn = "wxXmlDocument::Load" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "wxXmlDocument") and
    memberFunc.getName() = "Load" and
    qn = "wxXmlDocument::Load"
  ) or
  target.getQualifiedName().matches("wxXmlResource%::Load%") and qn = "wxXmlResource::Load" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "wxXmlResource") and
    memberFunc.getName() = "Load" and
    qn = "wxXmlResource::Load"
  ) or
  target.getQualifiedName().matches("Unreal%::FArchive%::operator>>%") and qn = "Unreal::FArchive::operator>>" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Unreal", "FArchive") and
    memberFunc.getName() = "operator>>" and
    qn = "Unreal::FArchive::operator>>"
  ) or
  target.getQualifiedName().matches("Unreal%::FMemoryReader%::Serialize%") and qn = "Unreal::FMemoryReader::Serialize" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Unreal", "FMemoryReader") and
    memberFunc.getName() = "Serialize" and
    qn = "Unreal::FMemoryReader::Serialize"
  ) or
  target.getQualifiedName().matches("Unreal%::FObjectAndNameAsStringProxyArchive%") and qn = "Unreal::FObjectAndNameAsStringProxyArchive" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "Unreal") and
    memberFunc.getName() = "FObjectAndNameAsStringProxyArchive" and
    qn = "Unreal::FObjectAndNameAsStringProxyArchive"
  ) or
  target.getQualifiedName().matches("Unreal%::FStructuredArchive%::Slot%::operator>>%") and qn = "Unreal::FStructuredArchive::Slot::operator>>" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Unreal::FStructuredArchive", "Slot") and
    memberFunc.getName() = "operator>>" and
    qn = "Unreal::FStructuredArchive::Slot::operator>>"
  ) or
  target.getQualifiedName().matches("Unreal%::LoadPackage%") and qn = "Unreal::LoadPackage" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "Unreal") and
    memberFunc.getName() = "LoadPackage" and
    qn = "Unreal::LoadPackage"
  ) or
  target.getQualifiedName().matches("CrySerialization%::IArchive%::operator>>%") and qn = "CrySerialization::IArchive::operator>>" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("CrySerialization", "IArchive") and
    memberFunc.getName() = "operator>>" and
    qn = "CrySerialization::IArchive::operator>>"
  ) or
  target.getQualifiedName().matches("CrySerialization%::Load%") and qn = "CrySerialization::Load" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "CrySerialization") and
    memberFunc.getName() = "Load" and
    qn = "CrySerialization::Load"
  ) or
  target.getQualifiedName().matches("UE%::Serialization%::FMemoryArchive%::Serialize%") and qn = "UE::Serialization::FMemoryArchive::Serialize" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("UE::Serialization", "FMemoryArchive") and
    memberFunc.getName() = "Serialize" and
    qn = "UE::Serialization::FMemoryArchive::Serialize"
  ) or
  target.getQualifiedName().matches("OpenSSL%::d2i_X509%") and qn = "OpenSSL::d2i_X509" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "OpenSSL") and
    memberFunc.getName() = "d2i_X509" and
    qn = "OpenSSL::d2i_X509"
  ) or
  target.getQualifiedName().matches("OpenSSL%::d2i_RSAPrivateKey%") and qn = "OpenSSL::d2i_RSAPrivateKey" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "OpenSSL") and
    memberFunc.getName() = "d2i_RSAPrivateKey" and
    qn = "OpenSSL::d2i_RSAPrivateKey"
  ) or
  target.getQualifiedName().matches("OpenSSL%::d2i_DSAPrivateKey%") and qn = "OpenSSL::d2i_DSAPrivateKey" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "OpenSSL") and
    memberFunc.getName() = "d2i_DSAPrivateKey" and
    qn = "OpenSSL::d2i_DSAPrivateKey"
  ) or
  target.getQualifiedName().matches("OpenSSL%::d2i_ECPrivateKey%") and qn = "OpenSSL::d2i_ECPrivateKey" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "OpenSSL") and
    memberFunc.getName() = "d2i_ECPrivateKey" and
    qn = "OpenSSL::d2i_ECPrivateKey"
  ) or
  target.getQualifiedName().matches("OpenSSL%::d2i_PrivateKey%") and qn = "OpenSSL::d2i_PrivateKey" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "OpenSSL") and
    memberFunc.getName() = "d2i_PrivateKey" and
    qn = "OpenSSL::d2i_PrivateKey"
  ) or
  target.getQualifiedName().matches("OpenSSL%::d2i_PKCS8PrivateKey%") and qn = "OpenSSL::d2i_PKCS8PrivateKey" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "OpenSSL") and
    memberFunc.getName() = "d2i_PKCS8PrivateKey" and
    qn = "OpenSSL::d2i_PKCS8PrivateKey"
  ) or
  target.getQualifiedName().matches("OpenSSL%::d2i_X509_REQ%") and qn = "OpenSSL::d2i_X509_REQ" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "OpenSSL") and
    memberFunc.getName() = "d2i_X509_REQ" and
    qn = "OpenSSL::d2i_X509_REQ"
  ) or
  target.getQualifiedName().matches("OpenSSL%::d2i_X509_CRL%") and qn = "OpenSSL::d2i_X509_CRL" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "OpenSSL") and
    memberFunc.getName() = "d2i_X509_CRL" and
    qn = "OpenSSL::d2i_X509_CRL"
  ) or
  target.getQualifiedName().matches("OpenSSL%::d2i_PKCS7%") and qn = "OpenSSL::d2i_PKCS7" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "OpenSSL") and
    memberFunc.getName() = "d2i_PKCS7" and
    qn = "OpenSSL::d2i_PKCS7"
  ) or
  target.getQualifiedName().matches("libxml2%::xmlReadFile%") and qn = "libxml2::xmlReadFile" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "libxml2") and
    memberFunc.getName() = "xmlReadFile" and
    qn = "libxml2::xmlReadFile"
  ) or
  target.getQualifiedName().matches("libxml2%::xmlReadMemory%") and qn = "libxml2::xmlReadMemory" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "libxml2") and
    memberFunc.getName() = "xmlReadMemory" and
    qn = "libxml2::xmlReadMemory"
  ) or
  target.getQualifiedName().matches("libxml2%::xmlParseFile%") and qn = "libxml2::xmlParseFile" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "libxml2") and
    memberFunc.getName() = "xmlParseFile" and
    qn = "libxml2::xmlParseFile"
  ) or
  target.getQualifiedName().matches("libxml2%::xmlParseMemory%") and qn = "libxml2::xmlParseMemory" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "libxml2") and
    memberFunc.getName() = "xmlParseMemory" and
    qn = "libxml2::xmlParseMemory"
  ) or
  target.getQualifiedName().matches("libxml2%::xmlSAXUserParseFile%") and qn = "libxml2::xmlSAXUserParseFile" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "libxml2") and
    memberFunc.getName() = "xmlSAXUserParseFile" and
    qn = "libxml2::xmlSAXUserParseFile"
  ) or
  target.getQualifiedName().matches("libxml2%::xmlSAXUserParseMemory%") and qn = "libxml2::xmlSAXUserParseMemory" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "libxml2") and
    memberFunc.getName() = "xmlSAXUserParseMemory" and
    qn = "libxml2::xmlSAXUserParseMemory"
  ) or
  target.getQualifiedName().matches("OpenCV%::FileStorage%::open%") and qn = "OpenCV::FileStorage::open" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("OpenCV", "FileStorage") and
    memberFunc.getName() = "open" and
    qn = "OpenCV::FileStorage::open"
  ) or
  target.getQualifiedName().matches("OpenCV%::FileStorage%::operator>>%") and qn = "OpenCV::FileStorage::operator>>" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("OpenCV", "FileStorage") and
    memberFunc.getName() = "operator>>" and
    qn = "OpenCV::FileStorage::operator>>"
  ) or
  target.getQualifiedName().matches("OpenCV%::FileNode%::operator>>%") and qn = "OpenCV::FileNode::operator>>" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("OpenCV", "FileNode") and
    memberFunc.getName() = "operator>>" and
    qn = "OpenCV::FileNode::operator>>"
  ) or
  target.getQualifiedName().matches("archive_read_open_filename%") and qn = "archive_read_open_filename" or
  target.getQualifiedName().matches("archive_read_data%") and qn = "archive_read_data" or
  target.getQualifiedName().matches("archive_read_extract%") and qn = "archive_read_extract" or
  target.getQualifiedName().matches("archive_read_next_header%") and qn = "archive_read_next_header"
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
