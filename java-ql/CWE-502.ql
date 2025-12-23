// Auto-generated; CWE-502; number of APIs 103
import java

predicate isTargetApi(Callable target, string qn) {
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("java.io", "ObjectInputStream") and
    qn = "java.io.ObjectInputStream.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.io", "ObjectInputStream") and
    m.getName() = "readObject" and
    qn = "java.io.ObjectInputStream.readObject"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.io", "ObjectInputStream") and
    m.getName() = "readUnshared" and
    qn = "java.io.ObjectInputStream.readUnshared"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.io", "ObjectInputStream") and
    m.getName() = "resolveClass" and
    qn = "java.io.ObjectInputStream.resolveClass"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.io", "ObjectInputStream") and
    m.getName() = "resolveProxyClass" and
    qn = "java.io.ObjectInputStream.resolveProxyClass"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.io", "ObjectInputStream") and
    m.getName() = "readClassDescriptor" and
    qn = "java.io.ObjectInputStream.readClassDescriptor"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.io", "ObjectInputStream") and
    m.getName() = "readFields" and
    qn = "java.io.ObjectInputStream.readFields"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("java.io", "ObjectOutputStream") and
    qn = "java.io.ObjectOutputStream.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.io", "ObjectOutputStream") and
    m.getName() = "writeObject" and
    qn = "java.io.ObjectOutputStream.writeObject"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.io", "ObjectOutputStream") and
    m.getName() = "writeUnshared" and
    qn = "java.io.ObjectOutputStream.writeUnshared"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.io", "ObjectOutputStream") and
    m.getName() = "reset" and
    qn = "java.io.ObjectOutputStream.reset"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.io", "ObjectOutputStream") and
    m.getName() = "writeObjectOverride" and
    qn = "java.io.ObjectOutputStream.writeObjectOverride"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.io", "ObjectStreamClass") and
    m.getName() = "lookup" and
    qn = "java.io.ObjectStreamClass.lookup"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.io", "ObjectStreamClass") and
    m.getName() = "lookupAny" and
    qn = "java.io.ObjectStreamClass.lookupAny"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.io", "ObjectStreamClass") and
    m.getName() = "forClass" and
    qn = "java.io.ObjectStreamClass.forClass"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.io", "ObjectStreamClass") and
    m.getName() = "getName" and
    qn = "java.io.ObjectStreamClass.getName"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.io", "ObjectStreamClass") and
    m.getName() = "getSerialVersionUID" and
    qn = "java.io.ObjectStreamClass.getSerialVersionUID"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("java.beans", "XMLDecoder") and
    qn = "java.beans.XMLDecoder.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.beans", "XMLDecoder") and
    m.getName() = "readObject" and
    qn = "java.beans.XMLDecoder.readObject"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("java.beans", "XMLEncoder") and
    qn = "java.beans.XMLEncoder.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.beans", "XMLEncoder") and
    m.getName() = "writeObject" and
    qn = "java.beans.XMLEncoder.writeObject"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("com.thoughtworks.xstream", "XStream") and
    qn = "com.thoughtworks.xstream.XStream.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.thoughtworks.xstream", "XStream") and
    m.getName() = "fromXML" and
    qn = "com.thoughtworks.xstream.XStream.fromXML"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.thoughtworks.xstream", "XStream") and
    m.getName() = "unmarshal" and
    qn = "com.thoughtworks.xstream.XStream.unmarshal"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("com.thoughtworks.xstream.io.xml", "DomDriver") and
    qn = "com.thoughtworks.xstream.io.xml.DomDriver.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("com.thoughtworks.xstream.io.xml", "StaxDriver") and
    qn = "com.thoughtworks.xstream.io.xml.StaxDriver.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.thoughtworks.xstream.security", "AnyTypePermission") and
    m.getName() = "ANY" and
    qn = "com.thoughtworks.xstream.security.AnyTypePermission.ANY"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.thoughtworks.xstream.security", "NoTypePermission") and
    m.getName() = "NONE" and
    qn = "com.thoughtworks.xstream.security.NoTypePermission.NONE"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.thoughtworks.xstream.security", "TypePermission") and
    m.getName() = "allows" and
    qn = "com.thoughtworks.xstream.security.TypePermission.allows"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("com.thoughtworks.xstream.security", "WildcardTypePermission") and
    qn = "com.thoughtworks.xstream.security.WildcardTypePermission.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("com.thoughtworks.xstream.security", "ExplicitTypePermission") and
    qn = "com.thoughtworks.xstream.security.ExplicitTypePermission.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.apache.commons.collections4.functors", "InvokerTransformer") and
    qn = "org.apache.commons.collections4.functors.InvokerTransformer.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.apache.commons.collections4.functors", "InstantiateTransformer") and
    qn = "org.apache.commons.collections4.functors.InstantiateTransformer.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.apache.commons.collections4.functors", "ChainedTransformer") and
    qn = "org.apache.commons.collections4.functors.ChainedTransformer.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.apache.commons.collections4.comparators", "TransformingComparator") and
    qn = "org.apache.commons.collections4.comparators.TransformingComparator.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.collections4.map", "LazyMap") and
    m.getName() = "decorate" and
    qn = "org.apache.commons.collections4.map.LazyMap.decorate"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.collections4.map", "TransformedMap") and
    m.getName() = "decorate" and
    qn = "org.apache.commons.collections4.map.TransformedMap.decorate"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.collections4.set", "TransformedSet") and
    m.getName() = "decorate" and
    qn = "org.apache.commons.collections4.set.TransformedSet.decorate"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.apache.commons.collections.functors", "InvokerTransformer") and
    qn = "org.apache.commons.collections.functors.InvokerTransformer.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.apache.commons.collections.functors", "InstantiateTransformer") and
    qn = "org.apache.commons.collections.functors.InstantiateTransformer.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.apache.commons.collections.functors", "ChainedTransformer") and
    qn = "org.apache.commons.collections.functors.ChainedTransformer.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.apache.commons.collections.comparators", "TransformingComparator") and
    qn = "org.apache.commons.collections.comparators.TransformingComparator.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.collections.map", "LazyMap") and
    m.getName() = "decorate" and
    qn = "org.apache.commons.collections.map.LazyMap.decorate"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.collections.map", "TransformedMap") and
    m.getName() = "decorate" and
    qn = "org.apache.commons.collections.map.TransformedMap.decorate"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.collections.set", "TransformedSet") and
    m.getName() = "decorate" and
    qn = "org.apache.commons.collections.set.TransformedSet.decorate"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("com.caucho.hessian.io", "HessianInput") and
    qn = "com.caucho.hessian.io.HessianInput.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.caucho.hessian.io", "HessianInput") and
    m.getName() = "readObject" and
    qn = "com.caucho.hessian.io.HessianInput.readObject"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("com.caucho.hessian.io", "Hessian2Input") and
    qn = "com.caucho.hessian.io.Hessian2Input.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.caucho.hessian.io", "Hessian2Input") and
    m.getName() = "readObject" and
    qn = "com.caucho.hessian.io.Hessian2Input.readObject"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("com.caucho.hessian.io", "SerializerFactory") and
    qn = "com.caucho.hessian.io.SerializerFactory.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.caucho.hessian.io", "SerializerFactory") and
    m.getName() = "setAllowNonSerializable" and
    qn = "com.caucho.hessian.io.SerializerFactory.setAllowNonSerializable"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.springframework.remoting.rmi", "RmiServiceExporter") and
    qn = "org.springframework.remoting.rmi.RmiServiceExporter.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.remoting.rmi", "RmiServiceExporter") and
    m.getName() = "setServiceInterface" and
    qn = "org.springframework.remoting.rmi.RmiServiceExporter.setServiceInterface"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.remoting.rmi", "RmiServiceExporter") and
    m.getName() = "setService" and
    qn = "org.springframework.remoting.rmi.RmiServiceExporter.setService"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.springframework.remoting.rmi", "RmiProxyFactoryBean") and
    qn = "org.springframework.remoting.rmi.RmiProxyFactoryBean.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.remoting.rmi", "RmiProxyFactoryBean") and
    m.getName() = "afterPropertiesSet" and
    qn = "org.springframework.remoting.rmi.RmiProxyFactoryBean.afterPropertiesSet"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.springframework.remoting.httpinvoker", "HttpInvokerServiceExporter") and
    qn = "org.springframework.remoting.httpinvoker.HttpInvokerServiceExporter.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.remoting.httpinvoker", "HttpInvokerServiceExporter") and
    m.getName() = "handleRequest" and
    qn = "org.springframework.remoting.httpinvoker.HttpInvokerServiceExporter.handleRequest"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.remoting.httpinvoker", "HttpInvokerServiceExporter") and
    m.getName() = "readRemoteInvocation" and
    qn = "org.springframework.remoting.httpinvoker.HttpInvokerServiceExporter.readRemoteInvocation"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.remoting.httpinvoker", "HttpInvokerRequestExecutor") and
    m.getName() = "executeRequest" and
    qn = "org.springframework.remoting.httpinvoker.HttpInvokerRequestExecutor.executeRequest"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.remoting.httpinvoker", "SimpleHttpInvokerRequestExecutor") and
    m.getName() = "executeRequest" and
    qn = "org.springframework.remoting.httpinvoker.SimpleHttpInvokerRequestExecutor.executeRequest"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.springframework.remoting.httpinvoker", "HttpInvokerProxyFactoryBean") and
    qn = "org.springframework.remoting.httpinvoker.HttpInvokerProxyFactoryBean.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.remoting.httpinvoker", "HttpInvokerProxyFactoryBean") and
    m.getName() = "afterPropertiesSet" and
    qn = "org.springframework.remoting.httpinvoker.HttpInvokerProxyFactoryBean.afterPropertiesSet"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.springframework.core.serializer", "DefaultDeserializer") and
    qn = "org.springframework.core.serializer.DefaultDeserializer.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.core.serializer", "DefaultDeserializer") and
    m.getName() = "deserialize" and
    qn = "org.springframework.core.serializer.DefaultDeserializer.deserialize"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.springframework.core.serializer.support", "DeserializingConverter") and
    qn = "org.springframework.core.serializer.support.DeserializingConverter.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.core.serializer.support", "DeserializingConverter") and
    m.getName() = "convert" and
    qn = "org.springframework.core.serializer.support.DeserializingConverter.convert"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.core.serializer.support", "SerializationDelegate") and
    m.getName() = "deserialize" and
    qn = "org.springframework.core.serializer.support.SerializationDelegate.deserialize"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.core.serializer.support", "SerializationDelegate") and
    m.getName() = "serialize" and
    qn = "org.springframework.core.serializer.support.SerializationDelegate.serialize"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.fasterxml.jackson.databind", "ObjectMapper") and
    m.getName() = "readValue" and
    qn = "com.fasterxml.jackson.databind.ObjectMapper.readValue"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.fasterxml.jackson.databind", "ObjectMapper") and
    m.getName() = "readerFor" and
    qn = "com.fasterxml.jackson.databind.ObjectMapper.readerFor"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.fasterxml.jackson.databind", "ObjectMapper") and
    m.getName() = "readerForUpdating" and
    qn = "com.fasterxml.jackson.databind.ObjectMapper.readerForUpdating"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.fasterxml.jackson.databind", "ObjectReader") and
    m.getName() = "readValue" and
    qn = "com.fasterxml.jackson.databind.ObjectReader.readValue"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.fasterxml.jackson.databind", "ObjectMapper") and
    m.getName() = "enableDefaultTyping" and
    qn = "com.fasterxml.jackson.databind.ObjectMapper.enableDefaultTyping"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.fasterxml.jackson.databind", "ObjectMapper") and
    m.getName() = "activateDefaultTyping" and
    qn = "com.fasterxml.jackson.databind.ObjectMapper.activateDefaultTyping"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.fasterxml.jackson.databind", "ObjectMapper") and
    m.getName() = "activateDefaultTypingAsProperty" and
    qn = "com.fasterxml.jackson.databind.ObjectMapper.activateDefaultTypingAsProperty"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("com.fasterxml.jackson.databind.jsontype.impl", "LaissezFaireSubTypeValidator") and
    qn = "com.fasterxml.jackson.databind.jsontype.impl.LaissezFaireSubTypeValidator.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.fasterxml.jackson.dataformat.xml", "XmlMapper") and
    m.getName() = "readValue" and
    qn = "com.fasterxml.jackson.dataformat.xml.XmlMapper.readValue"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.fasterxml.jackson.dataformat.yaml", "YAMLMapper") and
    m.getName() = "readValue" and
    qn = "com.fasterxml.jackson.dataformat.yaml.YAMLMapper.readValue"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.alibaba.fastjson", "JSON") and
    m.getName() = "parseObject" and
    qn = "com.alibaba.fastjson.JSON.parseObject"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.alibaba.fastjson", "JSON") and
    m.getName() = "parse" and
    qn = "com.alibaba.fastjson.JSON.parse"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.alibaba.fastjson", "JSONObject") and
    m.getName() = "parseObject" and
    qn = "com.alibaba.fastjson.JSONObject.parseObject"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.alibaba.fastjson.parser", "ParserConfig") and
    m.getName() = "setAutoTypeSupport" and
    qn = "com.alibaba.fastjson.parser.ParserConfig.setAutoTypeSupport"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.alibaba.fastjson.parser", "ParserConfig") and
    m.getName() = "addAccept" and
    qn = "com.alibaba.fastjson.parser.ParserConfig.addAccept"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.alibaba.fastjson.parser", "ParserConfig") and
    m.getName() = "setSafeMode" and
    qn = "com.alibaba.fastjson.parser.ParserConfig.setSafeMode"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("com.esotericsoftware.kryo", "Kryo") and
    qn = "com.esotericsoftware.kryo.Kryo.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.esotericsoftware.kryo", "Kryo") and
    m.getName() = "readClassAndObject" and
    qn = "com.esotericsoftware.kryo.Kryo.readClassAndObject"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.esotericsoftware.kryo", "Kryo") and
    m.getName() = "readObject" and
    qn = "com.esotericsoftware.kryo.Kryo.readObject"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("com.esotericsoftware.kryo.io", "Input") and
    qn = "com.esotericsoftware.kryo.io.Input.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.esotericsoftware.kryo.io", "Input") and
    m.getName() = "readBytes" and
    qn = "com.esotericsoftware.kryo.io.Input.readBytes"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.esotericsoftware.kryo.io", "Input") and
    m.getName() = "readString" and
    qn = "com.esotericsoftware.kryo.io.Input.readString"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.yaml.snakeyaml", "Yaml") and
    qn = "org.yaml.snakeyaml.Yaml.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.yaml.snakeyaml", "Yaml") and
    m.getName() = "load" and
    qn = "org.yaml.snakeyaml.Yaml.load"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.yaml.snakeyaml", "Yaml") and
    m.getName() = "loadAs" and
    qn = "org.yaml.snakeyaml.Yaml.loadAs"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.yaml.snakeyaml", "Yaml") and
    m.getName() = "loadAll" and
    qn = "org.yaml.snakeyaml.Yaml.loadAll"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.yaml.snakeyaml.constructor", "Constructor") and
    qn = "org.yaml.snakeyaml.constructor.Constructor.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.yaml.snakeyaml.constructor", "SafeConstructor") and
    qn = "org.yaml.snakeyaml.constructor.SafeConstructor.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.apache.commons.configuration2.io", "ConfigurationReader") and
    qn = "org.apache.commons.configuration2.io.ConfigurationReader.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.configuration2.builder.fluent", "Configurations") and
    m.getName() = "properties" and
    qn = "org.apache.commons.configuration2.builder.fluent.Configurations.properties"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.configuration2.builder.fluent", "Configurations") and
    m.getName() = "xml" and
    qn = "org.apache.commons.configuration2.builder.fluent.Configurations.xml"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.configuration2.builder.fluent", "Configurations") and
    m.getName() = "yaml" and
    qn = "org.apache.commons.configuration2.builder.fluent.Configurations.yaml"
  )
}

from Call call, Callable targetFunc, Callable enclosingFunc, string qn, ControlFlowNode node
where
  targetFunc = call.getCallee() and
  isTargetApi(targetFunc, qn) and
  enclosingFunc = call.getEnclosingCallable() and
  enclosingFunc.fromSource() and
  node.asExpr() = call
select
  "Path: " + call.getLocation().getFile().getAbsolutePath(),
  "call function: " +
    call.getLocation().getStartLine().toString() + ":" + call.getLocation().getStartColumn().toString() +
    "-" + call.getLocation().getEndLine().toString() + ":" + call.getLocation().getEndColumn().toString(),
  "call in function: " + enclosingFunc.getName() + "@" +
    enclosingFunc.getLocation().getStartLine().toString() + "-" +
    enclosingFunc.getBody().getLocation().getEndLine().toString(),
  "callee=" + qn,
  "basic block: " +
    node.getLocation().getStartLine().toString() + ":" + node.getLocation().getStartColumn().toString() + "-" +
    node.getLocation().getEndLine().toString() + ":" + node.getLocation().getEndColumn().toString()
