// Auto-generated; CWE-377; number of APIs 73
import java

predicate isTargetApi(Callable target, string qn) {
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("java.io", "File") and
    qn = "java.io.File.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.io", "File") and
    m.getName() = "createNewFile" and
    qn = "java.io.File.createNewFile"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.io", "File") and
    m.getName() = "deleteOnExit" and
    qn = "java.io.File.deleteOnExit"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.io", "File") and
    m.getName() = "mkdir" and
    qn = "java.io.File.mkdir"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.io", "File") and
    m.getName() = "mkdirs" and
    qn = "java.io.File.mkdirs"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.io", "File") and
    m.getName() = "renameTo" and
    qn = "java.io.File.renameTo"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.io", "File") and
    m.getName() = "exists" and
    qn = "java.io.File.exists"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("java.io", "FileInputStream") and
    qn = "java.io.FileInputStream.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("java.io", "FileOutputStream") and
    qn = "java.io.FileOutputStream.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("java.io", "FileReader") and
    qn = "java.io.FileReader.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("java.io", "FileWriter") and
    qn = "java.io.FileWriter.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("java.io", "RandomAccessFile") and
    qn = "java.io.RandomAccessFile.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.nio.file", "Files") and
    m.getName() = "createTempFile" and
    qn = "java.nio.file.Files.createTempFile"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.nio.file", "Files") and
    m.getName() = "createTempDirectory" and
    qn = "java.nio.file.Files.createTempDirectory"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.nio.file", "Files") and
    m.getName() = "createFile" and
    qn = "java.nio.file.Files.createFile"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.nio.file", "Files") and
    m.getName() = "createDirectory" and
    qn = "java.nio.file.Files.createDirectory"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.nio.file", "Files") and
    m.getName() = "createDirectories" and
    qn = "java.nio.file.Files.createDirectories"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.nio.file", "Files") and
    m.getName() = "newOutputStream" and
    qn = "java.nio.file.Files.newOutputStream"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.nio.file", "Files") and
    m.getName() = "newByteChannel" and
    qn = "java.nio.file.Files.newByteChannel"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.nio.file", "Files") and
    m.getName() = "write" and
    qn = "java.nio.file.Files.write"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.nio.file", "Files") and
    m.getName() = "writeString" and
    qn = "java.nio.file.Files.writeString"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.nio.file", "Files") and
    m.getName() = "copy" and
    qn = "java.nio.file.Files.copy"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.nio.file", "Files") and
    m.getName() = "move" and
    qn = "java.nio.file.Files.move"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.nio.file", "Files") and
    m.getName() = "delete" and
    qn = "java.nio.file.Files.delete"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.nio.file", "Files") and
    m.getName() = "deleteIfExists" and
    qn = "java.nio.file.Files.deleteIfExists"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.nio.file", "Files") and
    m.getName() = "setPosixFilePermissions" and
    qn = "java.nio.file.Files.setPosixFilePermissions"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.nio.file", "Files") and
    m.getName() = "setAttribute" and
    qn = "java.nio.file.Files.setAttribute"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.nio.file", "Files") and
    m.getName() = "createSymbolicLink" and
    qn = "java.nio.file.Files.createSymbolicLink"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.nio.file", "Files") and
    m.getName() = "createLink" and
    qn = "java.nio.file.Files.createLink"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.nio.file", "Path") and
    m.getName() = "resolve" and
    qn = "java.nio.file.Path.resolve"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.nio.file", "Path") and
    m.getName() = "toAbsolutePath" and
    qn = "java.nio.file.Path.toAbsolutePath"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.nio.file", "Path") and
    m.getName() = "toRealPath" and
    qn = "java.nio.file.Path.toRealPath"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.nio.file", "Paths") and
    m.getName() = "get" and
    qn = "java.nio.file.Paths.get"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.nio.file", "Path") and
    m.getName() = "of" and
    qn = "java.nio.file.Path.of"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.io", "File") and
    m.getName() = "createTempFile" and
    qn = "java.io.File.createTempFile"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.io", "FileUtils") and
    m.getName() = "getTempDirectory" and
    qn = "org.apache.commons.io.FileUtils.getTempDirectory"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.io", "FileUtils") and
    m.getName() = "getTempDirectoryPath" and
    qn = "org.apache.commons.io.FileUtils.getTempDirectoryPath"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.io", "FileUtils") and
    m.getName() = "getTempFile" and
    qn = "org.apache.commons.io.FileUtils.getTempFile"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.io", "FileUtils") and
    m.getName() = "openOutputStream" and
    qn = "org.apache.commons.io.FileUtils.openOutputStream"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.io", "FileUtils") and
    m.getName() = "touch" and
    qn = "org.apache.commons.io.FileUtils.touch"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.io", "FileUtils") and
    m.getName() = "writeStringToFile" and
    qn = "org.apache.commons.io.FileUtils.writeStringToFile"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.io", "FileUtils") and
    m.getName() = "writeByteArrayToFile" and
    qn = "org.apache.commons.io.FileUtils.writeByteArrayToFile"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.io", "FileUtils") and
    m.getName() = "copyFile" and
    qn = "org.apache.commons.io.FileUtils.copyFile"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.io", "FileUtils") and
    m.getName() = "moveFile" and
    qn = "org.apache.commons.io.FileUtils.moveFile"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.io", "FileUtils") and
    m.getName() = "forceMkdir" and
    qn = "org.apache.commons.io.FileUtils.forceMkdir"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.io", "FileUtils") and
    m.getName() = "forceDelete" and
    qn = "org.apache.commons.io.FileUtils.forceDelete"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.io", "FileUtils") and
    m.getName() = "deleteQuietly" and
    qn = "org.apache.commons.io.FileUtils.deleteQuietly"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.io", "FilenameUtils") and
    m.getName() = "getName" and
    qn = "org.apache.commons.io.FilenameUtils.getName"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.io", "FilenameUtils") and
    m.getName() = "normalize" and
    qn = "org.apache.commons.io.FilenameUtils.normalize"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.google.common.io", "Files") and
    m.getName() = "createTempDir" and
    qn = "com.google.common.io.Files.createTempDir"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.google.common.io", "Files") and
    m.getName() = "touch" and
    qn = "com.google.common.io.Files.touch"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.google.common.io", "Files") and
    m.getName() = "write" and
    qn = "com.google.common.io.Files.write"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.google.common.io", "Files") and
    m.getName() = "append" and
    qn = "com.google.common.io.Files.append"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.google.common.io", "Files") and
    m.getName() = "copy" and
    qn = "com.google.common.io.Files.copy"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.google.common.io", "Files") and
    m.getName() = "move" and
    qn = "com.google.common.io.Files.move"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.util", "FileCopyUtils") and
    m.getName() = "copy" and
    qn = "org.springframework.util.FileCopyUtils.copy"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.util", "StreamUtils") and
    m.getName() = "copy" and
    qn = "org.springframework.util.StreamUtils.copy"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("okio", "FileSystem") and
    m.getName() = "createDirectories" and
    qn = "okio.FileSystem.createDirectories"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("okio", "FileSystem") and
    m.getName() = "sink" and
    qn = "okio.FileSystem.sink"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("okio", "FileSystem") and
    m.getName() = "appendingSink" and
    qn = "okio.FileSystem.appendingSink"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("okio", "FileSystem") and
    m.getName() = "atomicMove" and
    qn = "okio.FileSystem.atomicMove"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("okio", "Path") and
    qn = "okio.Path.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.util", "UUID") and
    m.getName() = "randomUUID" and
    qn = "java.util.UUID.randomUUID"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("java.util", "Random") and
    qn = "java.util.Random.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.util", "Random") and
    m.getName() = "nextInt" and
    qn = "java.util.Random.nextInt"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("java.security", "SecureRandom") and
    qn = "java.security.SecureRandom.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.security", "SecureRandom") and
    m.getName() = "nextBytes" and
    qn = "java.security.SecureRandom.nextBytes"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.lang3", "RandomStringUtils") and
    m.getName() = "random" and
    qn = "org.apache.commons.lang3.RandomStringUtils.random"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.lang3", "RandomStringUtils") and
    m.getName() = "randomAlphabetic" and
    qn = "org.apache.commons.lang3.RandomStringUtils.randomAlphabetic"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.lang3", "RandomStringUtils") and
    m.getName() = "randomAlphanumeric" and
    qn = "org.apache.commons.lang3.RandomStringUtils.randomAlphanumeric"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.text", "RandomStringGenerator") and
    m.getName() = "generate" and
    qn = "org.apache.commons.text.RandomStringGenerator.generate"
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
