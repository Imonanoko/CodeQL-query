// Auto-generated; CWE-022; number of APIs 196
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
    m.getName() = "toPath" and
    qn = "java.io.File.toPath"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.io", "File") and
    m.getName() = "getCanonicalPath" and
    qn = "java.io.File.getCanonicalPath"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.io", "File") and
    m.getName() = "getCanonicalFile" and
    qn = "java.io.File.getCanonicalFile"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.io", "File") and
    m.getName() = "getAbsolutePath" and
    qn = "java.io.File.getAbsolutePath"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.io", "File") and
    m.getName() = "getAbsoluteFile" and
    qn = "java.io.File.getAbsoluteFile"
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
    m.getName() = "delete" and
    qn = "java.io.File.delete"
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
    m.getName() = "list" and
    qn = "java.io.File.list"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.io", "File") and
    m.getName() = "listFiles" and
    qn = "java.io.File.listFiles"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.io", "File") and
    m.getName() = "listRoots" and
    qn = "java.io.File.listRoots"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.io", "File") and
    m.getName() = "canRead" and
    qn = "java.io.File.canRead"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.io", "File") and
    m.getName() = "canWrite" and
    qn = "java.io.File.canWrite"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.io", "File") and
    m.getName() = "canExecute" and
    qn = "java.io.File.canExecute"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.io", "File") and
    m.getName() = "exists" and
    qn = "java.io.File.exists"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.io", "File") and
    m.getName() = "isFile" and
    qn = "java.io.File.isFile"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.io", "File") and
    m.getName() = "isDirectory" and
    qn = "java.io.File.isDirectory"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.io", "File") and
    m.getName() = "length" and
    qn = "java.io.File.length"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.io", "File") and
    m.getName() = "lastModified" and
    qn = "java.io.File.lastModified"
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
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("java.io", "PrintWriter") and
    qn = "java.io.PrintWriter.<init>"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("java.util", "Scanner") and
    qn = "java.util.Scanner.<init>"
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
    m.getDeclaringType().hasQualifiedName("java.nio.file", "FileSystems") and
    m.getName() = "getDefault" and
    qn = "java.nio.file.FileSystems.getDefault"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.nio.file", "FileSystem") and
    m.getName() = "getPath" and
    qn = "java.nio.file.FileSystem.getPath"
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
    m.getName() = "resolveSibling" and
    qn = "java.nio.file.Path.resolveSibling"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.nio.file", "Path") and
    m.getName() = "normalize" and
    qn = "java.nio.file.Path.normalize"
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
    m.getDeclaringType().hasQualifiedName("java.nio.file", "Path") and
    m.getName() = "relativize" and
    qn = "java.nio.file.Path.relativize"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.nio.file", "Path") and
    m.getName() = "subpath" and
    qn = "java.nio.file.Path.subpath"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.nio.file", "Path") and
    m.getName() = "startsWith" and
    qn = "java.nio.file.Path.startsWith"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.nio.file", "Files") and
    m.getName() = "newInputStream" and
    qn = "java.nio.file.Files.newInputStream"
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
    m.getName() = "newDirectoryStream" and
    qn = "java.nio.file.Files.newDirectoryStream"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.nio.file", "Files") and
    m.getName() = "newBufferedReader" and
    qn = "java.nio.file.Files.newBufferedReader"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.nio.file", "Files") and
    m.getName() = "newBufferedWriter" and
    qn = "java.nio.file.Files.newBufferedWriter"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.nio.file", "Files") and
    m.getName() = "readAllBytes" and
    qn = "java.nio.file.Files.readAllBytes"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.nio.file", "Files") and
    m.getName() = "readAllLines" and
    qn = "java.nio.file.Files.readAllLines"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.nio.file", "Files") and
    m.getName() = "readString" and
    qn = "java.nio.file.Files.readString"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.nio.file", "Files") and
    m.getName() = "lines" and
    qn = "java.nio.file.Files.lines"
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
    m.getName() = "walk" and
    qn = "java.nio.file.Files.walk"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.nio.file", "Files") and
    m.getName() = "list" and
    qn = "java.nio.file.Files.list"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.nio.file", "Files") and
    m.getName() = "find" and
    qn = "java.nio.file.Files.find"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.nio.file", "Files") and
    m.getName() = "walkFileTree" and
    qn = "java.nio.file.Files.walkFileTree"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.nio.file", "Files") and
    m.getName() = "exists" and
    qn = "java.nio.file.Files.exists"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.nio.file", "Files") and
    m.getName() = "isDirectory" and
    qn = "java.nio.file.Files.isDirectory"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.nio.file", "Files") and
    m.getName() = "isRegularFile" and
    qn = "java.nio.file.Files.isRegularFile"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.nio.file", "Files") and
    m.getName() = "isReadable" and
    qn = "java.nio.file.Files.isReadable"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.nio.file", "Files") and
    m.getName() = "isWritable" and
    qn = "java.nio.file.Files.isWritable"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.nio.file", "Files") and
    m.getName() = "isExecutable" and
    qn = "java.nio.file.Files.isExecutable"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.nio.file", "Files") and
    m.getName() = "readAttributes" and
    qn = "java.nio.file.Files.readAttributes"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.nio.file", "Files") and
    m.getName() = "getAttribute" and
    qn = "java.nio.file.Files.getAttribute"
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
    m.getName() = "getLastModifiedTime" and
    qn = "java.nio.file.Files.getLastModifiedTime"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.nio.file", "Files") and
    m.getName() = "setLastModifiedTime" and
    qn = "java.nio.file.Files.setLastModifiedTime"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.nio.file", "Files") and
    m.getName() = "getOwner" and
    qn = "java.nio.file.Files.getOwner"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.nio.file", "Files") and
    m.getName() = "setOwner" and
    qn = "java.nio.file.Files.setOwner"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.nio.file", "Files") and
    m.getName() = "getPosixFilePermissions" and
    qn = "java.nio.file.Files.getPosixFilePermissions"
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
    m.getDeclaringType().hasQualifiedName("java.nio.channels", "FileChannel") and
    m.getName() = "open" and
    qn = "java.nio.channels.FileChannel.open"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.nio.channels", "AsynchronousFileChannel") and
    m.getName() = "open" and
    qn = "java.nio.channels.AsynchronousFileChannel.open"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("java.util.zip", "ZipFile") and
    qn = "java.util.zip.ZipFile.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.util.zip", "ZipFile") and
    m.getName() = "getInputStream" and
    qn = "java.util.zip.ZipFile.getInputStream"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.util.zip", "ZipFile") and
    m.getName() = "entries" and
    qn = "java.util.zip.ZipFile.entries"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.util.zip", "ZipFile") and
    m.getName() = "getEntry" and
    qn = "java.util.zip.ZipFile.getEntry"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.util.zip", "ZipInputStream") and
    m.getName() = "getNextEntry" and
    qn = "java.util.zip.ZipInputStream.getNextEntry"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.util.zip", "ZipEntry") and
    m.getName() = "getName" and
    qn = "java.util.zip.ZipEntry.getName"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("java.util.jar", "JarFile") and
    qn = "java.util.jar.JarFile.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.util.jar", "JarFile") and
    m.getName() = "getInputStream" and
    qn = "java.util.jar.JarFile.getInputStream"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.util.jar", "JarFile") and
    m.getName() = "entries" and
    qn = "java.util.jar.JarFile.entries"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.util.jar", "JarFile") and
    m.getName() = "getJarEntry" and
    qn = "java.util.jar.JarFile.getJarEntry"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.util.jar", "JarInputStream") and
    m.getName() = "getNextJarEntry" and
    qn = "java.util.jar.JarInputStream.getNextJarEntry"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.util.jar", "JarEntry") and
    m.getName() = "getName" and
    qn = "java.util.jar.JarEntry.getName"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.lang", "Class") and
    m.getName() = "getResource" and
    qn = "java.lang.Class.getResource"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.lang", "Class") and
    m.getName() = "getResourceAsStream" and
    qn = "java.lang.Class.getResourceAsStream"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.lang", "ClassLoader") and
    m.getName() = "getResource" and
    qn = "java.lang.ClassLoader.getResource"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.lang", "ClassLoader") and
    m.getName() = "getResourceAsStream" and
    qn = "java.lang.ClassLoader.getResourceAsStream"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.net", "URL") and
    m.getName() = "openStream" and
    qn = "java.net.URL.openStream"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.servlet.http", "HttpServletRequest") and
    m.getName() = "getParameter" and
    qn = "jakarta.servlet.http.HttpServletRequest.getParameter"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.servlet.http", "HttpServletRequest") and
    m.getName() = "getParameterValues" and
    qn = "jakarta.servlet.http.HttpServletRequest.getParameterValues"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.servlet.http", "HttpServletRequest") and
    m.getName() = "getPathInfo" and
    qn = "jakarta.servlet.http.HttpServletRequest.getPathInfo"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.servlet.http", "HttpServletRequest") and
    m.getName() = "getServletPath" and
    qn = "jakarta.servlet.http.HttpServletRequest.getServletPath"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.servlet.http", "HttpServletRequest") and
    m.getName() = "getRequestURI" and
    qn = "jakarta.servlet.http.HttpServletRequest.getRequestURI"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.servlet.http", "HttpServletRequest") and
    m.getName() = "getQueryString" and
    qn = "jakarta.servlet.http.HttpServletRequest.getQueryString"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.servlet.http", "HttpServletRequest") and
    m.getName() = "getHeader" and
    qn = "jakarta.servlet.http.HttpServletRequest.getHeader"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("jakarta.servlet.http", "Part") and
    m.getName() = "getSubmittedFileName" and
    qn = "jakarta.servlet.http.Part.getSubmittedFileName"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.io", "FileUtils") and
    m.getName() = "openInputStream" and
    qn = "org.apache.commons.io.FileUtils.openInputStream"
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
    m.getName() = "readFileToString" and
    qn = "org.apache.commons.io.FileUtils.readFileToString"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.io", "FileUtils") and
    m.getName() = "readFileToByteArray" and
    qn = "org.apache.commons.io.FileUtils.readFileToByteArray"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.io", "FileUtils") and
    m.getName() = "readLines" and
    qn = "org.apache.commons.io.FileUtils.readLines"
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
    m.getName() = "writeLines" and
    qn = "org.apache.commons.io.FileUtils.writeLines"
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
    m.getName() = "copyDirectory" and
    qn = "org.apache.commons.io.FileUtils.copyDirectory"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.io", "FileUtils") and
    m.getName() = "copyURLToFile" and
    qn = "org.apache.commons.io.FileUtils.copyURLToFile"
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
    m.getName() = "moveDirectory" and
    qn = "org.apache.commons.io.FileUtils.moveDirectory"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.io", "FileUtils") and
    m.getName() = "deleteQuietly" and
    qn = "org.apache.commons.io.FileUtils.deleteQuietly"
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
    m.getName() = "forceMkdir" and
    qn = "org.apache.commons.io.FileUtils.forceMkdir"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.io", "FileUtils") and
    m.getName() = "forceMkdirParent" and
    qn = "org.apache.commons.io.FileUtils.forceMkdirParent"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.io", "FileUtils") and
    m.getName() = "cleanDirectory" and
    qn = "org.apache.commons.io.FileUtils.cleanDirectory"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.io", "FileUtils") and
    m.getName() = "listFiles" and
    qn = "org.apache.commons.io.FileUtils.listFiles"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.io", "FileUtils") and
    m.getName() = "iterateFiles" and
    qn = "org.apache.commons.io.FileUtils.iterateFiles"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.io", "FileUtils") and
    m.getName() = "toFile" and
    qn = "org.apache.commons.io.FileUtils.toFile"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.io", "FileUtils") and
    m.getName() = "toFiles" and
    qn = "org.apache.commons.io.FileUtils.toFiles"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.io", "FileUtils") and
    m.getName() = "toURLs" and
    qn = "org.apache.commons.io.FileUtils.toURLs"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.io", "IOUtils") and
    m.getName() = "copy" and
    qn = "org.apache.commons.io.IOUtils.copy"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.io", "IOUtils") and
    m.getName() = "copyLarge" and
    qn = "org.apache.commons.io.IOUtils.copyLarge"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.io", "IOUtils") and
    m.getName() = "toByteArray" and
    qn = "org.apache.commons.io.IOUtils.toByteArray"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.io", "IOUtils") and
    m.getName() = "toString" and
    qn = "org.apache.commons.io.IOUtils.toString"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.io", "FilenameUtils") and
    m.getName() = "normalize" and
    qn = "org.apache.commons.io.FilenameUtils.normalize"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.io", "FilenameUtils") and
    m.getName() = "normalizeNoEndSeparator" and
    qn = "org.apache.commons.io.FilenameUtils.normalizeNoEndSeparator"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.io", "FilenameUtils") and
    m.getName() = "concat" and
    qn = "org.apache.commons.io.FilenameUtils.concat"
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
    m.getName() = "getFullPath" and
    qn = "org.apache.commons.io.FilenameUtils.getFullPath"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.io", "FilenameUtils") and
    m.getName() = "getFullPathNoEndSeparator" and
    qn = "org.apache.commons.io.FilenameUtils.getFullPathNoEndSeparator"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.compress.archivers.zip", "ZipArchiveInputStream") and
    m.getName() = "getNextEntry" and
    qn = "org.apache.commons.compress.archivers.zip.ZipArchiveInputStream.getNextEntry"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.compress.archivers.zip", "ZipArchiveInputStream") and
    m.getName() = "getNextZipEntry" and
    qn = "org.apache.commons.compress.archivers.zip.ZipArchiveInputStream.getNextZipEntry"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.apache.commons.compress.archivers.zip", "ZipArchiveEntry") and
    qn = "org.apache.commons.compress.archivers.zip.ZipArchiveEntry.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.compress.archivers.zip", "ZipArchiveEntry") and
    m.getName() = "getName" and
    qn = "org.apache.commons.compress.archivers.zip.ZipArchiveEntry.getName"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.compress.archivers.tar", "TarArchiveInputStream") and
    m.getName() = "getNextTarEntry" and
    qn = "org.apache.commons.compress.archivers.tar.TarArchiveInputStream.getNextTarEntry"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.apache.commons.compress.archivers.tar", "TarArchiveEntry") and
    qn = "org.apache.commons.compress.archivers.tar.TarArchiveEntry.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.compress.archivers.tar", "TarArchiveEntry") and
    m.getName() = "getName" and
    qn = "org.apache.commons.compress.archivers.tar.TarArchiveEntry.getName"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.google.common.io", "Files") and
    m.getName() = "asByteSource" and
    qn = "com.google.common.io.Files.asByteSource"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.google.common.io", "Files") and
    m.getName() = "asByteSink" and
    qn = "com.google.common.io.Files.asByteSink"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.google.common.io", "Files") and
    m.getName() = "asCharSource" and
    qn = "com.google.common.io.Files.asCharSource"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.google.common.io", "Files") and
    m.getName() = "asCharSink" and
    qn = "com.google.common.io.Files.asCharSink"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.google.common.io", "Files") and
    m.getName() = "toByteArray" and
    qn = "com.google.common.io.Files.toByteArray"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.google.common.io", "Files") and
    m.getName() = "readLines" and
    qn = "com.google.common.io.Files.readLines"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.google.common.io", "Files") and
    m.getName() = "readFirstLine" and
    qn = "com.google.common.io.Files.readFirstLine"
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
    m.getDeclaringType().hasQualifiedName("com.google.common.io", "Files") and
    m.getName() = "touch" and
    qn = "com.google.common.io.Files.touch"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.google.common.io", "Files") and
    m.getName() = "createTempDir" and
    qn = "com.google.common.io.Files.createTempDir"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.google.common.io", "MoreFiles") and
    m.getName() = "asByteSource" and
    qn = "com.google.common.io.MoreFiles.asByteSource"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.google.common.io", "MoreFiles") and
    m.getName() = "asByteSink" and
    qn = "com.google.common.io.MoreFiles.asByteSink"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.google.common.io", "MoreFiles") and
    m.getName() = "asCharSource" and
    qn = "com.google.common.io.MoreFiles.asCharSource"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.google.common.io", "MoreFiles") and
    m.getName() = "asCharSink" and
    qn = "com.google.common.io.MoreFiles.asCharSink"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.google.common.io", "ByteSource") and
    m.getName() = "openStream" and
    qn = "com.google.common.io.ByteSource.openStream"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.google.common.io", "ByteSource") and
    m.getName() = "read" and
    qn = "com.google.common.io.ByteSource.read"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.google.common.io", "ByteSource") and
    m.getName() = "copyTo" and
    qn = "com.google.common.io.ByteSource.copyTo"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.google.common.io", "ByteSink") and
    m.getName() = "openStream" and
    qn = "com.google.common.io.ByteSink.openStream"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.google.common.io", "ByteSink") and
    m.getName() = "write" and
    qn = "com.google.common.io.ByteSink.write"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.google.common.io", "CharSource") and
    m.getName() = "openStream" and
    qn = "com.google.common.io.CharSource.openStream"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.google.common.io", "CharSource") and
    m.getName() = "read" and
    qn = "com.google.common.io.CharSource.read"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.google.common.io", "CharSource") and
    m.getName() = "copyTo" and
    qn = "com.google.common.io.CharSource.copyTo"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.google.common.io", "CharSink") and
    m.getName() = "openStream" and
    qn = "com.google.common.io.CharSink.openStream"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.google.common.io", "CharSink") and
    m.getName() = "write" and
    qn = "com.google.common.io.CharSink.write"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.util", "FileCopyUtils") and
    m.getName() = "copy" and
    qn = "org.springframework.util.FileCopyUtils.copy"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.util", "FileCopyUtils") and
    m.getName() = "copyToByteArray" and
    qn = "org.springframework.util.FileCopyUtils.copyToByteArray"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.util", "FileCopyUtils") and
    m.getName() = "copyToString" and
    qn = "org.springframework.util.FileCopyUtils.copyToString"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.util", "StreamUtils") and
    m.getName() = "copy" and
    qn = "org.springframework.util.StreamUtils.copy"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.util", "StreamUtils") and
    m.getName() = "copyToByteArray" and
    qn = "org.springframework.util.StreamUtils.copyToByteArray"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.util", "StreamUtils") and
    m.getName() = "copyToString" and
    qn = "org.springframework.util.StreamUtils.copyToString"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.web.multipart", "MultipartFile") and
    m.getName() = "getOriginalFilename" and
    qn = "org.springframework.web.multipart.MultipartFile.getOriginalFilename"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.web.multipart", "MultipartFile") and
    m.getName() = "transferTo" and
    qn = "org.springframework.web.multipart.MultipartFile.transferTo"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.core.io", "ResourceLoader") and
    m.getName() = "getResource" and
    qn = "org.springframework.core.io.ResourceLoader.getResource"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.core.io", "Resource") and
    m.getName() = "getFile" and
    qn = "org.springframework.core.io.Resource.getFile"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.springframework.core.io", "Resource") and
    m.getName() = "getInputStream" and
    qn = "org.springframework.core.io.Resource.getInputStream"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("okio", "FileSystem") and
    m.getName() = "read" and
    qn = "okio.FileSystem.read"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("okio", "FileSystem") and
    m.getName() = "write" and
    qn = "okio.FileSystem.write"
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
    m.getName() = "atomicMove" and
    qn = "okio.FileSystem.atomicMove"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("okio", "FileSystem") and
    m.getName() = "metadataOrNull" and
    qn = "okio.FileSystem.metadataOrNull"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("okio", "Path") and
    qn = "okio.Path.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("okio", "Path") and
    m.getName() = "toPath" and
    qn = "okio.Path.toPath"
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
