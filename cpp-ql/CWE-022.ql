// Auto-generated; CWE-022; number of APIs 248
import cpp

predicate isTargetApi(Function target, string qn) {
  target.getQualifiedName().matches("std%::basic_fstream%::open%") and qn = "std::basic_fstream::open" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "basic_fstream") and
    memberFunc.getName() = "open" and
    qn = "std::basic_fstream::open"
  ) or
  target.getQualifiedName().matches("std%::basic_ifstream%::open%") and qn = "std::basic_ifstream::open" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "basic_ifstream") and
    memberFunc.getName() = "open" and
    qn = "std::basic_ifstream::open"
  ) or
  target.getQualifiedName().matches("std%::basic_ofstream%::open%") and qn = "std::basic_ofstream::open" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "basic_ofstream") and
    memberFunc.getName() = "open" and
    qn = "std::basic_ofstream::open"
  ) or
  target.getQualifiedName().matches("std%::basic_fstream%::basic_fstream%") and qn = "std::basic_fstream::basic_fstream" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "basic_fstream") and
    memberFunc.getName() = "basic_fstream" and
    qn = "std::basic_fstream::basic_fstream"
  ) or
  target.getQualifiedName().matches("std%::basic_ifstream%::basic_ifstream%") and qn = "std::basic_ifstream::basic_ifstream" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "basic_ifstream") and
    memberFunc.getName() = "basic_ifstream" and
    qn = "std::basic_ifstream::basic_ifstream"
  ) or
  target.getQualifiedName().matches("std%::basic_ofstream%::basic_ofstream%") and qn = "std::basic_ofstream::basic_ofstream" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "basic_ofstream") and
    memberFunc.getName() = "basic_ofstream" and
    qn = "std::basic_ofstream::basic_ofstream"
  ) or
  target.getQualifiedName().matches("std%::filesystem%::path%") and qn = "std::filesystem::path" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "filesystem") and
    memberFunc.getName() = "path" and
    qn = "std::filesystem::path"
  ) or
  target.getQualifiedName().matches("std%::filesystem%::directory_iterator%") and qn = "std::filesystem::directory_iterator" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "filesystem") and
    memberFunc.getName() = "directory_iterator" and
    qn = "std::filesystem::directory_iterator"
  ) or
  target.getQualifiedName().matches("std%::filesystem%::recursive_directory_iterator%") and qn = "std::filesystem::recursive_directory_iterator" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "filesystem") and
    memberFunc.getName() = "recursive_directory_iterator" and
    qn = "std::filesystem::recursive_directory_iterator"
  ) or
  target.getQualifiedName().matches("std%::filesystem%::space%") and qn = "std::filesystem::space" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "filesystem") and
    memberFunc.getName() = "space" and
    qn = "std::filesystem::space"
  ) or
  target.getQualifiedName().matches("std%::filesystem%::absolute%") and qn = "std::filesystem::absolute" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "filesystem") and
    memberFunc.getName() = "absolute" and
    qn = "std::filesystem::absolute"
  ) or
  target.getQualifiedName().matches("std%::filesystem%::canonical%") and qn = "std::filesystem::canonical" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "filesystem") and
    memberFunc.getName() = "canonical" and
    qn = "std::filesystem::canonical"
  ) or
  target.getQualifiedName().matches("std%::filesystem%::weakly_canonical%") and qn = "std::filesystem::weakly_canonical" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "filesystem") and
    memberFunc.getName() = "weakly_canonical" and
    qn = "std::filesystem::weakly_canonical"
  ) or
  target.getQualifiedName().matches("std%::filesystem%::lexically_normal%") and qn = "std::filesystem::lexically_normal" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "filesystem") and
    memberFunc.getName() = "lexically_normal" and
    qn = "std::filesystem::lexically_normal"
  ) or
  target.getQualifiedName().matches("std%::filesystem%::relative%") and qn = "std::filesystem::relative" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "filesystem") and
    memberFunc.getName() = "relative" and
    qn = "std::filesystem::relative"
  ) or
  target.getQualifiedName().matches("std%::filesystem%::proximate%") and qn = "std::filesystem::proximate" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "filesystem") and
    memberFunc.getName() = "proximate" and
    qn = "std::filesystem::proximate"
  ) or
  target.getQualifiedName().matches("std%::filesystem%::current_path%") and qn = "std::filesystem::current_path" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "filesystem") and
    memberFunc.getName() = "current_path" and
    qn = "std::filesystem::current_path"
  ) or
  target.getQualifiedName().matches("std%::filesystem%::temp_directory_path%") and qn = "std::filesystem::temp_directory_path" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "filesystem") and
    memberFunc.getName() = "temp_directory_path" and
    qn = "std::filesystem::temp_directory_path"
  ) or
  target.getQualifiedName().matches("std%::filesystem%::status%") and qn = "std::filesystem::status" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "filesystem") and
    memberFunc.getName() = "status" and
    qn = "std::filesystem::status"
  ) or
  target.getQualifiedName().matches("std%::filesystem%::symlink_status%") and qn = "std::filesystem::symlink_status" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "filesystem") and
    memberFunc.getName() = "symlink_status" and
    qn = "std::filesystem::symlink_status"
  ) or
  target.getQualifiedName().matches("std%::filesystem%::remove%") and qn = "std::filesystem::remove" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "filesystem") and
    memberFunc.getName() = "remove" and
    qn = "std::filesystem::remove"
  ) or
  target.getQualifiedName().matches("std%::filesystem%::remove_all%") and qn = "std::filesystem::remove_all" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "filesystem") and
    memberFunc.getName() = "remove_all" and
    qn = "std::filesystem::remove_all"
  ) or
  target.getQualifiedName().matches("std%::filesystem%::rename%") and qn = "std::filesystem::rename" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "filesystem") and
    memberFunc.getName() = "rename" and
    qn = "std::filesystem::rename"
  ) or
  target.getQualifiedName().matches("std%::filesystem%::copy%") and qn = "std::filesystem::copy" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "filesystem") and
    memberFunc.getName() = "copy" and
    qn = "std::filesystem::copy"
  ) or
  target.getQualifiedName().matches("std%::filesystem%::copy_file%") and qn = "std::filesystem::copy_file" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "filesystem") and
    memberFunc.getName() = "copy_file" and
    qn = "std::filesystem::copy_file"
  ) or
  target.getQualifiedName().matches("std%::filesystem%::copy_symlink%") and qn = "std::filesystem::copy_symlink" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "filesystem") and
    memberFunc.getName() = "copy_symlink" and
    qn = "std::filesystem::copy_symlink"
  ) or
  target.getQualifiedName().matches("std%::filesystem%::create_directory%") and qn = "std::filesystem::create_directory" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "filesystem") and
    memberFunc.getName() = "create_directory" and
    qn = "std::filesystem::create_directory"
  ) or
  target.getQualifiedName().matches("std%::filesystem%::create_directories%") and qn = "std::filesystem::create_directories" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "filesystem") and
    memberFunc.getName() = "create_directories" and
    qn = "std::filesystem::create_directories"
  ) or
  target.getQualifiedName().matches("std%::filesystem%::create_hard_link%") and qn = "std::filesystem::create_hard_link" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "filesystem") and
    memberFunc.getName() = "create_hard_link" and
    qn = "std::filesystem::create_hard_link"
  ) or
  target.getQualifiedName().matches("std%::filesystem%::create_symlink%") and qn = "std::filesystem::create_symlink" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "filesystem") and
    memberFunc.getName() = "create_symlink" and
    qn = "std::filesystem::create_symlink"
  ) or
  target.getQualifiedName().matches("std%::filesystem%::create_directory_symlink%") and qn = "std::filesystem::create_directory_symlink" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "filesystem") and
    memberFunc.getName() = "create_directory_symlink" and
    qn = "std::filesystem::create_directory_symlink"
  ) or
  target.getQualifiedName().matches("std%::filesystem%::read_symlink%") and qn = "std::filesystem::read_symlink" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "filesystem") and
    memberFunc.getName() = "read_symlink" and
    qn = "std::filesystem::read_symlink"
  ) or
  target.getQualifiedName().matches("std%::filesystem%::exists%") and qn = "std::filesystem::exists" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "filesystem") and
    memberFunc.getName() = "exists" and
    qn = "std::filesystem::exists"
  ) or
  target.getQualifiedName().matches("std%::filesystem%::is_regular_file%") and qn = "std::filesystem::is_regular_file" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "filesystem") and
    memberFunc.getName() = "is_regular_file" and
    qn = "std::filesystem::is_regular_file"
  ) or
  target.getQualifiedName().matches("std%::filesystem%::is_directory%") and qn = "std::filesystem::is_directory" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "filesystem") and
    memberFunc.getName() = "is_directory" and
    qn = "std::filesystem::is_directory"
  ) or
  target.getQualifiedName().matches("std%::filesystem%::is_symlink%") and qn = "std::filesystem::is_symlink" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "filesystem") and
    memberFunc.getName() = "is_symlink" and
    qn = "std::filesystem::is_symlink"
  ) or
  target.getQualifiedName().matches("std%::filesystem%::file_size%") and qn = "std::filesystem::file_size" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "filesystem") and
    memberFunc.getName() = "file_size" and
    qn = "std::filesystem::file_size"
  ) or
  target.getQualifiedName().matches("std%::filesystem%::last_write_time%") and qn = "std::filesystem::last_write_time" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "filesystem") and
    memberFunc.getName() = "last_write_time" and
    qn = "std::filesystem::last_write_time"
  ) or
  target.getQualifiedName().matches("std%::filesystem%::permissions%") and qn = "std::filesystem::permissions" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("std", "filesystem") and
    memberFunc.getName() = "permissions" and
    qn = "std::filesystem::permissions"
  ) or
  target.getQualifiedName().matches("std%::FILE%") and qn = "std::FILE" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "std") and
    memberFunc.getName() = "FILE" and
    qn = "std::FILE"
  ) or
  target.getQualifiedName().matches("fopen%") and qn = "fopen" or
  target.getQualifiedName().matches("freopen%") and qn = "freopen" or
  target.getQualifiedName().matches("remove%") and qn = "remove" or
  target.getQualifiedName().matches("rename%") and qn = "rename" or
  target.getQualifiedName().matches("open%") and qn = "open" or
  target.getQualifiedName().matches("openat%") and qn = "openat" or
  target.getQualifiedName().matches("open64%") and qn = "open64" or
  target.getQualifiedName().matches("creat%") and qn = "creat" or
  target.getQualifiedName().matches("creat64%") and qn = "creat64" or
  target.getQualifiedName().matches("close%") and qn = "close" or
  target.getQualifiedName().matches("read%") and qn = "read" or
  target.getQualifiedName().matches("write%") and qn = "write" or
  target.getQualifiedName().matches("pread%") and qn = "pread" or
  target.getQualifiedName().matches("pwrite%") and qn = "pwrite" or
  target.getQualifiedName().matches("lseek%") and qn = "lseek" or
  target.getQualifiedName().matches("lseek64%") and qn = "lseek64" or
  target.getQualifiedName().matches("stat%") and qn = "stat" or
  target.getQualifiedName().matches("lstat%") and qn = "lstat" or
  target.getQualifiedName().matches("fstat%") and qn = "fstat" or
  target.getQualifiedName().matches("stat64%") and qn = "stat64" or
  target.getQualifiedName().matches("lstat64%") and qn = "lstat64" or
  target.getQualifiedName().matches("fstatat%") and qn = "fstatat" or
  target.getQualifiedName().matches("fstatat64%") and qn = "fstatat64" or
  target.getQualifiedName().matches("statfs%") and qn = "statfs" or
  target.getQualifiedName().matches("statvfs%") and qn = "statvfs" or
  target.getQualifiedName().matches("access%") and qn = "access" or
  target.getQualifiedName().matches("faccessat%") and qn = "faccessat" or
  target.getQualifiedName().matches("chmod%") and qn = "chmod" or
  target.getQualifiedName().matches("fchmod%") and qn = "fchmod" or
  target.getQualifiedName().matches("chown%") and qn = "chown" or
  target.getQualifiedName().matches("fchown%") and qn = "fchown" or
  target.getQualifiedName().matches("lchown%") and qn = "lchown" or
  target.getQualifiedName().matches("fchownat%") and qn = "fchownat" or
  target.getQualifiedName().matches("mkdir%") and qn = "mkdir" or
  target.getQualifiedName().matches("mkdirat%") and qn = "mkdirat" or
  target.getQualifiedName().matches("rmdir%") and qn = "rmdir" or
  target.getQualifiedName().matches("opendir%") and qn = "opendir" or
  target.getQualifiedName().matches("readdir%") and qn = "readdir" or
  target.getQualifiedName().matches("readdir_r%") and qn = "readdir_r" or
  target.getQualifiedName().matches("readdir64%") and qn = "readdir64" or
  target.getQualifiedName().matches("scandir%") and qn = "scandir" or
  target.getQualifiedName().matches("scandir64%") and qn = "scandir64" or
  target.getQualifiedName().matches("closedir%") and qn = "closedir" or
  target.getQualifiedName().matches("telldir%") and qn = "telldir" or
  target.getQualifiedName().matches("seekdir%") and qn = "seekdir" or
  target.getQualifiedName().matches("rewinddir%") and qn = "rewinddir" or
  target.getQualifiedName().matches("unlink%") and qn = "unlink" or
  target.getQualifiedName().matches("unlinkat%") and qn = "unlinkat" or
  target.getQualifiedName().matches("symlink%") and qn = "symlink" or
  target.getQualifiedName().matches("symlinkat%") and qn = "symlinkat" or
  target.getQualifiedName().matches("link%") and qn = "link" or
  target.getQualifiedName().matches("linkat%") and qn = "linkat" or
  target.getQualifiedName().matches("renameat%") and qn = "renameat" or
  target.getQualifiedName().matches("renameat2%") and qn = "renameat2" or
  target.getQualifiedName().matches("mkstemp%") and qn = "mkstemp" or
  target.getQualifiedName().matches("mkstemps%") and qn = "mkstemps" or
  target.getQualifiedName().matches("mkdtemp%") and qn = "mkdtemp" or
  target.getQualifiedName().matches("mktemp%") and qn = "mktemp" or
  target.getQualifiedName().matches("mktemp64%") and qn = "mktemp64" or
  target.getQualifiedName().matches("mkfifo%") and qn = "mkfifo" or
  target.getQualifiedName().matches("mkfifoat%") and qn = "mkfifoat" or
  target.getQualifiedName().matches("mknod%") and qn = "mknod" or
  target.getQualifiedName().matches("mknodat%") and qn = "mknodat" or
  target.getQualifiedName().matches("umask%") and qn = "umask" or
  target.getQualifiedName().matches("realpath%") and qn = "realpath" or
  target.getQualifiedName().matches("canonicalize_file_name%") and qn = "canonicalize_file_name" or
  target.getQualifiedName().matches("getcwd%") and qn = "getcwd" or
  target.getQualifiedName().matches("getwd%") and qn = "getwd" or
  target.getQualifiedName().matches("chdir%") and qn = "chdir" or
  target.getQualifiedName().matches("fchdir%") and qn = "fchdir" or
  target.getQualifiedName().matches("chroot%") and qn = "chroot" or
  target.getQualifiedName().matches("tmpfile%") and qn = "tmpfile" or
  target.getQualifiedName().matches("tmpnam%") and qn = "tmpnam" or
  target.getQualifiedName().matches("tmpnam_r%") and qn = "tmpnam_r" or
  target.getQualifiedName().matches("tmpfile64%") and qn = "tmpfile64" or
  target.getQualifiedName().matches("openlog%") and qn = "openlog" or
  target.getQualifiedName().matches("system%") and qn = "system" or
  target.getQualifiedName().matches("popen%") and qn = "popen" or
  target.getQualifiedName().matches("pclose%") and qn = "pclose" or
  target.getQualifiedName().matches("posix_spawn%") and qn = "posix_spawn" or
  target.getQualifiedName().matches("posix_spawnp%") and qn = "posix_spawnp" or
  target.getQualifiedName().matches("execv%") and qn = "execv" or
  target.getQualifiedName().matches("execve%") and qn = "execve" or
  target.getQualifiedName().matches("execl%") and qn = "execl" or
  target.getQualifiedName().matches("execvp%") and qn = "execvp" or
  target.getQualifiedName().matches("execvpe%") and qn = "execvpe" or
  target.getQualifiedName().matches("execle%") and qn = "execle" or
  target.getQualifiedName().matches("spawnl%") and qn = "spawnl" or
  target.getQualifiedName().matches("spawnv%") and qn = "spawnv" or
  target.getQualifiedName().matches("spawnle%") and qn = "spawnle" or
  target.getQualifiedName().matches("spawnve%") and qn = "spawnve" or
  target.getQualifiedName().matches("spawnlp%") and qn = "spawnlp" or
  target.getQualifiedName().matches("spawnvp%") and qn = "spawnvp" or
  target.getQualifiedName().matches("CreateFileA%") and qn = "CreateFileA" or
  target.getQualifiedName().matches("CreateFileW%") and qn = "CreateFileW" or
  target.getQualifiedName().matches("CreateDirectoryA%") and qn = "CreateDirectoryA" or
  target.getQualifiedName().matches("CreateDirectoryW%") and qn = "CreateDirectoryW" or
  target.getQualifiedName().matches("RemoveDirectoryA%") and qn = "RemoveDirectoryA" or
  target.getQualifiedName().matches("RemoveDirectoryW%") and qn = "RemoveDirectoryW" or
  target.getQualifiedName().matches("MoveFileA%") and qn = "MoveFileA" or
  target.getQualifiedName().matches("MoveFileW%") and qn = "MoveFileW" or
  target.getQualifiedName().matches("MoveFileExA%") and qn = "MoveFileExA" or
  target.getQualifiedName().matches("MoveFileExW%") and qn = "MoveFileExW" or
  target.getQualifiedName().matches("DeleteFileA%") and qn = "DeleteFileA" or
  target.getQualifiedName().matches("DeleteFileW%") and qn = "DeleteFileW" or
  target.getQualifiedName().matches("GetFileAttributesA%") and qn = "GetFileAttributesA" or
  target.getQualifiedName().matches("GetFileAttributesW%") and qn = "GetFileAttributesW" or
  target.getQualifiedName().matches("SetFileAttributesA%") and qn = "SetFileAttributesA" or
  target.getQualifiedName().matches("SetFileAttributesW%") and qn = "SetFileAttributesW" or
  target.getQualifiedName().matches("PathAppendA%") and qn = "PathAppendA" or
  target.getQualifiedName().matches("PathAppendW%") and qn = "PathAppendW" or
  target.getQualifiedName().matches("PathCombineA%") and qn = "PathCombineA" or
  target.getQualifiedName().matches("PathCombineW%") and qn = "PathCombineW" or
  target.getQualifiedName().matches("PathCanonicalizeA%") and qn = "PathCanonicalizeA" or
  target.getQualifiedName().matches("PathCanonicalizeW%") and qn = "PathCanonicalizeW" or
  target.getQualifiedName().matches("PathIsRelativeA%") and qn = "PathIsRelativeA" or
  target.getQualifiedName().matches("PathIsRelativeW%") and qn = "PathIsRelativeW" or
  target.getQualifiedName().matches("PathIsDirectoryA%") and qn = "PathIsDirectoryA" or
  target.getQualifiedName().matches("PathIsDirectoryW%") and qn = "PathIsDirectoryW" or
  target.getQualifiedName().matches("boost%::filesystem%::path%") and qn = "boost::filesystem::path" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost", "filesystem") and
    memberFunc.getName() = "path" and
    qn = "boost::filesystem::path"
  ) or
  target.getQualifiedName().matches("boost%::filesystem%::directory_iterator%") and qn = "boost::filesystem::directory_iterator" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost", "filesystem") and
    memberFunc.getName() = "directory_iterator" and
    qn = "boost::filesystem::directory_iterator"
  ) or
  target.getQualifiedName().matches("boost%::filesystem%::recursive_directory_iterator%") and qn = "boost::filesystem::recursive_directory_iterator" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost", "filesystem") and
    memberFunc.getName() = "recursive_directory_iterator" and
    qn = "boost::filesystem::recursive_directory_iterator"
  ) or
  target.getQualifiedName().matches("boost%::filesystem%::absolute%") and qn = "boost::filesystem::absolute" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost", "filesystem") and
    memberFunc.getName() = "absolute" and
    qn = "boost::filesystem::absolute"
  ) or
  target.getQualifiedName().matches("boost%::filesystem%::canonical%") and qn = "boost::filesystem::canonical" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost", "filesystem") and
    memberFunc.getName() = "canonical" and
    qn = "boost::filesystem::canonical"
  ) or
  target.getQualifiedName().matches("boost%::filesystem%::lexically_normal%") and qn = "boost::filesystem::lexically_normal" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost", "filesystem") and
    memberFunc.getName() = "lexically_normal" and
    qn = "boost::filesystem::lexically_normal"
  ) or
  target.getQualifiedName().matches("boost%::filesystem%::exists%") and qn = "boost::filesystem::exists" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost", "filesystem") and
    memberFunc.getName() = "exists" and
    qn = "boost::filesystem::exists"
  ) or
  target.getQualifiedName().matches("boost%::filesystem%::is_regular_file%") and qn = "boost::filesystem::is_regular_file" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost", "filesystem") and
    memberFunc.getName() = "is_regular_file" and
    qn = "boost::filesystem::is_regular_file"
  ) or
  target.getQualifiedName().matches("boost%::filesystem%::is_directory%") and qn = "boost::filesystem::is_directory" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost", "filesystem") and
    memberFunc.getName() = "is_directory" and
    qn = "boost::filesystem::is_directory"
  ) or
  target.getQualifiedName().matches("boost%::filesystem%::is_symlink%") and qn = "boost::filesystem::is_symlink" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost", "filesystem") and
    memberFunc.getName() = "is_symlink" and
    qn = "boost::filesystem::is_symlink"
  ) or
  target.getQualifiedName().matches("boost%::filesystem%::file_size%") and qn = "boost::filesystem::file_size" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost", "filesystem") and
    memberFunc.getName() = "file_size" and
    qn = "boost::filesystem::file_size"
  ) or
  target.getQualifiedName().matches("boost%::filesystem%::last_write_time%") and qn = "boost::filesystem::last_write_time" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost", "filesystem") and
    memberFunc.getName() = "last_write_time" and
    qn = "boost::filesystem::last_write_time"
  ) or
  target.getQualifiedName().matches("boost%::filesystem%::permissions%") and qn = "boost::filesystem::permissions" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost", "filesystem") and
    memberFunc.getName() = "permissions" and
    qn = "boost::filesystem::permissions"
  ) or
  target.getQualifiedName().matches("boost%::filesystem%::status%") and qn = "boost::filesystem::status" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost", "filesystem") and
    memberFunc.getName() = "status" and
    qn = "boost::filesystem::status"
  ) or
  target.getQualifiedName().matches("boost%::filesystem%::symlink_status%") and qn = "boost::filesystem::symlink_status" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost", "filesystem") and
    memberFunc.getName() = "symlink_status" and
    qn = "boost::filesystem::symlink_status"
  ) or
  target.getQualifiedName().matches("boost%::filesystem%::remove%") and qn = "boost::filesystem::remove" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost", "filesystem") and
    memberFunc.getName() = "remove" and
    qn = "boost::filesystem::remove"
  ) or
  target.getQualifiedName().matches("boost%::filesystem%::remove_all%") and qn = "boost::filesystem::remove_all" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost", "filesystem") and
    memberFunc.getName() = "remove_all" and
    qn = "boost::filesystem::remove_all"
  ) or
  target.getQualifiedName().matches("boost%::filesystem%::rename%") and qn = "boost::filesystem::rename" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost", "filesystem") and
    memberFunc.getName() = "rename" and
    qn = "boost::filesystem::rename"
  ) or
  target.getQualifiedName().matches("boost%::filesystem%::copy_file%") and qn = "boost::filesystem::copy_file" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost", "filesystem") and
    memberFunc.getName() = "copy_file" and
    qn = "boost::filesystem::copy_file"
  ) or
  target.getQualifiedName().matches("boost%::filesystem%::create_directory%") and qn = "boost::filesystem::create_directory" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost", "filesystem") and
    memberFunc.getName() = "create_directory" and
    qn = "boost::filesystem::create_directory"
  ) or
  target.getQualifiedName().matches("boost%::filesystem%::create_directories%") and qn = "boost::filesystem::create_directories" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost", "filesystem") and
    memberFunc.getName() = "create_directories" and
    qn = "boost::filesystem::create_directories"
  ) or
  target.getQualifiedName().matches("boost%::filesystem%::create_symlink%") and qn = "boost::filesystem::create_symlink" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost", "filesystem") and
    memberFunc.getName() = "create_symlink" and
    qn = "boost::filesystem::create_symlink"
  ) or
  target.getQualifiedName().matches("boost%::filesystem%::create_hard_link%") and qn = "boost::filesystem::create_hard_link" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost", "filesystem") and
    memberFunc.getName() = "create_hard_link" and
    qn = "boost::filesystem::create_hard_link"
  ) or
  target.getQualifiedName().matches("boost%::filesystem%::read_symlink%") and qn = "boost::filesystem::read_symlink" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost", "filesystem") and
    memberFunc.getName() = "read_symlink" and
    qn = "boost::filesystem::read_symlink"
  ) or
  target.getQualifiedName().matches("boost%::filesystem%::temp_directory_path%") and qn = "boost::filesystem::temp_directory_path" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost", "filesystem") and
    memberFunc.getName() = "temp_directory_path" and
    qn = "boost::filesystem::temp_directory_path"
  ) or
  target.getQualifiedName().matches("Poco%::File%") and qn = "Poco::File" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "Poco") and
    memberFunc.getName() = "File" and
    qn = "Poco::File"
  ) or
  target.getQualifiedName().matches("Poco%::Path%") and qn = "Poco::Path" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "Poco") and
    memberFunc.getName() = "Path" and
    qn = "Poco::Path"
  ) or
  target.getQualifiedName().matches("Poco%::Path%::append%") and qn = "Poco::Path::append" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Poco", "Path") and
    memberFunc.getName() = "append" and
    qn = "Poco::Path::append"
  ) or
  target.getQualifiedName().matches("Poco%::Path%::resolve%") and qn = "Poco::Path::resolve" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Poco", "Path") and
    memberFunc.getName() = "resolve" and
    qn = "Poco::Path::resolve"
  ) or
  target.getQualifiedName().matches("Qt%::QFile%") and qn = "Qt::QFile" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "Qt") and
    memberFunc.getName() = "QFile" and
    qn = "Qt::QFile"
  ) or
  target.getQualifiedName().matches("Qt%::QDir%") and qn = "Qt::QDir" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "Qt") and
    memberFunc.getName() = "QDir" and
    qn = "Qt::QDir"
  ) or
  target.getQualifiedName().matches("Qt%::QFile%::open%") and qn = "Qt::QFile::open" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Qt", "QFile") and
    memberFunc.getName() = "open" and
    qn = "Qt::QFile::open"
  ) or
  target.getQualifiedName().matches("Qt%::QFile%::remove%") and qn = "Qt::QFile::remove" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Qt", "QFile") and
    memberFunc.getName() = "remove" and
    qn = "Qt::QFile::remove"
  ) or
  target.getQualifiedName().matches("Qt%::QFile%::rename%") and qn = "Qt::QFile::rename" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Qt", "QFile") and
    memberFunc.getName() = "rename" and
    qn = "Qt::QFile::rename"
  ) or
  target.getQualifiedName().matches("Qt%::QDir%::mkdir%") and qn = "Qt::QDir::mkdir" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Qt", "QDir") and
    memberFunc.getName() = "mkdir" and
    qn = "Qt::QDir::mkdir"
  ) or
  target.getQualifiedName().matches("Qt%::QDir%::rmdir%") and qn = "Qt::QDir::rmdir" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Qt", "QDir") and
    memberFunc.getName() = "rmdir" and
    qn = "Qt::QDir::rmdir"
  ) or
  target.getQualifiedName().matches("Qt%::QDir%::removeRecursively%") and qn = "Qt::QDir::removeRecursively" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Qt", "QDir") and
    memberFunc.getName() = "removeRecursively" and
    qn = "Qt::QDir::removeRecursively"
  ) or
  target.getQualifiedName().matches("glib%::g_file_new_for_path%") and qn = "glib::g_file_new_for_path" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "glib") and
    memberFunc.getName() = "g_file_new_for_path" and
    qn = "glib::g_file_new_for_path"
  ) or
  target.getQualifiedName().matches("glib%::g_file_replace_contents%") and qn = "glib::g_file_replace_contents" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "glib") and
    memberFunc.getName() = "g_file_replace_contents" and
    qn = "glib::g_file_replace_contents"
  ) or
  target.getQualifiedName().matches("glib%::g_file_load_contents%") and qn = "glib::g_file_load_contents" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "glib") and
    memberFunc.getName() = "g_file_load_contents" and
    qn = "glib::g_file_load_contents"
  ) or
  target.getQualifiedName().matches("glib%::g_file_delete%") and qn = "glib::g_file_delete" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "glib") and
    memberFunc.getName() = "g_file_delete" and
    qn = "glib::g_file_delete"
  ) or
  target.getQualifiedName().matches("glib%::g_mkdir_with_parents%") and qn = "glib::g_mkdir_with_parents" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "glib") and
    memberFunc.getName() = "g_mkdir_with_parents" and
    qn = "glib::g_mkdir_with_parents"
  ) or
  target.getQualifiedName().matches("libuv%::fs_open%") and qn = "libuv::fs_open" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "libuv") and
    memberFunc.getName() = "fs_open" and
    qn = "libuv::fs_open"
  ) or
  target.getQualifiedName().matches("libuv%::fs_unlink%") and qn = "libuv::fs_unlink" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "libuv") and
    memberFunc.getName() = "fs_unlink" and
    qn = "libuv::fs_unlink"
  ) or
  target.getQualifiedName().matches("libuv%::fs_mkdir%") and qn = "libuv::fs_mkdir" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "libuv") and
    memberFunc.getName() = "fs_mkdir" and
    qn = "libuv::fs_mkdir"
  ) or
  target.getQualifiedName().matches("libuv%::fs_rmdir%") and qn = "libuv::fs_rmdir" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "libuv") and
    memberFunc.getName() = "fs_rmdir" and
    qn = "libuv::fs_rmdir"
  ) or
  target.getQualifiedName().matches("libuv%::fs_rename%") and qn = "libuv::fs_rename" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "libuv") and
    memberFunc.getName() = "fs_rename" and
    qn = "libuv::fs_rename"
  ) or
  target.getQualifiedName().matches("libuv%::fs_scandir%") and qn = "libuv::fs_scandir" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "libuv") and
    memberFunc.getName() = "fs_scandir" and
    qn = "libuv::fs_scandir"
  ) or
  target.getQualifiedName().matches("libcurl%::easy%") and qn = "libcurl::easy" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "libcurl") and
    memberFunc.getName() = "easy" and
    qn = "libcurl::easy"
  ) or
  target.getQualifiedName().matches("libcurl%::easy%::setopt_upload%") and qn = "libcurl::easy::setopt_upload" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("libcurl", "easy") and
    memberFunc.getName() = "setopt_upload" and
    qn = "libcurl::easy::setopt_upload"
  ) or
  target.getQualifiedName().matches("libcurl%::easy%::setopt_url%") and qn = "libcurl::easy::setopt_url" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("libcurl", "easy") and
    memberFunc.getName() = "setopt_url" and
    qn = "libcurl::easy::setopt_url"
  ) or
  target.getQualifiedName().matches("libcurl%::easy%::setopt_postfields%") and qn = "libcurl::easy::setopt_postfields" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("libcurl", "easy") and
    memberFunc.getName() = "setopt_postfields" and
    qn = "libcurl::easy::setopt_postfields"
  ) or
  target.getQualifiedName().matches("curl_easy_perform%") and qn = "curl_easy_perform" or
  target.getQualifiedName().matches("mongoose%::mg_http_upload%") and qn = "mongoose::mg_http_upload" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "mongoose") and
    memberFunc.getName() = "mg_http_upload" and
    qn = "mongoose::mg_http_upload"
  ) or
  target.getQualifiedName().matches("mongoose%::fs_open%") and qn = "mongoose::fs_open" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "mongoose") and
    memberFunc.getName() = "fs_open" and
    qn = "mongoose::fs_open"
  ) or
  target.getQualifiedName().matches("mongoose%::fs_remove%") and qn = "mongoose::fs_remove" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "mongoose") and
    memberFunc.getName() = "fs_remove" and
    qn = "mongoose::fs_remove"
  ) or
  target.getQualifiedName().matches("mongoose%::fs_rename%") and qn = "mongoose::fs_rename" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "mongoose") and
    memberFunc.getName() = "fs_rename" and
    qn = "mongoose::fs_rename"
  ) or
  target.getQualifiedName().matches("crow%::multipart%::save_file%") and qn = "crow::multipart::save_file" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("crow", "multipart") and
    memberFunc.getName() = "save_file" and
    qn = "crow::multipart::save_file"
  ) or
  target.getQualifiedName().matches("apache%::request%::upload%") and qn = "apache::request::upload" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("apache", "request") and
    memberFunc.getName() = "upload" and
    qn = "apache::request::upload"
  ) or
  target.getQualifiedName().matches("apache%::request%::upload%::save%") and qn = "apache::request::upload::save" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("apache::request", "upload") and
    memberFunc.getName() = "save" and
    qn = "apache::request::upload::save"
  ) or
  target.getQualifiedName().matches("Crow%::multipart%::save_file%") and qn = "Crow::multipart::save_file" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("Crow", "multipart") and
    memberFunc.getName() = "save_file" and
    qn = "Crow::multipart::save_file"
  ) or
  target.getQualifiedName().matches("crow%::multipart%::part%") and qn = "crow::multipart::part" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("crow", "multipart") and
    memberFunc.getName() = "part" and
    qn = "crow::multipart::part"
  ) or
  target.getQualifiedName().matches("crow%::multipart%::part%::save%") and qn = "crow::multipart::part::save" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("crow::multipart", "part") and
    memberFunc.getName() = "save" and
    qn = "crow::multipart::part::save"
  ) or
  target.getQualifiedName().matches("cpp-httplib%::Server%") and qn = "cpp-httplib::Server" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "cpp-httplib") and
    memberFunc.getName() = "Server" and
    qn = "cpp-httplib::Server"
  ) or
  target.getQualifiedName().matches("cpp-httplib%::detail%::read_file%") and qn = "cpp-httplib::detail::read_file" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("cpp-httplib", "detail") and
    memberFunc.getName() = "read_file" and
    qn = "cpp-httplib::detail::read_file"
  ) or
  target.getQualifiedName().matches("mongoose%") and qn = "mongoose" or
  target.getQualifiedName().matches("nginx_module_file_write%") and qn = "nginx_module_file_write" or
  target.getQualifiedName().matches("nginx_module_file_read%") and qn = "nginx_module_file_read" or
  target.getQualifiedName().matches("apache_module_file_write%") and qn = "apache_module_file_write" or
  target.getQualifiedName().matches("apache_module_file_read%") and qn = "apache_module_file_read" or
  target.getQualifiedName().matches("sqlite3%") and qn = "sqlite3" or
  target.getQualifiedName().matches("sqlite3_open%") and qn = "sqlite3_open" or
  target.getQualifiedName().matches("sqlite3_open_v2%") and qn = "sqlite3_open_v2" or
  target.getQualifiedName().matches("sqlite3_backup_init%") and qn = "sqlite3_backup_init" or
  target.getQualifiedName().matches("rocksdb%::DB%") and qn = "rocksdb::DB" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "rocksdb") and
    memberFunc.getName() = "DB" and
    qn = "rocksdb::DB"
  ) or
  target.getQualifiedName().matches("rocksdb%::DB%::Open%") and qn = "rocksdb::DB::Open" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("rocksdb", "DB") and
    memberFunc.getName() = "Open" and
    qn = "rocksdb::DB::Open"
  ) or
  target.getQualifiedName().matches("LevelDB%::DB%::Open%") and qn = "LevelDB::DB::Open" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("LevelDB", "DB") and
    memberFunc.getName() = "Open" and
    qn = "LevelDB::DB::Open"
  ) or
  target.getQualifiedName().matches("aws%::s3%::Client%") and qn = "aws::s3::Client" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("aws", "s3") and
    memberFunc.getName() = "Client" and
    qn = "aws::s3::Client"
  ) or
  target.getQualifiedName().matches("aws%::s3%::Client%::PutObject%") and qn = "aws::s3::Client::PutObject" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("aws::s3", "Client") and
    memberFunc.getName() = "PutObject" and
    qn = "aws::s3::Client::PutObject"
  ) or
  target.getQualifiedName().matches("aws%::s3%::Client%::GetObject%") and qn = "aws::s3::Client::GetObject" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("aws::s3", "Client") and
    memberFunc.getName() = "GetObject" and
    qn = "aws::s3::Client::GetObject"
  ) or
  target.getQualifiedName().matches("google%::cloud%::storage%::Client%") and qn = "google::cloud::storage::Client" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("google::cloud", "storage") and
    memberFunc.getName() = "Client" and
    qn = "google::cloud::storage::Client"
  ) or
  target.getQualifiedName().matches("google%::cloud%::storage%::Client%::WriteObject%") and qn = "google::cloud::storage::Client::WriteObject" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("google::cloud::storage", "Client") and
    memberFunc.getName() = "WriteObject" and
    qn = "google::cloud::storage::Client::WriteObject"
  ) or
  target.getQualifiedName().matches("google%::cloud%::storage%::Client%::ReadObject%") and qn = "google::cloud::storage::Client::ReadObject" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("google::cloud::storage", "Client") and
    memberFunc.getName() = "ReadObject" and
    qn = "google::cloud::storage::Client::ReadObject"
  ) or
  target.getQualifiedName().matches("boost%::asio%::stream_file%") and qn = "boost::asio::stream_file" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost", "asio") and
    memberFunc.getName() = "stream_file" and
    qn = "boost::asio::stream_file"
  ) or
  target.getQualifiedName().matches("boost%::asio%::stream_file%::open%") and qn = "boost::asio::stream_file::open" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("boost::asio", "stream_file") and
    memberFunc.getName() = "open" and
    qn = "boost::asio::stream_file::open"
  ) or
  target.getQualifiedName().matches("ace%::ACE_OS%") and qn = "ace::ACE_OS" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("", "ace") and
    memberFunc.getName() = "ACE_OS" and
    qn = "ace::ACE_OS"
  ) or
  target.getQualifiedName().matches("ace%::ACE_OS%::open%") and qn = "ace::ACE_OS::open" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("ace", "ACE_OS") and
    memberFunc.getName() = "open" and
    qn = "ace::ACE_OS::open"
  ) or
  target.getQualifiedName().matches("ace%::ACE_OS%::unlink%") and qn = "ace::ACE_OS::unlink" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("ace", "ACE_OS") and
    memberFunc.getName() = "unlink" and
    qn = "ace::ACE_OS::unlink"
  ) or
  target.getQualifiedName().matches("ace%::ACE_OS%::mkdir%") and qn = "ace::ACE_OS::mkdir" or
  exists(MemberFunction memberFunc | 
    memberFunc = target and
    memberFunc.getDeclaringType().hasQualifiedName("ace", "ACE_OS") and
    memberFunc.getName() = "mkdir" and
    qn = "ace::ACE_OS::mkdir"
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
