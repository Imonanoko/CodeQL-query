/**
 * CodeQL for Python — match a curated list of path/file touching APIs (CALLS only)
 * Strategy: match Call c where callee expression forms an Attribute/Name chain
 * that equals any target qualified name in our list.
 */

import python

/** Build dotted qualified name from an expression like Name/Attribute into string s. */
predicate dotted(Expr e, string s) {
  exists(Name n | e = n and s = n.getId()) or
  exists(Attribute a, string base, string attr |
    e = a and a.getAttr() = attr and dotted(a.getBase(), base) and s = base + "." + attr
  )
}

/** True if expr e's dotted name equals qn exactly (for Name/Attribute chains). */
predicate isQName(Expr e, string qn) { dotted(e, qn) }

/** Targets we want to match exactly (module.function or class.member as a dotted string). */
predicate targetExact(string qn) {
  qn =
    // core file/path operations
    "open" or
    "os.open" or
    "pathlib.Path.open" or
    "os.readlink" or
    "os.symlink" or
    "os.link" or
    "os.remove" or
    "os.unlink" or
    "pathlib.Path.unlink" or
    "os.rename" or
    "pathlib.Path.rename" or
    "shutil.move" or
    "os.replace" or
    "os.mkdir" or
    "os.makedirs" or
    "pathlib.Path.mkdir" or
    "os.rmdir" or
    "shutil.rmtree" or
    "pathlib.Path.rmdir" or
    "shutil.copy" or
    "shutil.copy2" or
    "shutil.copyfile" or
    "shutil.copytree" or
    "shutil.chown" or
    "os.chmod" or
    "pathlib.Path.chmod" or
    "os.path.join" or
    "pathlib.Path.__truediv__" or
    "pathlib.PurePath.joinpath" or
    "glob.glob" or
    "pathlib.Path.glob" or
    "pathlib.Path.rglob" or
    "os.walk" or
    "pathlib.Path.iterdir" or
    "zipfile.ZipFile.extract" or
    "zipfile.ZipFile.extractall" or
    "tarfile.TarFile.extract" or
    "tarfile.TarFile.extractall" or
    "shutil.unpack_archive" or
    "flask.send_file" or
    "flask.send_from_directory" or
    "werkzeug.datastructures.FileStorage.save" or
    "django.core.files.storage.Storage.save" or
    "django.core.files.storage.FileSystemStorage.save" or
    "django.db.connection.cursor.execute" or
    // helpers / normalizers
    "os.path.normpath" or
    "os.path.realpath" or
    "pathlib.Path.resolve" or
    "os.path.commonpath" or
    "pathlib.Path.is_relative_to" or
    "os.path.isabs" or
    "werkzeug.utils.secure_filename" or
    "werkzeug.utils.safe_join" or
    "flask.send_from_directory" or
    "django.utils.text.get_valid_filename" or
    "tempfile.NamedTemporaryFile" or
    "tempfile.TemporaryDirectory"
}

/** Whether a Call's callee expression matches any target qname. */
predicate isTargetCall(Call c, string qn) { isQName(c.getFunc(), qn) and targetExact(qn) }

/** MAIN QUERY: one SELECT only (no union) */
from Function f, Call c, string qn
where f.contains(c) and isTargetCall(c, qn)
select
  f.getName(),
  c.getLocation(),
  f.getLastStatement().getLocation(),
  "CALL -> " + qn
