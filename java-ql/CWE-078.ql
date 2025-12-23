// Auto-generated; CWE-078; number of APIs 120
import java

predicate isTargetApi(Callable target, string qn) {
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.lang", "Runtime") and
    m.getName() = "getRuntime" and
    qn = "java.lang.Runtime.getRuntime"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.lang", "Runtime") and
    m.getName() = "exec" and
    qn = "java.lang.Runtime.exec"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("java.lang", "ProcessBuilder") and
    qn = "java.lang.ProcessBuilder.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.lang", "ProcessBuilder") and
    m.getName() = "command" and
    qn = "java.lang.ProcessBuilder.command"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.lang", "ProcessBuilder") and
    m.getName() = "start" and
    qn = "java.lang.ProcessBuilder.start"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.lang", "ProcessBuilder") and
    m.getName() = "startPipeline" and
    qn = "java.lang.ProcessBuilder.startPipeline"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.lang", "ProcessBuilder") and
    m.getName() = "directory" and
    qn = "java.lang.ProcessBuilder.directory"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.lang", "ProcessBuilder") and
    m.getName() = "environment" and
    qn = "java.lang.ProcessBuilder.environment"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.lang", "ProcessBuilder") and
    m.getName() = "inheritIO" and
    qn = "java.lang.ProcessBuilder.inheritIO"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.lang", "ProcessBuilder") and
    m.getName() = "redirectErrorStream" and
    qn = "java.lang.ProcessBuilder.redirectErrorStream"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.lang", "ProcessBuilder") and
    m.getName() = "redirectInput" and
    qn = "java.lang.ProcessBuilder.redirectInput"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.lang", "ProcessBuilder") and
    m.getName() = "redirectOutput" and
    qn = "java.lang.ProcessBuilder.redirectOutput"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.lang", "ProcessBuilder") and
    m.getName() = "redirectError" and
    qn = "java.lang.ProcessBuilder.redirectError"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.lang", "ProcessBuilder$Redirect") and
    m.getName() = "from" and
    qn = "java.lang.ProcessBuilder$Redirect.from"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.lang", "ProcessBuilder$Redirect") and
    m.getName() = "to" and
    qn = "java.lang.ProcessBuilder$Redirect.to"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.lang", "ProcessBuilder$Redirect") and
    m.getName() = "appendTo" and
    qn = "java.lang.ProcessBuilder$Redirect.appendTo"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.lang", "ProcessBuilder$Redirect") and
    m.getName() = "pipe" and
    qn = "java.lang.ProcessBuilder$Redirect.pipe"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.util.concurrent", "Executors") and
    m.getName() = "newSingleThreadExecutor" and
    qn = "java.util.concurrent.Executors.newSingleThreadExecutor"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.util.concurrent", "Executors") and
    m.getName() = "newFixedThreadPool" and
    qn = "java.util.concurrent.Executors.newFixedThreadPool"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.util.concurrent", "ExecutorService") and
    m.getName() = "submit" and
    qn = "java.util.concurrent.ExecutorService.submit"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("java.util.concurrent", "ExecutorService") and
    m.getName() = "execute" and
    qn = "java.util.concurrent.ExecutorService.execute"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.apache.commons.exec", "CommandLine") and
    qn = "org.apache.commons.exec.CommandLine.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.exec", "CommandLine") and
    m.getName() = "parse" and
    qn = "org.apache.commons.exec.CommandLine.parse"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.exec", "CommandLine") and
    m.getName() = "addArgument" and
    qn = "org.apache.commons.exec.CommandLine.addArgument"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.exec", "CommandLine") and
    m.getName() = "addArguments" and
    qn = "org.apache.commons.exec.CommandLine.addArguments"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.apache.commons.exec", "DefaultExecutor") and
    qn = "org.apache.commons.exec.DefaultExecutor.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.exec", "DefaultExecutor") and
    m.getName() = "execute" and
    qn = "org.apache.commons.exec.DefaultExecutor.execute"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.exec", "Executor") and
    m.getName() = "execute" and
    qn = "org.apache.commons.exec.Executor.execute"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.apache.commons.exec", "PumpStreamHandler") and
    qn = "org.apache.commons.exec.PumpStreamHandler.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.exec", "PumpStreamHandler") and
    m.getName() = "setProcessInputStream" and
    qn = "org.apache.commons.exec.PumpStreamHandler.setProcessInputStream"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.exec", "PumpStreamHandler") and
    m.getName() = "setProcessOutputStream" and
    qn = "org.apache.commons.exec.PumpStreamHandler.setProcessOutputStream"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.exec", "PumpStreamHandler") and
    m.getName() = "setProcessErrorStream" and
    qn = "org.apache.commons.exec.PumpStreamHandler.setProcessErrorStream"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.apache.commons.exec", "ExecuteWatchdog") and
    qn = "org.apache.commons.exec.ExecuteWatchdog.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.exec", "ExecuteWatchdog") and
    m.getName() = "start" and
    qn = "org.apache.commons.exec.ExecuteWatchdog.start"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.exec", "ExecuteWatchdog") and
    m.getName() = "stop" and
    qn = "org.apache.commons.exec.ExecuteWatchdog.stop"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.commons.exec.environment", "EnvironmentUtils") and
    m.getName() = "getProcEnvironment" and
    qn = "org.apache.commons.exec.environment.EnvironmentUtils.getProcEnvironment"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.codehaus.plexus.util.cli", "Commandline") and
    qn = "org.codehaus.plexus.util.cli.Commandline.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.codehaus.plexus.util.cli", "Commandline") and
    m.getName() = "setExecutable" and
    qn = "org.codehaus.plexus.util.cli.Commandline.setExecutable"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.codehaus.plexus.util.cli", "Commandline") and
    m.getName() = "setWorkingDirectory" and
    qn = "org.codehaus.plexus.util.cli.Commandline.setWorkingDirectory"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.codehaus.plexus.util.cli", "Commandline") and
    m.getName() = "addArguments" and
    qn = "org.codehaus.plexus.util.cli.Commandline.addArguments"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.codehaus.plexus.util.cli", "Commandline") and
    m.getName() = "execute" and
    qn = "org.codehaus.plexus.util.cli.Commandline.execute"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.codehaus.plexus.util.cli", "CommandLineUtils") and
    m.getName() = "executeCommandLine" and
    qn = "org.codehaus.plexus.util.cli.CommandLineUtils.executeCommandLine"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.codehaus.plexus.util.cli", "CommandLineUtils") and
    m.getName() = "executeCommandLineAsynchronously" and
    qn = "org.codehaus.plexus.util.cli.CommandLineUtils.executeCommandLineAsynchronously"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.apache.maven.shared.utils.cli", "Commandline") and
    qn = "org.apache.maven.shared.utils.cli.Commandline.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.maven.shared.utils.cli", "Commandline") and
    m.getName() = "setExecutable" and
    qn = "org.apache.maven.shared.utils.cli.Commandline.setExecutable"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.maven.shared.utils.cli", "Commandline") and
    m.getName() = "setWorkingDirectory" and
    qn = "org.apache.maven.shared.utils.cli.Commandline.setWorkingDirectory"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.maven.shared.utils.cli", "Commandline") and
    m.getName() = "addArguments" and
    qn = "org.apache.maven.shared.utils.cli.Commandline.addArguments"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.maven.shared.utils.cli", "Commandline") and
    m.getName() = "execute" and
    qn = "org.apache.maven.shared.utils.cli.Commandline.execute"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.maven.shared.utils.cli", "CommandLineUtils") and
    m.getName() = "executeCommandLine" and
    qn = "org.apache.maven.shared.utils.cli.CommandLineUtils.executeCommandLine"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.maven.shared.utils.cli", "CommandLineUtils") and
    m.getName() = "executeCommandLineAsynchronously" and
    qn = "org.apache.maven.shared.utils.cli.CommandLineUtils.executeCommandLineAsynchronously"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.apache.tools.ant.taskdefs", "Execute") and
    qn = "org.apache.tools.ant.taskdefs.Execute.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.tools.ant.taskdefs", "Execute") and
    m.getName() = "execute" and
    qn = "org.apache.tools.ant.taskdefs.Execute.execute"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.tools.ant.taskdefs", "Execute") and
    m.getName() = "launch" and
    qn = "org.apache.tools.ant.taskdefs.Execute.launch"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.tools.ant.taskdefs", "Execute") and
    m.getName() = "run" and
    qn = "org.apache.tools.ant.taskdefs.Execute.run"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.tools.ant.taskdefs", "ExecTask") and
    m.getName() = "execute" and
    qn = "org.apache.tools.ant.taskdefs.ExecTask.execute"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.apache.tools.ant.taskdefs", "PumpStreamHandler") and
    qn = "org.apache.tools.ant.taskdefs.PumpStreamHandler.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.apache.tools.ant.taskdefs.optional.ssh", "SSHExec") and
    m.getName() = "execute" and
    qn = "org.apache.tools.ant.taskdefs.optional.ssh.SSHExec.execute"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.gradle.api", "Project") and
    m.getName() = "exec" and
    qn = "org.gradle.api.Project.exec"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.gradle.process", "ExecOperations") and
    m.getName() = "exec" and
    qn = "org.gradle.process.ExecOperations.exec"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.gradle.api.tasks", "Exec") and
    m.getName() = "exec" and
    qn = "org.gradle.api.tasks.Exec.exec"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.gradle.process", "ExecSpec") and
    m.getName() = "commandLine" and
    qn = "org.gradle.process.ExecSpec.commandLine"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.gradle.process", "ExecSpec") and
    m.getName() = "args" and
    qn = "org.gradle.process.ExecSpec.args"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.gradle.process", "ExecSpec") and
    m.getName() = "setArgs" and
    qn = "org.gradle.process.ExecSpec.setArgs"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.gradle.process", "ExecSpec") and
    m.getName() = "executable" and
    qn = "org.gradle.process.ExecSpec.executable"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.gradle.process", "ExecSpec") and
    m.getName() = "setExecutable" and
    qn = "org.gradle.process.ExecSpec.setExecutable"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.gradle.process", "ExecSpec") and
    m.getName() = "workingDir" and
    qn = "org.gradle.process.ExecSpec.workingDir"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.gradle.process", "ExecSpec") and
    m.getName() = "setWorkingDir" and
    qn = "org.gradle.process.ExecSpec.setWorkingDir"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.gradle.process", "ExecSpec") and
    m.getName() = "environment" and
    qn = "org.gradle.process.ExecSpec.environment"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.gradle.process", "ExecSpec") and
    m.getName() = "setEnvironment" and
    qn = "org.gradle.process.ExecSpec.setEnvironment"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.gradle.process", "ExecSpec") and
    m.getName() = "setStandardInput" and
    qn = "org.gradle.process.ExecSpec.setStandardInput"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.gradle.process", "ExecSpec") and
    m.getName() = "setStandardOutput" and
    qn = "org.gradle.process.ExecSpec.setStandardOutput"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.gradle.process", "ExecSpec") and
    m.getName() = "setErrorOutput" and
    qn = "org.gradle.process.ExecSpec.setErrorOutput"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.gradle.api.tasks", "JavaExec") and
    m.getName() = "exec" and
    qn = "org.gradle.api.tasks.JavaExec.exec"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.gradle.process", "JavaExecSpec") and
    m.getName() = "jvmArgs" and
    qn = "org.gradle.process.JavaExecSpec.jvmArgs"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.gradle.process", "JavaExecSpec") and
    m.getName() = "args" and
    qn = "org.gradle.process.JavaExecSpec.args"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.gradle.process", "JavaExecSpec") and
    m.getName() = "setMain" and
    qn = "org.gradle.process.JavaExecSpec.setMain"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.gradle.process", "JavaExecSpec") and
    m.getName() = "mainClass" and
    qn = "org.gradle.process.JavaExecSpec.mainClass"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("org.zeroturnaround.exec", "ProcessExecutor") and
    qn = "org.zeroturnaround.exec.ProcessExecutor.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.zeroturnaround.exec", "ProcessExecutor") and
    m.getName() = "command" and
    qn = "org.zeroturnaround.exec.ProcessExecutor.command"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.zeroturnaround.exec", "ProcessExecutor") and
    m.getName() = "commandSplit" and
    qn = "org.zeroturnaround.exec.ProcessExecutor.commandSplit"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.zeroturnaround.exec", "ProcessExecutor") and
    m.getName() = "start" and
    qn = "org.zeroturnaround.exec.ProcessExecutor.start"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.zeroturnaround.exec", "ProcessExecutor") and
    m.getName() = "execute" and
    qn = "org.zeroturnaround.exec.ProcessExecutor.execute"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.zeroturnaround.exec", "ProcessExecutor") and
    m.getName() = "directory" and
    qn = "org.zeroturnaround.exec.ProcessExecutor.directory"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.zeroturnaround.exec", "ProcessExecutor") and
    m.getName() = "environment" and
    qn = "org.zeroturnaround.exec.ProcessExecutor.environment"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.zeroturnaround.exec", "ProcessExecutor") and
    m.getName() = "redirectOutput" and
    qn = "org.zeroturnaround.exec.ProcessExecutor.redirectOutput"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.zeroturnaround.exec", "ProcessExecutor") and
    m.getName() = "redirectError" and
    qn = "org.zeroturnaround.exec.ProcessExecutor.redirectError"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.zeroturnaround.exec", "ProcessExecutor") and
    m.getName() = "redirectInput" and
    qn = "org.zeroturnaround.exec.ProcessExecutor.redirectInput"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("com.zaxxer.nuprocess", "NuProcessBuilder") and
    qn = "com.zaxxer.nuprocess.NuProcessBuilder.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.zaxxer.nuprocess", "NuProcessBuilder") and
    m.getName() = "command" and
    qn = "com.zaxxer.nuprocess.NuProcessBuilder.command"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.zaxxer.nuprocess", "NuProcessBuilder") and
    m.getName() = "start" and
    qn = "com.zaxxer.nuprocess.NuProcessBuilder.start"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.zaxxer.nuprocess", "NuProcessBuilder") and
    m.getName() = "environment" and
    qn = "com.zaxxer.nuprocess.NuProcessBuilder.environment"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.zaxxer.nuprocess", "NuProcessBuilder") and
    m.getName() = "directory" and
    qn = "com.zaxxer.nuprocess.NuProcessBuilder.directory"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.codehaus.groovy.runtime", "ProcessGroovyMethods") and
    m.getName() = "execute" and
    qn = "org.codehaus.groovy.runtime.ProcessGroovyMethods.execute"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.codehaus.groovy.runtime", "ProcessGroovyMethods") and
    m.getName() = "getText" and
    qn = "org.codehaus.groovy.runtime.ProcessGroovyMethods.getText"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.codehaus.groovy.runtime", "ProcessGroovyMethods") and
    m.getName() = "consumeProcessOutput" and
    qn = "org.codehaus.groovy.runtime.ProcessGroovyMethods.consumeProcessOutput"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.codehaus.groovy.runtime", "ProcessGroovyMethods") and
    m.getName() = "consumeProcessOutputStream" and
    qn = "org.codehaus.groovy.runtime.ProcessGroovyMethods.consumeProcessOutputStream"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("org.codehaus.groovy.runtime", "ProcessGroovyMethods") and
    m.getName() = "consumeProcessErrorStream" and
    qn = "org.codehaus.groovy.runtime.ProcessGroovyMethods.consumeProcessErrorStream"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.jcraft.jsch", "JSch") and
    m.getName() = "getSession" and
    qn = "com.jcraft.jsch.JSch.getSession"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.jcraft.jsch", "Session") and
    m.getName() = "connect" and
    qn = "com.jcraft.jsch.Session.connect"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.jcraft.jsch", "Session") and
    m.getName() = "openChannel" and
    qn = "com.jcraft.jsch.Session.openChannel"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.jcraft.jsch", "Channel") and
    m.getName() = "connect" and
    qn = "com.jcraft.jsch.Channel.connect"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.jcraft.jsch", "ChannelExec") and
    m.getName() = "setCommand" and
    qn = "com.jcraft.jsch.ChannelExec.setCommand"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.jcraft.jsch", "ChannelExec") and
    m.getName() = "start" and
    qn = "com.jcraft.jsch.ChannelExec.start"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.jcraft.jsch", "ChannelShell") and
    m.getName() = "start" and
    qn = "com.jcraft.jsch.ChannelShell.start"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("ch.ethz.ssh2", "Connection") and
    qn = "ch.ethz.ssh2.Connection.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("ch.ethz.ssh2", "Connection") and
    m.getName() = "connect" and
    qn = "ch.ethz.ssh2.Connection.connect"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("ch.ethz.ssh2", "Connection") and
    m.getName() = "openSession" and
    qn = "ch.ethz.ssh2.Connection.openSession"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("ch.ethz.ssh2", "Session") and
    m.getName() = "execCommand" and
    qn = "ch.ethz.ssh2.Session.execCommand"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("ch.ethz.ssh2", "Session") and
    m.getName() = "startShell" and
    qn = "ch.ethz.ssh2.Session.startShell"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("ch.ethz.ssh2", "Session") and
    m.getName() = "startSubSystem" and
    qn = "ch.ethz.ssh2.Session.startSubSystem"
  ) or
  exists(Constructor c |
    c = target and
    c.getDeclaringType().hasQualifiedName("net.schmizz.sshj", "SSHClient") and
    qn = "net.schmizz.sshj.SSHClient.<init>"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("net.schmizz.sshj", "SSHClient") and
    m.getName() = "connect" and
    qn = "net.schmizz.sshj.SSHClient.connect"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("net.schmizz.sshj", "SSHClient") and
    m.getName() = "startSession" and
    qn = "net.schmizz.sshj.SSHClient.startSession"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("net.schmizz.sshj.connection.channel.direct", "Session") and
    m.getName() = "exec" and
    qn = "net.schmizz.sshj.connection.channel.direct.Session.exec"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("net.schmizz.sshj.connection.channel.direct", "Session") and
    m.getName() = "startShell" and
    qn = "net.schmizz.sshj.connection.channel.direct.Session.startShell"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("net.schmizz.sshj.connection.channel.direct", "Session") and
    m.getName() = "allocateDefaultPTY" and
    qn = "net.schmizz.sshj.connection.channel.direct.Session.allocateDefaultPTY"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.github.dockerjava.api", "DockerClient") and
    m.getName() = "execCreateCmd" and
    qn = "com.github.dockerjava.api.DockerClient.execCreateCmd"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.github.dockerjava.api", "DockerClient") and
    m.getName() = "execStartCmd" and
    qn = "com.github.dockerjava.api.DockerClient.execStartCmd"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.github.dockerjava.api.command", "ExecCreateCmd") and
    m.getName() = "withCmd" and
    qn = "com.github.dockerjava.api.command.ExecCreateCmd.withCmd"
  ) or
  exists(Method m |
    m = target and
    m.getDeclaringType().hasQualifiedName("com.github.dockerjava.api.command", "ExecStartCmd") and
    m.getName() = "exec" and
    qn = "com.github.dockerjava.api.command.ExecStartCmd.exec"
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
