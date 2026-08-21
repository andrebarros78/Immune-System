using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.ServiceProcess;
using System.Text;

namespace BarrosTech.ImmuneServiceHost {
 internal sealed class HostConfig {
  internal string ServiceName, Executable, Arguments, WorkingDirectory, LogFile;
  internal static HostConfig Load(string path) {
   var d=new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);
   foreach(var raw in File.ReadAllLines(path,Encoding.UTF8)){var line=raw.Trim(); if(line.Length==0||line.StartsWith("#")) continue; int p=line.IndexOf('='); if(p>0)d[line.Substring(0,p).Trim()]=line.Substring(p+1).Trim();}
   string[] req={"service_name","executable","arguments","working_directory","log_file"}; foreach(var k in req) if(!d.ContainsKey(k)||d[k].Length==0) throw new InvalidDataException("Missing config key: "+k);
   return new HostConfig{ServiceName=d["service_name"],Executable=d["executable"],Arguments=d["arguments"],WorkingDirectory=d["working_directory"],LogFile=d["log_file"]};
  }
 }
 internal sealed class HostedService:ServiceBase {
  readonly HostConfig c; readonly object gate=new object(); Process child; volatile bool stopping;
  internal HostedService(HostConfig cfg){c=cfg;ServiceName=c.ServiceName;CanStop=true;CanShutdown=true;AutoLog=true;}
  protected override void OnStart(string[] args){stopping=false;Directory.CreateDirectory(Path.GetDirectoryName(c.LogFile));Log("SERVICE_START");StartChild();}
  void StartChild(){var psi=new ProcessStartInfo{FileName=c.Executable,Arguments=c.Arguments,WorkingDirectory=c.WorkingDirectory,UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true};psi.EnvironmentVariables["PYTHONUTF8"]="1";child=new Process{StartInfo=psi,EnableRaisingEvents=true};child.OutputDataReceived+=(s,e)=>{if(e.Data!=null)Log("OUT "+e.Data);};child.ErrorDataReceived+=(s,e)=>{if(e.Data!=null)Log("ERR "+e.Data);};child.Exited+=(s,e)=>{int code=-1;try{code=child.ExitCode;}catch{}Log("CHILD_EXIT code="+code);if(!stopping)Environment.Exit(code==0?1067:code);};if(!child.Start())throw new InvalidOperationException("Child process failed to start");child.BeginOutputReadLine();child.BeginErrorReadLine();Log("CHILD_STARTED pid="+child.Id);}
  protected override void OnStop(){stopping=true;Log("SERVICE_STOP");StopChild();}
  protected override void OnShutdown(){stopping=true;Log("SERVICE_SHUTDOWN");StopChild();base.OnShutdown();}
  void StopChild(){var p=child;if(p==null)return;try{if(!p.HasExited){try{p.CloseMainWindow();}catch{}if(!p.WaitForExit(3000)){p.Kill();p.WaitForExit(5000);}}}catch(Exception ex){Log("CHILD_STOP_ERROR "+ex.GetType().Name);}finally{try{p.Dispose();}catch{}child=null;}}
  void Log(string m){lock(gate){File.AppendAllText(c.LogFile,DateTime.UtcNow.ToString("o")+" "+m+Environment.NewLine,Encoding.UTF8);}}
 }
 internal static class Program {
  static int Main(string[] args){try{string cfg=null;for(int i=0;i<args.Length-1;i++)if(string.Equals(args[i],"--config",StringComparison.OrdinalIgnoreCase))cfg=args[i+1];if(string.IsNullOrEmpty(cfg))throw new ArgumentException("--config is required");var c=HostConfig.Load(cfg);if(Environment.UserInteractive&&Array.IndexOf(args,"--console")>=0){Console.WriteLine("SERVICE_HOST_CONFIG_OK="+c.ServiceName);return 0;}ServiceBase.Run(new HostedService(c));return 0;}catch(Exception ex){try{Console.Error.WriteLine(ex);}catch{}return 2;}}
 }
}
