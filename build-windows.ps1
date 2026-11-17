$ErrorActionPreference = 'Stop'
$source = $PSScriptRoot
$release = Join-Path (Split-Path $source) 'release'
$output = Join-Path (Split-Path $source) 'outputs'
$env:GOCACHE = Join-Path (Split-Path $source) 'gocache'
$env:GOMODCACHE = Join-Path (Split-Path $source) 'gomodcache'
$env:CGO_ENABLED = '0'
$env:GOOS = 'windows'
$env:GOARCH = 'amd64'
$go = (Get-Command go.exe -ErrorAction Stop).Source
New-Item -ItemType Directory -Force -Path $release,$output | Out-Null
Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class HubMasterIcon {
 [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr BeginUpdateResource(string file, bool delete);
 [DllImport("kernel32.dll", SetLastError=true)] static extern bool UpdateResource(IntPtr handle, IntPtr type, IntPtr name, ushort language, byte[] data, uint size);
 [DllImport("kernel32.dll", SetLastError=true)] static extern bool EndUpdateResource(IntPtr handle, bool discard);
 public static void Apply(string file,string icon) {
  byte[] data=File.ReadAllBytes(icon);
  ushort count=BitConverter.ToUInt16(data,4);
  IntPtr handle=BeginUpdateResource(file,false);
  if(handle==IntPtr.Zero) throw new Win32Exception();
  try {
   using(var stream=new MemoryStream()) using(var writer=new BinaryWriter(stream)) {
    writer.Write((ushort)0);writer.Write((ushort)1);writer.Write(count);
    for(int i=0;i<count;i++) {
     int offset=6+i*16;
     uint size=BitConverter.ToUInt32(data,offset+8);
     uint position=BitConverter.ToUInt32(data,offset+12);
     byte[] image=new byte[size]; Buffer.BlockCopy(data,(int)position,image,0,(int)size);
     if(!UpdateResource(handle,(IntPtr)3,(IntPtr)(i+1),1033,image,size)) throw new Win32Exception();
     writer.Write(data,offset,12);writer.Write((ushort)(i+1));
    }
    byte[] group=stream.ToArray();
    if(!UpdateResource(handle,(IntPtr)14,(IntPtr)1,1033,group,(uint)group.Length)) throw new Win32Exception();
   }
  } catch {EndUpdateResource(handle,true);throw;}
  if(!EndUpdateResource(handle,false)) throw new Win32Exception();
 }
}
'@
foreach($role in @('Agent','Admin','Setup-Agent','Setup-Admin')) {
 $target=Join-Path $release ($role+'.exe')
 & $go -C $source build -trimpath -buildvcs=false -ldflags "-H=windowsgui -X main.role=$role" -o $target .
 if($LASTEXITCODE -ne 0){throw "Build failed: $role"}
 [HubMasterIcon]::Apply($target,(Join-Path $source 'hubmaster.ico'))
 Write-Output "Built $role"
}
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
foreach($component in @('Admin','Agent')) {
 $payload=Join-Path $release ($component+'-payload.zip')
 $memory=[IO.MemoryStream]::new()
 $archive=[IO.Compression.ZipArchive]::new($memory,[IO.Compression.ZipArchiveMode]::Create,$true)
 $parts=@('Agent');if($component -eq 'Admin'){$parts+= 'Admin'}
 foreach($part in $parts){[IO.Compression.ZipFileExtensions]::CreateEntryFromFile($archive,(Join-Path $release ($part+'.exe')),($part+'.exe'),[IO.Compression.CompressionLevel]::Optimal) | Out-Null}
 $archive.Dispose()
 $bytes=$memory.ToArray();$memory.Dispose()
 $target=Join-Path $output ('HubMaster-'+$component+'-2.3.2-Setup.exe')
 $stream=[IO.File]::Create($target)
 try {
  $stub=[IO.File]::ReadAllBytes((Join-Path $release ('Setup-'+$component+'.exe')))
  $stream.Write($stub,0,$stub.Length);$stream.Write($bytes,0,$bytes.Length)
  $magic=[Text.Encoding]::ASCII.GetBytes('HUBMZIP2');$stream.Write($magic,0,8)
  $length=[BitConverter]::GetBytes([uint64]$bytes.Length);$stream.Write($length,0,8)
 } finally {$stream.Dispose()}
 # Verify the installer footer and every embedded executable byte-for-byte.
 $check=[IO.File]::ReadAllBytes($target)
 $size=[BitConverter]::ToUInt64($check,$check.Length-8)
 if([Text.Encoding]::ASCII.GetString($check,$check.Length-16,8) -ne 'HUBMZIP2' -or $size -ne $bytes.Length){throw 'Invalid installer footer'}
 $payloadStream=[IO.MemoryStream]::new($bytes,$false)
 $zip=[IO.Compression.ZipArchive]::new($payloadStream,[IO.Compression.ZipArchiveMode]::Read)
 try {
  if($zip.Entries.Count -ne $parts.Count){throw 'Invalid payload count'}
  foreach($part in $parts){
   $entry=$zip.GetEntry($part+'.exe');$entryStream=$entry.Open();$copy=[IO.MemoryStream]::new()
   $entryStream.CopyTo($copy);$entryStream.Dispose()
   $actual=[Convert]::ToBase64String($copy.ToArray());$copy.Dispose()
   $expected=[Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $release ($part+'.exe'))))
   if($actual -cne $expected){throw 'Payload verification failed'}
  }
 } finally {$zip.Dispose();$payloadStream.Dispose()}
 Write-Output "Verified $target"
}
Get-FileHash -LiteralPath (Join-Path $output 'HubMaster-Admin-2.3.2-Setup.exe'),(Join-Path $output 'HubMaster-Agent-2.3.2-Setup.exe')
