# SPDX-License-Identifier: Apache-2.0
# Windows PowerShell 5.1 strips embedded quotes when calling native commands.
# Pass one explicitly escaped CRT command line, preserving SCM's ImagePath.
function ConvertTo-EdgeNativeArguments {
    param([string[]]$Arguments)
    $escaped = foreach ($value in $Arguments) {
        $value = [regex]::Replace($value, '(\\*)"', '$1$1\"')
        $value = [regex]::Replace($value, '(\\+)$', '$1$1')
        '"' + $value + '"'
    }
    return ($escaped -join ' ')
}
function Invoke-EdgeServiceControl {
    param([Parameter(Mandatory=$true)][string[]]$Arguments)
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = Join-Path $env:SystemRoot 'System32/sc.exe'
    $info.Arguments = ConvertTo-EdgeNativeArguments -Arguments $Arguments
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $info
    try {
        [void]$process.Start()
        $output = $process.StandardOutput.ReadToEnd()
        $errors = $process.StandardError.ReadToEnd()
        $process.WaitForExit()
        if ($process.ExitCode -ne 0) { throw "sc.exe failed ($($process.ExitCode)): $output $errors" }
        return $output
    } finally { $process.Dispose() }
}

# Windows 10 sc.exe has no preshutdown configuration command. Use the SCM API
# from the offline .NET Framework available with Windows PowerShell 5.1.
function Initialize-EdgeServiceConfigurationApi {
    if ('Izuma.EdgeServiceConfiguration' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
namespace Izuma {
    public static class EdgeServiceConfiguration {
        [StructLayout(LayoutKind.Sequential)]
        private struct PreshutdownInfo { public uint Timeout; }
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr OpenSCManager(string machine, string database, uint access);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr OpenService(IntPtr manager, string name, uint access);
        [DllImport("advapi32.dll", EntryPoint = "ChangeServiceConfig2W", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool ChangeConfig(IntPtr service, uint level, ref PreshutdownInfo info);
        [DllImport("advapi32.dll", EntryPoint = "QueryServiceConfig2W", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool QueryConfig(IntPtr service, uint level, ref PreshutdownInfo info,
                                               uint size, out uint needed);
        [DllImport("advapi32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseServiceHandle(IntPtr handle);
        private static uint AccessTimeout(string name, uint? timeout) {
            IntPtr manager = OpenSCManager(null, null, 1); // CONNECT
            if (manager == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
            try {
                IntPtr service = OpenService(manager, name, timeout.HasValue ? 2u : 1u);
                if (service == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
                try {
                    PreshutdownInfo info = new PreshutdownInfo();
                    if (timeout.HasValue) {
                        info.Timeout = timeout.Value;
                        if (!ChangeConfig(service, 7, ref info))
                            throw new Win32Exception(Marshal.GetLastWin32Error());
                    } else {
                        uint needed;
                        if (!QueryConfig(service, 7, ref info, 4, out needed))
                            throw new Win32Exception(Marshal.GetLastWin32Error());
                    }
                    return info.Timeout;
                } finally { CloseServiceHandle(service); }
            } finally { CloseServiceHandle(manager); }
        }
        public static void SetTimeout(string name, uint timeout) { AccessTimeout(name, timeout); }
        public static uint GetTimeout(string name) { return AccessTimeout(name, null); }
    }
}
'@
}
function Set-EdgeServicePreshutdownTimeout {
    param([Parameter(Mandatory=$true)][string]$ServiceName,
          [Parameter(Mandatory=$true)][uint32]$Milliseconds)
    Initialize-EdgeServiceConfigurationApi
    [Izuma.EdgeServiceConfiguration]::SetTimeout($ServiceName,$Milliseconds)
}
function Get-EdgeServicePreshutdownTimeout {
    param([Parameter(Mandatory=$true)][string]$ServiceName)
    Initialize-EdgeServiceConfigurationApi
    return [Izuma.EdgeServiceConfiguration]::GetTimeout($ServiceName)
}
