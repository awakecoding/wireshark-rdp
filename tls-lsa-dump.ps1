#Requires -Module PSDetour
#Requires -RunAsAdministrator

#
# This tool was made possible thanks to Jordan Borean:
# https://github.com/jborean93
# https://twitter.com/BoreanJordan
#
# References:
# https://b.poc.fun/decrypting-schannel-tls-part-1/
# https://gist.github.com/jborean93/6c1f1b3130f2675f1618da56633eb1fa
#

[CmdletBinding()]
param (
    [Parameter(Position=0)]
    [string] $LogFile
)

if ([string]::IsNullOrEmpty($LogFile)) {
    $WindowsTemp = Join-Path $Env:SystemRoot 'Temp'
    $LogFile = Join-Path $WindowsTemp 'tls-lsa.log'
}

$LogFile = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($LogFile)
$session = New-PSDetourSession -ProcessId lsass -ErrorAction Stop
try {
    Invoke-Command -Session $session -ScriptBlock {

        Function Get-SecretKey {
            param([Parameter(Mandatory)][IntPtr]$KeyPtr)

            $dddbStructPtr = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($KeyPtr)
            $ssl3StructPtr = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($dddbStructPtr, 0x10)
            $uuurStructPtr = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($ssl3StructPtr, 0x20)
            $mskyStructPtr = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($uuurStructPtr, 0x10)

            $secretLength = [System.Runtime.InteropServices.Marshal]::ReadInt32($mskyStructPtr, 0x10)
            $secretPtr = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($mskyStructPtr, 0x18)

            $secret = [byte[]]::new($secretLength)
            [System.Runtime.InteropServices.Marshal]::Copy($secretPtr, $secret, 0, $secret.Length)
            , $secret
        }

        $tlsLog = [System.IO.File]::Open($using:LogFile, "Append", "Write", "Read")
        $tlsWriter = [System.IO.StreamWriter]::new($tlsLog)
        $tlsWriter.AutoFlush = $true
        $state = @{
            GetSecretKeyFunc = ${function:Get-SecretKey}.ToString()
            ClientRandoms    = [Hashtable]::Synchronized(@{})
            Stages           = [Hashtable]::Synchronized(@{})
            TlsWriter        = $tlsWriter
        }

        $ncrypt = @{ DllName = 'ncrypt.dll' }
        Start-PSDetour -State $state -Hook @(
            New-PSDetourHook @ncrypt -MethodName SslHashHandshake -Action {
                <#
                .DESCRIPTION
                Called for TLS 1.3 sessions and TLS 1.2 with RFC 7627 session hashing.
                It is used to capture the client_random value in the TLS ClientHello
                message for future reference in the other hooked functions.
                #>
                [OutputType([int])]
                param (
                    [IntPtr]$SslProvider,
                    [IntPtr]$HandshakeHash,
                    [IntPtr]$InputBytes,
                    [int]$InputLength,
                    [int]$Flags
                )

                # This buffer is the TLS packets, we are interested in the ClientHello
                # which is msgType 1 and version 0x0303 (TLS 1.2)
                $data = [byte[]]::new($InputLength)
                [System.Runtime.InteropServices.Marshal]::Copy($InputBytes, $data, 0, $data.Length)

                $msgType = $data[0]
                $version = if ($msgType -eq 1) {
                    [System.BitConverter]::ToUInt16($data, 4)
                }

                if ($msgType -eq 1 -and $version -eq 0x0303) {
                    $crandom = [byte[]]::new(32)
                    [System.Buffer]::BlockCopy($data, 6, $crandom, 0, $crandom.Length)

                    $tid = [System.Threading.Thread]::CurrentThread.ManagedThreadId
                    $this.State.ClientRandoms[$tid] = $crandom
                }

                $this.Invoke($SslProvider, $HandshakeHash, $InputBytes, $InputLength, $Flags)
            }
            New-PSDetourHook @ncrypt -MethodName SslExpandTrafficKeys -Action {
                <#
                .DESCRIPTION
                Called for TLS 1.3 sessions twice.
                First is for the handshake traffic key and second for the first
                handshake traffic secret.
                The function is undocumented but Param4 is the client secret and Param5
                is the server secret.
                #>
                [OutputType([int])]
                param (
                    [IntPtr]$Param1,
                    [IntPtr]$Param2,
                    [IntPtr]$Param3,
                    [IntPtr]$Param4,
                    [IntPtr]$Param5
                )

                $res = $this.Invoke($Param1, $Param2, $Param3, $Param4, $Param5)

                $null = New-Item -Path Function:\Get-SecretKey -Value ([ScriptBlock]::Create(
                        $this.State.GetSecretKeyFunc))
                $tid = [System.Threading.Thread]::CurrentThread.ManagedThreadId

                if ($this.State.Stages[$tid]) {
                    $suffix = 'TRAFFIC_SECRET_0'
                }
                else {
                    $suffix = 'HANDSHAKE_TRAFFIC_SECRET'
                    $this.State.Stages[$tid] = $true
                }

                $clientSecret = Get-SecretKey -KeyPtr $Param4
                $serverSecret = Get-SecretKey -KeyPtr $Param5
                $cr = $this.State.ClientRandoms[$tid]

                ($this.State.TlsWriter).WriteLine('CLIENT_{0} {1} {2}', $suffix,
                    [System.Convert]::ToHexString($cr),
                    [System.Convert]::ToHexString($clientSecret))
                ($this.State.TlsWriter).WriteLine('SERVER_{0} {1} {2}', $suffix,
                    [System.Convert]::ToHexString($cr),
                    [System.Convert]::ToHexString($serverSecret))

                $res
            }
            New-PSDetourHook @ncrypt -MethodName SslExpandExporterMasterKey -Action {
                <#
                .DESCRIPTION
                Called for TLS 1.3 sessions.
                Gets the exporter secret through the undocumented function.
                #>
                [OutputType([int])]
                param (
                    [IntPtr]$Param1,
                    [IntPtr]$Param2,
                    [IntPtr]$Param3,
                    [IntPtr]$Param4
                )

                $res = $this.Invoke($Param1, $Param2, $Param3, $Param4)

                $null = New-Item -Path Function:\Get-SecretKey -Value ([ScriptBlock]::Create(
                        $this.State.GetSecretKeyFunc))
                $tid = [System.Threading.Thread]::CurrentThread.ManagedThreadId

                $secret = Get-SecretKey -KeyPtr $Param4
                $cr = $this.State.ClientRandoms[$tid]

                ($this.State.TlsWriter).WriteLine('EXPORTER_SECRET {0} {1}',
                    [System.Convert]::ToHexString($cr),
                    [System.Convert]::ToHexString($secret))

                $res
            }
            New-PSDetourHook @ncrypt -MethodName SslGenerateSessionKeys -Action {
                <#
                .DESCRIPTION
                Called for TLS 1.2 sessions.
                Gets the master secret key for TLS 1.2 sessions.
                #>
                [OutputType([int])]
                param (
                    [IntPtr]$SslProvider,
                    [IntPtr]$MasterKey,
                    [IntPtr]$ReadKey,
                    [IntPtr]$WriteKey,
                    [IntPtr]$ParameterList,
                    [int]$Flags
                )

                <#
                typedef struct _NCryptBufferDesc {
                    ULONG         ulVersion;
                    ULONG         cBuffers;
                    PNCryptBuffer pBuffers;
                } NCryptBufferDesc, *PNCryptBufferDesc;

                typedef struct _NCryptBuffer {
                    ULONG cbBuffer;
                    ULONG BufferType;
                    PVOID pvBuffer;
                } NCryptBuffer, *PNCryptBuffer;
                #>
                $bufferCount = [System.Runtime.InteropServices.Marshal]::ReadInt32($ParameterList, 4)
                $bufferPtr = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($ParameterList, 8)
                for ($i = 0; $i -lt $bufferCount; $i++) {
                    $bufferSize = [System.Runtime.InteropServices.Marshal]::ReadInt32($bufferPtr)
                    $bufferType = [System.Runtime.InteropServices.Marshal]::ReadInt32($bufferPtr, 4)
                    $bufferValuePtr = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($bufferPtr, 8)
                    if ($bufferType -eq 20) {
                        # NCRYPTBUFFER_SSL_CLIENT_RANDOM
                        $cr = [byte[]]::new($bufferSize)
                        [System.Runtime.InteropServices.Marshal]::Copy($bufferValuePtr, $cr, 0, $cr.Length)
                        break
                    }

                    $bufferPtr = [IntPtr]::Add($bufferPtr, 8 + ([IntPtr]::Size))
                }

                # The client_random should always be in the ParameterList but the
                # fallback is still used.
                if (-not $cr) {
                    $cr = ($this.State.ClientRandoms)[([System.Threading.Thread]::CurrentThread.ManagedThreadId)]
                }

                $ssl5StructPtr = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($MasterKey, 0x10)
                $secretPtr = [IntPtr]::Add($ssl5StructPtr,
                    ([IntPtr]::Size -eq 8 ? 28 : 20))

                $secret = [byte[]]::new(48)
                [System.Runtime.InteropServices.Marshal]::Copy($secretPtr, $secret, 0, $secret.Length)

                ($this.State.TlsWriter).WriteLine('CLIENT_RANDOM {0} {1}',
                    [System.Convert]::ToHexString($cr),
                    [System.Convert]::ToHexString($secret))

                $this.Invoke($SslProvider, $MasterKey, $ReadKey, $WriteKey, $ParameterList, $Flags)
            }
        )

        Write-Host "SSLKEYLOGFILE=`'$using:LogFile`'"
        Write-Host "Press any key to stop SChannel TLS logging..."
        $null = $host.UI.RawUI.ReadKey()

        Stop-PSDetour

        $tlsWriter.Dispose()
        $tlsLog.Dispose()
    }
}
finally {
    $session | Remove-PSSession
}
