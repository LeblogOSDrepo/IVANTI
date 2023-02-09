Function ConvertIP_3digits {
    param(
        [string] $IPaddr
    )
	
	$Temp = $IPaddr.split(".")
	if ($Temp[0].Length -eq 1) { $Temp[0] = "00" + $Temp[0] }
	if ($Temp[0].Length -eq 2) { $Temp[0] = "0"  + $Temp[0] }
	if ($Temp[1].Length -eq 1) { $Temp[1] = "00" + $Temp[1] }
	if ($Temp[1].Length -eq 2) { $Temp[1] = "0"  + $Temp[1] }
	if ($Temp[2].Length -eq 1) { $Temp[2] = "00" + $Temp[2] }
	if ($Temp[2].Length -eq 2) { $Temp[2] = "0"  + $Temp[2] }
	if ($Temp[3].Length -eq 1) { $Temp[3] = "00" + $Temp[3] }
	if ($Temp[3].Length -eq 2) { $Temp[3] = "0"  + $Temp[3] }
	$IPaddr = $Temp[0]+"."+$Temp[1]+"."+$Temp[2]+"."+$Temp[3]
	
	Return $IPaddr
}

Function ConvertIP_Clean {
    param(
        [string] $IPaddr
    )
	
	$temp = $IPaddr.split(".")
	If ($temp[0].substring(0, 1) -eq "0") { $temp[0] = $temp[0].substring(1, ($temp[0].Length -1)) }
	If ($temp[0].substring(0, 1) -eq "0") { $temp[0] = $temp[0].substring(1, ($temp[0].Length -1)) }
	If ($temp[1].substring(0, 1) -eq "0") { $temp[1] = $temp[1].substring(1, ($temp[1].Length -1)) }
	If ($temp[1].substring(0, 1) -eq "0") { $temp[1] = $temp[1].substring(1, ($temp[1].Length -1)) }
	If ($temp[2].substring(0, 1) -eq "0") { $temp[2] = $temp[2].substring(1, ($temp[2].Length -1)) }
	If ($temp[2].substring(0, 1) -eq "0") { $temp[2] = $temp[2].substring(1, ($temp[2].Length -1)) }
	If ($temp[3].substring(0, 1) -eq "0") { $temp[3] = $temp[3].substring(1, ($temp[3].Length -1)) }
	If ($temp[3].substring(0, 1) -eq "0") { $temp[3] = $temp[3].substring(1, ($temp[3].Length -1)) }	
	$IPaddr=$temp[0]+"."+$temp[1]+"."+$temp[2]+"."+$temp[3]
	
	Return $IPaddr
}

function Ignore-SSLCertificates
{
    $Provider = New-Object Microsoft.CSharp.CSharpCodeProvider
    $Compiler = $Provider.CreateCompiler()
    $Params = New-Object System.CodeDom.Compiler.CompilerParameters
    $Params.GenerateExecutable = $false
    $Params.GenerateInMemory = $true
    $Params.IncludeDebugInformation = $false
    $Params.ReferencedAssemblies.Add("System.DLL") > $null
    $TASource=@'
        namespace Local.ToolkitExtensions.Net.CertificatePolicy
        {
            public class TrustAll : System.Net.ICertificatePolicy
            {
                public bool CheckValidationResult(System.Net.ServicePoint sp,System.Security.Cryptography.X509Certificates.X509Certificate cert, System.Net.WebRequest req, int problem)
                {
                    return true;
                }
            }
        }
'@ 
    $TAResults=$Provider.CompileAssemblyFromSource($Params,$TASource)
    $TAAssembly=$TAResults.CompiledAssembly
    ## We create an instance of TrustAll and attach it to the ServicePointManager
    $TrustAll = $TAAssembly.CreateInstance("Local.ToolkitExtensions.Net.CertificatePolicy.TrustAll")
    [System.Net.ServicePointManager]::CertificatePolicy = $TrustAll
}

function IsIpAddressInRange {
	param(
			[string] $ipAddress,
			[string] $fromAddress,
			[string] $toAddress
		)
	
	#write-host "$ipAddress : $fromAddress => $toAddress"
	$ErrorActionPreference = "SilentlyContinue"
	$ip = [system.net.ipaddress]::Parse($ipAddress).GetAddressBytes()
	[array]::Reverse($ip)
	$ip = [system.BitConverter]::ToUInt32($ip, 0)

	$from = [system.net.ipaddress]::Parse($fromAddress).GetAddressBytes()
	[array]::Reverse($from)
	$from = [system.BitConverter]::ToUInt32($from, 0)

	$to = [system.net.ipaddress]::Parse($toAddress).GetAddressBytes()
	[array]::Reverse($to)
	$to = [system.BitConverter]::ToUInt32($to, 0)

	$from -le $ip -and $ip -le $to
	$ErrorActionPreference = "Continue"
}
