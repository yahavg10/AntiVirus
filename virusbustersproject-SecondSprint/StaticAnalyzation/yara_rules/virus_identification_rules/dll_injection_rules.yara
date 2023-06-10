
rule generic_dll_injection
{
	strings:
		$static_str_a = "Injecting DLL"
		$static_str_b = "Starting DLL Injection"
		$apicall_1 = "CreateRemoteThread"
		$apicall_2 = "CreateRemoteThreadEx"
		$apicall_3 = "GetProcAddress"
	condition:
		($apicall_3 and ($apicall_1 or $apicall_2)) or any of($static*)
}


rule processEmuration
{
	strings:
		$static_str_a = "Enumerating through processes"
		$apicall_1 = "Process32FirstW"
		$apicall_2 = "Process32NextW"
	condition:
		any of ($apicall*) or $static_str_a


}



rule APC_injection
{
	strings:
	$apicall_1 = "Thread32First"
	$apicall_2 = "Thread32Next"
	$apicall_3 = "QueueUserAPC"


condition:
	all of ($apicall*)


}


rule ThreadContext_Injection
{
	strings:
		$apicall_1 = "Thread32First"
		$apicall_2 = "Thread32Next"
		$apicall_3 = "GetThreadContext"
		$apicall_4 = "SetThreadContext"
condition:
	any of ($apicall*)
}

rule suspiciousDLLS
{
$first_dll = "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows\Appinit_Dlls"
$second_dll = "HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows\Appinit_Dlls"
$third_dll = "HKLM\System\CurrentControlSet\Control\Session Manager\AppCertDlls HKLM\Software\Microsoft\Windows"
$fourth_dll = "NT\currentversion\image file execution options"


}




rule ReflectiveDLL_Injection
{
strings:
      $x1 = "ReflectiveLoader" fullword ascii
      $x2 = "ReflectivLoader.dll" fullword ascii
      $x3 = "?ReflectiveLoader@@" ascii
      $x4 = "reflective_dll.x64.dll" fullword ascii
      $x5 = "reflective_dll.dll" fullword ascii
   condition:
    any of ($x*)
}