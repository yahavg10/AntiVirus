

rule genericKeyLogger
{
	strings:
		$a = "GetAsyncKeyState" 
		$b = "GetKeyState"
	condition:
		any of ($*)
}

rule hookKeyLogger
{
	strings:
		$a = "SetWindowsHookEx"
	condition:
		$a
}


