rule generic_process_hollowing
{
	strings:
		$static_str_a = "Starting process hollowing"
		$api_call1 = "VirtualAllocEx"
		$api_call2 = "VirtualAlloc"
		$api_call3 = "ResumeThread"
		$api_call5 = "WriteProcessMemory"
		$api_call6 = "NtUnmapViewOfSection"
	condition:
		(($api_call1 or $api_call2) and $api_call3 and $api_call5 and $api_call6) or $static_str_a
}

