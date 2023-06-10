rule ip_rule
{
strings:
	$ipv4_string = /([0-9]{1,3}\.){3}[0-9]{1,3}/
condition:
	$ipv4_string
}
rule url_rule
{
strings:
	$url_string = /https?:\/\/([\w\.-]+)([\/\w \.-]*)/ wide ascii
condition:
	$url_string
}

