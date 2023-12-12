rule suspicious_version : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 3
		
	strings:
		$magic = { 25 50 44 46 }
		$ver = /%PDF-1.\d{1}/
	condition:
		$magic in (0..1024) and not $ver
}