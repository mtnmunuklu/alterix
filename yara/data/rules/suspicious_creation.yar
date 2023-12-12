rule suspicious_creation : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 2
		
	strings:
		$magic = { 25 50 44 46 }
		$header = /%PDF-1\.(3|4|6)/
		
		$create0 = /CreationDate \(D:20101015142358\)/
		$create1 = /CreationDate \(2008312053854\)/
	condition:
		$magic in (0..1024) and $header and 1 of ($create*)
}