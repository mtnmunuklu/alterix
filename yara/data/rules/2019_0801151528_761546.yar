/*
Bu YARA kurali ZARLAB tarafından hazırlanmıştır.
*/

rule sddddddddd
{
	meta:
		description = "01.08.2019 gün ve 15:15 saatinde oluşturulan YARA kuralıdır."
		reference = ""
		author = "ZARLAB"
		date = "01.08.2019"
		maltype = ""
		filetype = ""
		os = ""

	strings:
		$IP0 = "192.168.77.1" nocase fullword 

		$URL0 = "dropbox.com" nocase fullword 
		$URL1 = "1.77.168.192.in-addr.arpa" nocase fullword 

		$hash0 = "c562d245745ffcf4c3964920b89b190c" nocase fullword 
		$hash1 = "8bf0b7a494f3f86e6f1574a6414fcf0a1eb41508" nocase fullword 
		$hash2 = "a56d4329ff40f723a7493170d904c4cc09b9a5f3e4642d2a8520db3c344ffbe6373008aa874beaa412c9276d2601c4fab2d4e32b2e7c6f5a6ccf7a1e931e052e" nocase fullword 
		$hash3 = "67943159" nocase fullword 

		$stringsASCII0 = "0x41a030" nocase fullword 
		$stringsASCII1 = "0x41a068" nocase fullword 
		$stringsASCII2 = "0x41a078" nocase fullword 

	condition:
		
	    ( 1 of ($URL*) ) or
            ( 2 of ($hash*) and all of ($stringsASCII*))

}
