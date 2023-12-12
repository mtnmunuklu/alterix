rule win_files_operation {
    meta:
        author = "x0r"
        description = "Affect private profile"
    version = "0.1"
    strings:
        $f1 = "kernel32.dll" nocase
        $c1 = "WriteFile"
        $c2 = "SetFilePointer"
        $c3 = "WriteFile"
        $c4 = "ReadFile"
        $c5 = "DeleteFileA"
        $c6 = "CreateFileA"
        $c7 = "FindFirstFileA"
        $c8 = "MoveFileExA"
        $c9 = "FindClose"
        $c10 = "SetFileAttributesA"
        $c11 = "CopyFile"

    condition:
        $f1 and 3 of ($c*)
}