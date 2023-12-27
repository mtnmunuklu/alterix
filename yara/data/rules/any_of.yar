rule foo {
  strings:
    $a = "foo"
    $a2 = "foo2"
  condition:
    none of ($a*)
}