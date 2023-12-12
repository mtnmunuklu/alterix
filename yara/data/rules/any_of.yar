rule foo {
  strings:
    $a = "foo"
    $b = "bar"
  condition:
    any of ($a*)
}