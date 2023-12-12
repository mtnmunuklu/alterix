rule foo {
  strings:
    $a = "foo"
    $b = "bar"
  condition:
    all of ($a, $b)
}