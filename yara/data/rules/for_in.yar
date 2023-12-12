rule foo {
  condition:
    for any i in (1..2) : (i < 3)
}