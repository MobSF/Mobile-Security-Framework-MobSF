rule ANDROID_Generic_Signs {
  meta:
    author = "team"
    description = "Generic suspicious Android strings"
  strings:
    $a = "DexClassLoader"
    $b = "PathClassLoader"
    $c = "Base64.decode"
  condition:
    any of them
}