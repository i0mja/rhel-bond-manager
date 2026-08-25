#!/usr/bin/env bats
# bm::json::* — RFC 8259 string escaping and value helpers.
# Every escape case is validated by a real parser (python3 -m json.tool / jq).

load ../helpers

setup() {
  setup_sandbox
  load_artifact
}

# Build {"v": <str>} from a raw value, parse it back with jq, compare.
roundtrip() { # roundtrip <raw-string>
  local raw="$1" doc decoded
  doc="{\"v\":$(bm::json::str "$raw")}"
  printf '%s\n' "$doc" | python3 -m json.tool >/dev/null || return 1
  decoded="$(printf '%s' "$doc" | jq -j '.v')"
  [ "$decoded" = "$raw" ]
}

@test "json escape: double quotes" {
  run bm::json::escape 'say "hello"'
  [ "$output" = 'say \"hello\"' ]
  roundtrip 'say "hello"'
}

@test "json escape: backslash" {
  run bm::json::escape 'C:\net\bond'
  [ "$output" = 'C:\\net\\bond' ]
  roundtrip 'C:\net\bond'
}

@test "json escape: newline" {
  local s=$'line1\nline2'
  [ "$(bm::json::escape "$s")" = 'line1\nline2' ]
  roundtrip "$s"
}

@test "json escape: tab and carriage return" {
  local s=$'a\tb\rc'
  [ "$(bm::json::escape "$s")" = 'a\tb\rc' ]
  roundtrip "$s"
}

@test "json escape: control characters become \\u00XX" {
  local s=$'a\x01b\x1fc'
  [ "$(bm::json::escape "$s")" = 'a\u0001b\u001fc' ]
  roundtrip "$s"
}

@test "json escape: kitchen sink survives a real parser" {
  local s=$'mixed: "quotes" \\ back\nnew\ttab \x02ctrl :colon:'
  roundtrip "$s"
}

@test "json str: wraps in quotes" {
  run bm::json::str plain
  [ "$output" = '"plain"' ]
}

@test "json num_or_str: integers stay numbers" {
  [ "$(bm::json::num_or_str 100)" = "100" ]
  [ "$(bm::json::num_or_str -42)" = "-42" ]
  [ "$(bm::json::num_or_str 0)" = "0" ]
}

@test "json num_or_str: non-numbers become strings" {
  [ "$(bm::json::num_or_str unknown)" = '"unknown"' ]
  [ "$(bm::json::num_or_str "1000 Mbps")" = '"1000 Mbps"' ]
  [ "$(bm::json::num_or_str 1.5)" = '"1.5"' ]
}

@test "json bool" {
  [ "$(bm::json::bool 1)" = "true" ]
  [ "$(bm::json::bool true)" = "true" ]
  [ "$(bm::json::bool 0)" = "false" ]
  [ "$(bm::json::bool banana)" = "false" ]
}

@test "json arr and arr_of_lines produce parseable arrays" {
  local arr
  arr="$(bm::json::arr '"a"' '2' 'true')"
  [ "$arr" = '["a",2,true]' ]
  arr="$(printf 'eth0\neth1\n\n' | bm::json::arr_of_lines)"
  [ "$arr" = '["eth0","eth1"]' ]
  printf '%s\n' "$arr" | python3 -m json.tool >/dev/null
  arr="$(printf '' | bm::json::arr_of_lines)"
  [ "$arr" = "[]" ]
}
