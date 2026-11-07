#!/usr/bin/env bash
# Print the CodeQL languages a change touches, one per line.
#
# Reads changed paths (one per line) on stdin. With --all, ignores stdin and
# prints every language. Changes to the CodeQL workflow or this script select
# every language so a configuration change is always exercised in full.
set -euo pipefail

all_languages=(actions c-cpp java-kotlin javascript-typescript rust swift)

if [[ "${1:-}" == "--all" ]]; then
  printf '%s\n' "${all_languages[@]}"
  exit 0
fi

hits=" "

while IFS= read -r path; do
  [[ -z "$path" ]] && continue
  case "$path" in
    .github/workflows/codeql.yml | .github/scripts/codeql-languages.sh | .github/codeql/*)
      printf '%s\n' "${all_languages[@]}"
      exit 0
      ;;
  esac
  case "$path" in
    .github/workflows/* | .github/actions/* | */action.yml | */action.yaml | action.yml | action.yaml)
      hits+="actions " ;;
  esac
  case "$path" in
    *.c | *.h | *.cc | *.cpp | *.cxx | *.hh | *.hpp | *.hxx | *.inl)
      hits+="c-cpp " ;;
  esac
  case "$path" in
    *.java | *.kt | *.kts | packages/kms-jvm/*)
      hits+="java-kotlin " ;;
  esac
  case "$path" in
    *.js | *.jsx | *.mjs | *.cjs | *.ts | *.tsx | *.mts | *.cts | *.vue | *.html | *.htm \
      | */package.json | package.json | */package-lock.json | package-lock.json \
      | */tsconfig*.json | tsconfig*.json)
      hits+="javascript-typescript " ;;
  esac
  case "$path" in
    *.rs | Cargo.toml | */Cargo.toml | Cargo.lock | .cargo/*)
      hits+="rust " ;;
  esac
  case "$path" in
    *.swift | packages/kms-swift/*)
      hits+="swift " ;;
  esac
done

for lang in "${all_languages[@]}"; do
  if [[ "$hits" == *" $lang "* ]]; then
    printf '%s\n' "$lang"
  fi
done
