#!/usr/bin/env bash
# p10k-style status line: dir (blue) + git branch/status (green clean, yellow dirty) + model.
# Previous claude-hud launcher saved as statusline.sh.bak.

input=$(cat)
dir=$(jq -r '.workspace.current_dir // .cwd // empty' <<<"$input")
model=$(jq -r '.model.display_name // empty' <<<"$input")
[ -z "$dir" ] && dir=$PWD

# Directory, ~-abbreviated like p10k
short=${dir/#$HOME/\~}
out=$(printf '\033[38;5;31m%s\033[0m' "$short")

# Git segment
if branch=$(git -C "$dir" --no-optional-locks symbolic-ref --short -q HEAD 2>/dev/null ||
            git -C "$dir" --no-optional-locks rev-parse --short HEAD 2>/dev/null); then
  status=$(git -C "$dir" --no-optional-locks status --porcelain=v2 --branch 2>/dev/null)
  marks=""
  ab=$(grep -m1 '^# branch.ab' <<<"$status")
  if [ -n "$ab" ]; then
    read -r _ _ ahead behind <<<"$ab"
    [ "${behind#-}" != 0 ] && marks+=" ⇣${behind#-}"
    [ "${ahead#+}" != 0 ] && marks+=" ⇡${ahead#+}"
  fi
  staged=$(grep -cE '^[12] [^.]' <<<"$status")
  unstaged=$(grep -cE '^[12] .[^.]' <<<"$status")
  untracked=$(grep -c '^?' <<<"$status")
  [ "$staged" -gt 0 ] && marks+=" +$staged"
  [ "$unstaged" -gt 0 ] && marks+=" !$unstaged"
  [ "$untracked" -gt 0 ] && marks+=" ?$untracked"
  if [ $((staged + unstaged + untracked)) -gt 0 ]; then color=178; else color=76; fi
  out+=$(printf ' \033[38;5;%sm%s%s\033[0m' "$color" "$branch" "$marks")
fi

[ -n "$model" ] && out+=$(printf ' \033[38;5;244m%s\033[0m' "$model")
printf '%s' "$out"
