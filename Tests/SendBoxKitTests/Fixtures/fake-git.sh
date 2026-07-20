#!/bin/sh
if [ "$1" = "branch" ] && [ "$2" = "--show-current" ]; then
  printf '%s\n' "$FAKE_GIT_BRANCH"
  exit 0
fi
if [ "$1" = "rev-parse" ] && [ "$2" = "--show-toplevel" ]; then
  printf '%s\n' "$FAKE_GIT_ROOT"
  exit 0
fi
if [ "$1" = "rev-parse" ] && [ "$2" = "--abbrev-ref" ]; then
  [ -n "${FAKE_GIT_UPSTREAM:-}" ] || exit 1
  printf '%s\n' "$FAKE_GIT_UPSTREAM"
  exit 0
fi
if [ "$1" = "remote" ] && [ "$2" = "get-url" ]; then
  printf '%s\n' "$FAKE_GIT_REMOTE_URL"
  exit 0
fi
if [ "$1" = "config" ] && [ "$2" = "--get" ]; then
  if [ "$3" = "push.default" ] && [ -n "${FAKE_GIT_PUSH_DEFAULT:-}" ]; then
    printf '%s\n' "$FAKE_GIT_PUSH_DEFAULT"
    exit 0
  fi
  exit 1
fi
if [ "$1" = "config" ] && [ "$2" = "--get-all" ]; then
  exit 1
fi
if [ "$1" = "show-ref" ]; then
  [ "$4" = "refs/heads/$FAKE_GIT_BRANCH" ]
  exit $?
fi
printf '%s\n' "$*" >> "$FAKE_GIT_LOG"
exit 0
