#!/bin/sh
set -eu

task=${1:-src/task.c}
grep -F 'munmap(sft->data, sft->length)' "$task" >/dev/null
grep -F 'free(sft->source_path)' "$task" >/dev/null
grep -F 'free(sft->nego)' "$task" >/dev/null
grep -F 'free(sft);' "$task" >/dev/null
