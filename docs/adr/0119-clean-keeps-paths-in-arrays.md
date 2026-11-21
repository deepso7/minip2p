# `clean.sh` never round-trips paths through newline-delimited text

`scripts/clean.sh` collects, deduplicates and filters deletion candidates in bash arrays (NUL-delimited `find -print0` in, `in_array` for dedup) instead of `sort -u`. A newline-delimited sort would split a filename that contains a newline and could turn a fragment into a deletion target outside the repository; `in_repo` is the second guard.
