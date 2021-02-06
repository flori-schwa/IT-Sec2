echo $1 | base64 -d | openssl rsautl -decrypt -inkey key.private | hexdump -C
