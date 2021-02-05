echo $1 | openssl rsautl -encrypt -pubin -inkey key.public | hexdump -C
