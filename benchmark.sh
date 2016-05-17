#!/bin/bash

echo "Forking 100 concurrent clients to do one request each..."
for i in {1..100}; do
	(
		curl -Ss -w "%{http_code}\t%{time_total}\n" -o /dev/null --resolve google.com:443:127.0.0.1 https://google.com/
	) &
done

wait
