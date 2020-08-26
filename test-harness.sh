#!/bin/bash
#
# Author: Matthew Rasa
# E-mail: mrasa3@gatech.edu
#

declare -r test_exec=./test-firewall.py
declare -r test_exec_args='--timeout 2'
declare pass_num=0
declare test_num=0

if [[ "$(id -u)" -eq 0 ]]; then
	echo "$0: must run as non-root user" >&2
	exit 1
fi

if [[ ! -x "$test_exec" ]]; then
	echo "$0: no executable named $test_exec in the current directory" >&2
	exit 1
fi

sudo -v

#
# Wait for a server process to start listening on <port>.
#
# Returns with error status if <timeout> is exceeded before <port> comes alive.
#
_wait_for_port() {
	local port="$1"; local timeout="$2"
	local tend=$(($(date +'%s') + timeout))
	while ! nc -z 127.0.0.1 "$port"; do
		if [[ "$(date +'%s')" -ge "$tend" ]]; then
			echo "$0: timeout waiting for port $port" >&2
			return 1
		fi
	done
}

#
# If <allowed> is set to true, verify that <protocol> traffic was allowed.
# Otherwise, verify that it was blocked.
#
# Echoes an error message in the event of failure.
#
_assert_allowed() {
	local protocol="$1"; local allowed="$2"; shift 2
	if [[ "$(echo "$@" | awk "/$protocol:/ { print \$2 }")" == allowed ]]; then
		"$allowed" || echo "$protocol traffic was allowed by firewall\n"
	elif "$allowed"; then
		echo "$protocol traffic was blocked by firewall\n"
	fi
}

#
# Run a test case named <name>.
#
# ICMP, TCP, and UDP traffic is sent from <sender> to <receiver> on the given
# <port> and allowed/blocked status is recorded.  The test case passes if all
# protocol assumptions were correct (e.g. <tcp_allowed> was true and TCP was
# allowed, <udp_allowed> was false and UDP was blocked, etc.), otherwise the
# test reports a failure.
#
_run_test() {
	local name="$1"; local sender="$2" local receiver="$3" local port="$4"
	local icmp_allowed="$5" local tcp_allowed="$6"; local udp_allowed="$7"
	((test_num++))

	printf "%-50s%s" "$name"

	# Run test
	local output="$(sudo "$test_exec" $test_exec_args "$sender" "$receiver" "$port")"
	local errstr=""
	errstr="${errstr}$(_assert_allowed "ICMP" "$icmp_allowed" "$output")"
	errstr="${errstr}$(_assert_allowed "TCP" "$tcp_allowed" "$output")"
	errstr="${errstr}$(_assert_allowed "UDP" "$udp_allowed" "$output")"

	if [[ -z "$errstr" ]]; then
		((pass_num++))
		echo -e "\033[1;32mPASS\033[0m"
		return 0
	else
		echo -e "\033[1;31mFAIL\033[0m"
		echo -e "$errstr"
		return 1
	fi
}

#
# Start the firewall with <cfg>, run the given test via _run_test(), and
# perform clean up.
#
_full_test() {
	local name="$1"; local cfg="$2"; local sender="$3" local receiver="$4" local port="$5"
	local icmp_allowed="$6" local tcp_allowed="$7"; local udp_allowed="$8"

	# Start run-firewall.sh in the background
	echo "$cfg" > .run-firewall-cfg
	./run-firewall.sh .run-firewall-cfg &>/dev/null &
	_wait_for_port 6633 5 || exit 1

	_run_test "$name" "$sender" "$receiver" "$port" "$icmp_allowed" "$tcp_allowed" "$udp_allowed"
	rtn="$?"

	# Clean up
	sudo ./cleanup.sh &>/dev/null
	rm -f .run-firewall-cfg

	return "$rtn"
}

#
# Basic tests - verify that each rule field works as expected
#

_full_test "Empty rule" "1,-,-,-,-,-,-,-,-" e2 e1 1234 true true true
_full_test "Allow srcmac" "1,00:00:00:00:00:01,-,-,-,-,-,-,-" e2 e1 1234 true true true
for node in "02" "03"; do
	_full_test "Block srcmac $node" "1,00:00:00:00:00:$node,-,-,-,-,-,-,-" e2 e1 1234 false false false
done
_full_test "Allow dstmac" "1,-,00:00:00:00:00:01,-,-,-,-,-,-" e2 e1 1234 true true true
for node in "02" "03"; do
	_full_test "Block dstmac $node" "1,-,00:00:00:00:00:$node,-,-,-,-,-,-" e2 e1 1234 false false false
done
_full_test "Allow srcip" "1,-,-,10.0.0.1,-,-,-,-,-" e2 e1 1234 true true true
for node in "2" "3"; do
	_full_test "Block srcip $node" "1,-,-,10.0.0.$node,-,-,-,-,-" e2 e1 1234 false false false
done
_full_test "Allow dstip" "1,-,-,-,10.0.0.1,-,-,-,-" e2 e1 1234 true true true
for node in "2" "3"; do
	_full_test "Block dstip $node" "1,-,-,-,10.0.0.$node,-,-,-,-" e2 e1 1234 false false false
done
_full_test "Allow srcport" "1,-,-,-,-,1233,-,B,-" e2 e1 1234 true true true
_full_test "Block srcport" "1,-,-,-,-,1234,-,B,-" e2 e1 1234 true false false
_full_test "Allow dstport" "1,-,-,-,-,1233,-,B,-" e2 e1 1234 true true true
_full_test "Block dstport" "1,-,-,-,-,1234,-,B,-" e2 e1 1234 true false false
_full_test "Block protocol TCP" "1,-,-,-,-,-,-,T,-" e2 e1 1234 true false true
_full_test "Block protocol UDP" "1,-,-,-,-,-,-,U,-" e2 e1 1234 true true false
_full_test "Block protocol Both" "1,-,-,-,-,-,-,B,-" e2 e1 1234 true false false
_full_test "Block protocol ICMP" "1,-,-,-,-,-,-,I,-" e2 e1 1234 false true true
_full_test "Block protocol 6 (TCP)" "1,-,-,-,-,-,-,O,6" e2 e1 1234 true false true
_full_test "Block protocol 17 (UDP)" "1,-,-,-,-,-,-,O,17" e2 e1 1234 true true false
_full_test "Block protocol 1 (ICMP)" "1,-,-,-,-,-,-,O,1" e2 e1 1234 false true true

#
# Tests for each rule in firewall-config.pol
#
# Note: protocol blocking rules (e.g. verify GRE traffic is blocked), is not
# tested here. The above test cases do test protocol blocking for TCP, UDP, and
# ICMP; if those tests pass, it should be safe to assume that protocol blocking
# works in general.
#

./run-firewall.sh firewall-config.pol &>/dev/null &
_wait_for_port 6633 5 || exit 1

_run_test "Verify server2 TCP:1723 is blocked" client1 server2 1723 true false true
_run_test "Verify server2 TCP is allowed" client1 server2 1724 true true true
_run_test "Verify e1 SSH is blocked" w1 e1 22 true false true
_run_test "Verify e1 TCP is allowed" w1 e1 23 true true true
_run_test "Verify e2 SSH is blocked" w1 e2 22 true false true
_run_test "Verify e2 TCP is allowed" w1 e2 23 true true true
_run_test "Verify e3 SSH is blocked" w1 e3 22 true false true
_run_test "Verify e3 TCP is allowed" w1 e3 23 true true true
_run_test "Verify server1 DNS is blocked" client1 server1 53 true true false
_run_test "Verify server1 NTP is blocked" client1 server1 123 true true false
_run_test "Verify server1 UDP is allowed" client1 server1 124 true true true
_run_test "Verify server2 DNS is blocked" client1 server2 53 true true false
_run_test "Verify server2 NTP is blocked" client1 server2 123 true true false
_run_test "Verify server2 UDP is allowed" client1 server2 124 true true true
_run_test "Verify server3 DNS is allowed" client1 server3 53 true true true
_run_test "Verify server3 NTP is allowed" client1 server3 123 true true true
_run_test "Verify w1 cannot ping client1" w1 client1 1234 false true true
_run_test "Verify w2 cannot ping client1" w2 client1 1234 false true true
_run_test "Verify w3 can ping client1" w3 client1 1234 true true true
_run_test "Verify e1 cannot send to e3 TCP:9950" e1 e3 9950 true false true
_run_test "Verify e1 cannot send to e3 TCP:9951" e1 e3 9951 true false true
_run_test "Verify e1 cannot send to e3 TCP:9952" e1 e3 9952 true false true
_run_test "Verify e1 can send to e3 TCP" e1 e3 9953 true true true
_run_test "Verify e2 can send to e3 TCP:9950" e2 e3 9950 true true true
_run_test "Verify e2 can send to e3 TCP:9951" e2 e3 9951 true true true
_run_test "Verify e2 can send to e3 TCP:9952" e2 e3 9952 true true true
_run_test "Verify client1 cannot send TCP/UDP to e1" client1 e1 1234 true false false
_run_test "Verify client1 cannot send TCP/UDP to e2" client1 e2 1234 true false false
_run_test "Verify client1 cannot send TCP/UDP to e3" client1 e3 1234 true false false
_run_test "Verify server3 UDP:500 is blocked" client1 server3 500 true true false
_run_test "Verify server3 UDP:1701 is blocked" client1 server3 1701 true true false
_run_test "Verify server3 UDP is allowed" client1 server3 1702 true true true

sudo ./cleanup.sh &>/dev/null

echo -e "\nPassed ($pass_num/$test_num)"
[[ "$pass_num" -eq "$test_num" ]]
exit "$?"
