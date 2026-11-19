#!/bin/bash
# PC self-test of the DNS filter and packet code. Needs ./build.sh first (for out/assets/block.txt).
set -e
cd "$(dirname "$0")/.."
rm -rf out/test && mkdir -p out/test
javac -encoding UTF-8 -nowarn -d out/test app/java/local/pureguard/Dns.java test/DnsTest.java
java -cp out/test local.pureguard.DnsTest out/assets/block.txt out/assets/wild.txt
# Wireless-debugging pairing crypto (SPAKE2, adb key format, certificate, HKDF).
javac -encoding UTF-8 -nowarn -d out/test app/java/local/pureguard/Spake2.java app/java/local/pureguard/AdbKeys.java test/Spake2Test.java
java -cp out/test local.pureguard.Spake2Test
