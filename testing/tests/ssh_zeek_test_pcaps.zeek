# @TEST-DOC: Test for creation of ssh.log and no reporter.log
# @TEST-EXEC: $ZEEK -Cr $TRACES/ssh_zeek_test_pcaps.pcap $PACKAGE %INPUT
# @TEST-EXEC: cat ssh.log | zeek-cut id.orig_h id.orig_p id.resp_h id.resp_p client server hassh hasshServer > ssh_cut.log
# @TEST-EXEC: btest-diff ssh_cut.log
# @TEST-EXEC: test ! -f reporter.log
