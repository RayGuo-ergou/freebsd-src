#!/bin/csh
#
# Read in a configuration file and then run tests based on this
# input. Assume all nessesary VMs are already running and port
# forwarding has been configured.
#
# Does not attempt to validate here, so should be careful when 
# specifying the config file that everything is included.
#
# Usage: ./test_controller.sh test_config.sh


if ($#argv != 1) then
        echo "Usage: $0 <test_config.sh>"
        echo "Controller script for basic MP tests"
        goto out
endif

set test_config = $1

# SSH key
set sshkey = "mptcprootkey"

# Address of VM Host Machine
set vmhostaddr = "localhost"

# Check for file existence and read in vars from config. 
if (-f $test_config) then
    source $test_config
else
    echo "Can't find config file ${test_config}"
    goto out
endif

# State the VM Host Machine we are connecting to
echo "Running tests on VM Host Machine address $vmhostaddr"

# Set addresses on test hosts
echo "Configure $srchost with mp_addr $srchostmpaddr"
echo "Configure $dsthost with mp_addr $dsthostmpaddr"

# Note this use of sysctl results in an error message but does achieve
# the desired result of clearing the net.inet.tcp.mptcp.mp_addresses list.
ssh -p $srchostport -i ~/.ssh/$sshkey root@$vmhostaddr "sysctl net.inet.tcp.mptcp.mp_addresses="${srchostmpaddr}""
ssh -p $dsthostport -i ~/.ssh/$sshkey root@$vmhostaddr "sysctl net.inet.tcp.mptcp.mp_addresses="${dsthostmpaddr}""


# Configure desired dummynet settings
echo "Configuring DummynetVM1 for $vm1drate"
ssh -p $router1port -i ~/.ssh/$sshkey root@$vmhostaddr "ipfw pipe 1 config bw $vm1drate"
ssh -p $router1port -i ~/.ssh/$sshkey root@$vmhostaddr "ipfw pipe 2 config bw $vm1drate"

echo "Configuring DummynetVM2 for $vm2drate"
ssh -p $router2port -i ~/.ssh/$sshkey root@$vmhostaddr "ipfw pipe 1 config bw $vm2drate"
ssh -p $router2port -i ~/.ssh/$sshkey root@$vmhostaddr "ipfw pipe 2 config bw $vm2drate"

# Configure siftr, if enabled
if ($do_siftr == 1) then
    sleep 1
    echo "Starting siftr on $srchost"
    ssh -p $srchostport -i ~/.ssh/$sshkey root@$vmhostaddr \
    "rm /root/${testname}.siftr.log ; touch /root/${testname}.siftr.log ; sysctl net.inet.siftr.logfile=/root/${testname}.siftr.log"
    ssh -p $srchostport -i ~/.ssh/$sshkey root@$vmhostaddr \
    "sysctl net.inet.siftr.enabled=1"

    sleep 1
    echo "Starting siftr on $dsthost"
    ssh -p $dsthostport -i ~/.ssh/$sshkey root@$vmhostaddr \
    "rm /root/${testname}.siftr.log ; touch /root/${testname}.siftr.log ; sysctl net.inet.siftr.logfile=/root/${testname}.siftr.log"
    ssh -p $dsthostport -i ~/.ssh/$sshkey root@$vmhostaddr \
    "sysctl net.inet.siftr.enabled=1"
endif

# Start tcpdump, if enabled
if ($do_tcpdump == 1) then
    sleep 1
    echo "Starting tcpdump on $srchost"
    ssh -p $srchostport -i ~/.ssh/$sshkey root@$vmhostaddr \
    "tcpdump -i em1 -w /root/${testname}.em1.pcap >& tcpdump.em1.out & ; tcpdump -i em2 -w /root/${testname}.em2.pcap >& tcpdump.em2.out & ;"
endif

# Initiate rsync
echo "Executing rsync on $srchost"
sleep 1
# Log into receiver and clear file
ssh -p $rcvhostport -i ~/.ssh/$sshkey root@$vmhostaddr "rm -f ${rcvfilepath}/${filename}"
sleep 1
# Log into client host (srchost) and start rsync
ssh -p $srchostport -i ~/.ssh/$sshkey root@$vmhostaddr \
'rsync -e "ssh -i /root/.ssh/'$sshkey' -o StrictHostKeyChecking=no " --progress '$filesource' '$filedest

# Stop siftr, if enabled
if ($do_siftr == 1) then
    sleep 1
    echo "Stop siftr on $srchost"
    ssh -p $srchostport -i ~/.ssh/$sshkey root@$vmhostaddr \
    "sysctl net.inet.siftr.enabled=0"

    sleep 1
    echo "Stop siftr on $dsthost"
    ssh -p $dsthostport -i ~/.ssh/$sshkey root@$vmhostaddr \
    "sysctl net.inet.siftr.enabled=0"
endif

# Stop tcpdump, if enabled
if ($do_siftr == 1) then
    sleep 1
    echo "Stop tcpdump on $srchost"
    ssh -p $srchostport -i ~/.ssh/$sshkey root@$vmhostaddr \
    "killall tcpdump"
endif

# completed
echo "Test complete"
exit 0

# error
out:
    echo "Abort test"
    exit 1
