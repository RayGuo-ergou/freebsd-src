#!/bin/csh
#
# Launch a single-path rsync where the client initiates a connection
# then pushes data.
#

set testname="singlpath"

# Access to the source host
set srcvm = "FB11-test1"
set srchost = "test1"
set srchostport = "3322"
set srchostaddr = "172.16.2.2"
set srchostmpaddr = "0"

# Access to the destination host
set dstvm = "FB11-test2"
set dsthost = "test2"
set dsthostport = "3323"
set dsthostaddr = "172.16.3.2"
set dsthostmpaddr = "0"

# Access to the two dummynet routers
set router1port = "4422"
set router2port = "4423"

# Dummynet data rate
set vm1drate = "8Mbps"
set vm2drate = "8Mbps"

# File to be transferred
set rcvfilepath = "/tmp"               # path on the receiver
set filename = "random10M.file"        # the actual filename
set filesource = "/root/${filename}"   # source for rsync command
set filedest = "172.16.3.2:/tmp"       # dest for rsync command

# Receiver host port (to clear data before transfer)
set rcvhostport = $dsthostport  # Pushing data to server

# Set siftr (0 disabled, 1 enabled)
set do_siftr = "0"

# Set tcpdump (0 disabled, 1 enabled)
set do_tcpdump = "1"

echo "Loaded config for single path rysnc"
echo "----"
echo "" && echo "${srchost} (client) is single-homed, ${dsthost} (server) is"
echo "single-homed and we PUSH data from ${srchost} to ${dsthost}."


