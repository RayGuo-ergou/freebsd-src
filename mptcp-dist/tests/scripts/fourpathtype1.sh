#!/bin/csh
#
# Launch a four-path rsync where the client initiates a connection
# then pushes data to the server.
#

set testname="twopathtype1"

# Access to the source host
set srcvm = "FB11-test1"
set srchost = "test1"
set srchostport = "3322"
set srchostaddr = "172.16.1.2"
set srchostmpaddr = "172.16.2.2"

# Access to the destination host
set dstvm = "FB11-test2"
set dsthost = "test2"
set dsthostport = "3323"
set dsthostaddr = "172.16.3.2"
set dsthostmpaddr = "172.16.4.2"

# receiver host port (to clear data before transfer)
set rcvhostport = $dsthostport  # Push data to server

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

# Set siftr (0 disabled, 1 enabled)
set do_siftr = "0"

# Set tcpdump (0 disabled, 1 enabled)
set do_tcpdump = "0"

echo "Loaded config for four path rysnc"
echo "" && echo "${srchost} (client) is multi-homed, ${dsthost} (server) is"
echo "multi-homed and we PUSH data from ${dsthost} to ${srchost}."
echo "----"


