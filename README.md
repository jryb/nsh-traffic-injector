#  NSH Traffic Injector

The NSH traffic injector can be used to test NSH based service functions.  It uses a GRE/NSH encapsulations taking a PCAP file, extracts the IP packets, inserting the GRE/NSH header and passing the traffic on to the service function.

Using PCAP timestamp data the traffic can be replayed through the service function either at real-time replay speed, or as fast as the platform will handle.

### Test Topology
A typical setup would include this NSH traffic injection code and the test service function running in a docker network.  The code currently will run on an ubuntu docker image that can be started by using the following command (assuming you're running docker)

    nsh-traffic-injector$ docker run -it -v ~/Code/nsh-traffic-injector:/root/code ubuntu /bin/bash

### Requirments
The following packages are required to build:

    gcc
    make
    libpcap-dev

### Build
To build the code run make from the top directory:

    make

### Run
To run the code, please see the usage information. For example:

    root@06a9815ae875:~/code# ./pcap_to_nsh
    
    [+] Usage: ./pcap_to_nsh <options>
    
    + Options:
    -f -----------> Send packets fast (no realtime pkt spacing)
    -c <val> -----> PCAP packet count to send
    -i <val> -----> IP address to send to
    -p <val> -----> PCAP File to read from
    
    root@06a9815ae875:~/code# ./pcap_to_nsh -i 172.20.10.3 -p test.pcap
    Socket initialize.
    Reading test.pcap to send packets from....
    Progress: 97%
    Packet send finished.
    
    Sent 43 pkts in test.pcap
    Elapsed time: 30.063956 seconds

### Future Features
The current implementation of this NSh injector does not perform any validation on return traffic.  That feature is TBD.

