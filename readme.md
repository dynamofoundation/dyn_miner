This repo contains the Windows project files built in Visual Studio 2019.

To build, clone the repo and open the solution in Visual Studio.

The miner will display any OpenCL compatible platforms and will display all devices for any platform found.

Miner parameters are:

RPC URL - the URL of the full node RPC in the form of http://<server name>:<port>  e.g.  http://pool.dynamocoin.org:6344
RPC username
RPC password
Wallet to mine to (bech32 format)
CPU or GPU
    if CPU, the next parameter is the number of threads to create (should be less than number of cores on your system)
    if GPU, the next parameter is the number of compute units - values between 1000 and 2000 seem to work well for modern cards
Number of threads or compute units, as noted above
The platform ID to use for GPU mining.  Ignored for CPU.
"pool" or "solo" - indicator if you are mining on a pool or solo
