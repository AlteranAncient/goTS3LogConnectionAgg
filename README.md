# TS3 Server Log Connection Aggregator
This script will read through a default format TS3 log file and tell you how many 
clients were connected to the server at that given time, along with who the clients were.

It is pretty basic. The numbers are estimates based on the number of client connections/disconnections observed, 
with the counter reset when the server starts listening.

## Usage
The script has two collection methods - local log file, or from the serverquery interface via Telnet. 
The serverquery method is experimental and comes with caveats, so it is probably better to use the file method.

The binary is reasonably documented - you can use the `--help` flag at any time to see which options are available.

### File method
If you have not set `logappend=1` on your TS server, you may want to concatenate your logs into a single file first. 
You can do this in any way you wish, but one option is to run `cat *.log > somefile.log` to create a single file.

Once you have your log file, run the binary like so:
```
file --file ts3server_logs_2016.log --datetime "2016-09-18 15:04:05"
```

The script uses SQLite to process the log file and then queries the client count at the most recent connection log 
prior to datetime stamp that you specify.

### Serverquery Method
As mentioned earlier, I wouldn't recommend this method. It's not quite as simple and clear-cut as the file method. 
You risk getting yourself temporarily bannd by Serverquery due to command flood, unless you whitelist your IP or 
change your flood configuration - and also risk incomplete log download as a result.

Usage:
```
serverquery --help
```
This will tell you which flags to use to specify host, port, user and password. The `--datetime` flag is also required.