# F5 WAF Sync

## Backup and sync WAF policies from source F5 to destination F5

## Running the commands
python waf_sync.py <source_f5_ip> <destination_f5_ip>

## Features
1. Export all waf policies locally on source and destination devices.
2. Backup all waf policies to the local server.
3. SCP transfer waf policies from source device to destination device.
4. Apply all waf policies from source device on destination device.

