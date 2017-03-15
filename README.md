# ipLookup
Python3 script used to get ip address info and check addresses against common blacklists

## Usage
Run script with default settings:

'python3 {path_to_script} -i {input file} -o {output file}'

Option to point to a non-default database (used for not repeating lookups):

'-d {ip database}'

Option to remove IPs from the database (if you want to rescan them)"

'-c {database cleanup file}'

Planned features can be found in the script

### Disclaimer

I did not write any of the tools used by Omnislash and do not take credit for doing so. Omnislash is just meant to make using these tools easier with a single kick-off point for automation.

It has been provided for testing and academic purposes only. Do not use this tool against networks that you do not own or have express/strict written consent to test against. Do not use for illegal purposes.

