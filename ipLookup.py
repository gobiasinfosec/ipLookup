#! Python3
# ipLookup.py- v1
# Author - David Sullivan
#
# Calls the ipinfo.io website api and does a basic cURL-like request on an IP and also checks the IP against abuseipdb
#
# Notes:
#   -abuseIPDB only allows 1 lookup per second, for this reason there is a 1 second sleep delay in the loop between lookups (and why threading is not implemented)
#
# Revision  1.0     -   03/15/2015- Initial creation of script
#
# To do:
#   -add other sites to lookup
#   -add support for input options instead of just command line (just run the script and prompt for input if run with no options?)
#   -better output for report (parse the ipinfo data to a dictionary instead of a string)
#   -add parsing to automatically look for blacklisted IPs (will potentially need to add support for CIDR notation)
#   -better error handling
#   -add support to lookup email-address blacklists (potentially make this a separate program?)

import requests, optparse, pickle, datetime, os, time

ipdbOverQuota = False
ipdbAPI = '' #put your API for abuseipdb here
ipdbDays = '90' #how far back to look on abuseipdb for suspicious activity
ipdbOverload =  r'[{"id":"Too Many Requests","links":{"about":"https:\/\/www.abuseipdb.com\/api"},"status":"429","code":"1050","title":"The user has sent too many requests in a given amount of time.","detail":"You have exceeded the rate limit for this service."}]' #this is the error message from abuseipdb if you are overquota
divider = '--------------------------------------------------------------------'
ipDictDB = r'c:\temp\ip.db' #this is where the binary data for the database will be saved to check if the database has already looked up the IPs in the list
timeDiff = 15 #number of days before looking up an IP again
verifySetting = True

def cleanup(file):
    # create empty lists
    oList = []

    # save each line from file to a string in a list
    f = open(file, 'r')
    for line in f:
        oList.append(line.split()[0])
    f.close()

    # remove duplicates and put in numerical order by IP
    oList = list(set(oList))
    oList.sort(key=lambda s: list(map(int, s.split('.'))))

    # overwrite original IP file with ordered/deduplicated list
    out = open(file, 'w')
    for address in oList:
        out.write(address + '\n')
    out.close()

    return oList

def compare(oList, ipDictDB):
    # check to see if the dictionary/database already exists
    if os.path.exists(ipDictDB):
        f = open(ipDictDB, 'rb')
        myDict = pickle.loads(f.read())
        f.close()
    else:
        print('No database exists at specified location, creating database')
        myDict = {}

    # create empty lists
    workingList = []
    checkList = []

    # check to see if any addresses in the new list are already in the dictionary
    for address in oList:
        dictBool = True if address in myDict else False
        checkList.append(address) if dictBool else workingList.append(address)

    # check the positive matches against the dictionary to ensure that the timestamps aren't expired
    for address in checkList:
        workingList.append(address) if datetime.date.today() - myDict[address] > datetime.timedelta(timeDiff) else False

    # update the dictionary with new addresses and timestamps
    for address in workingList:
        myDict.update({address: datetime.date.today()})

    # save the dictionary back to the binary database
    f = open(ipDictDB, 'wb')
    pickle.dump(myDict, f)
    f.close()

    # return the list of IPs that need to be checked
    return workingList

def ioScan(ipList, outfile):
    global ipdbAPI, ipdbDays, ipdbOverQuota

    ioList = []
    badList = []
    outList = []
    suspendList = []

    #run the lookups and append the results to a list
    for address in ipList:
        if ipdbOverQuota:
            suspendList.append(address)
        else:
            time.sleep(1)
            r = requests.request('GET',r'http://ipinfo.io/%s' % address, verify=verifySetting)

            #abuseIPDB lookup
            ipdbRequest = (requests.request('Get', r'https://www.abuseipdb.com/check/%s/json?key=%s&days=%s' % (address, ipdbAPI, ipdbDays), verify=verifySetting).text)
            ipdbBool = (ipdbRequest != '[]')
            if ipdbRequest != ipdbOverload:
                ioList.append((r.text).rstrip('\n'))
                ioList.append((r'Address found in IPDB (https://www.abuseipdb.com/check/%s)' % address if ipdbBool else 'Address not reported in the last %s days' % ipdbDays).rstrip())
                if ipdbBool == True:
                    outList.append(address)
                    badList.append((r.text).rstrip('\n'))
                    badList.append((r'Address found in IPDB (https://www.abuseipdb.com/check/%s)' % address).rstrip())
            else:
                suspendList.append(address)
                ipdbOverQuota = True
                print('Your abuseipdb API is over-quota, suspending lookups')

    #write full results to a file
    if ioList != []:
        out = open(('%s.txt' % outfile), 'w')
        for x in range(len(ioList)):
            out.write(ioList[x]+'\n')
            out.write(divider+'\n')
        out.close()
        print('Full results saved to %s.txt' % outfile)
    else:
        print('No results to display')

    #write bad results to a file
    if badList != []:
        out = open(('%s_bad.txt' % outfile), 'w')
        for x in range(len(badList)):
            out.write(badList[x] + '\n')
            out.write(divider+'\n')
        out.close()
        print('Bad results saved to %s_bad.txt' % outfile)
    else:
        print('No bad IPs')

    #write bad IPs to a file
    if outList != []:
        out = open(('%s_badIPs.txt' % outfile), 'w')
        for address in outList:
            out.write(address+'\n')
        out.close()
        print('Bad IPs saved to %s_badIPs.txt' % outfile)

    # write suspended IPs to a file
    if suspendList != []:
        out = open(('%s_suspendedIPs.txt' % outfile), 'w')
        for address in suspendList:
            out.write(address + '\n')
        out.close()
        print('Over quota IPs saved to %s_suspendIPs.txt, try running these again in 24 hours' % outfile)

        #remove suspended IPs from database
        dbCleanup(suspendList)

def dbCleanup(oList):
    # check to see if the dictionary/database already exists
    ipTotal = 0
    if os.path.exists(ipDictDB):
        f = open(ipDictDB, 'rb')
        myDict = pickle.loads(f.read())
        f.close()
    else:
        print('No database exists at specified location, exiting')
        exit(0)

    # check to see if any addresses in the new list are already in the dictionary
    for address in oList:
        if address in myDict:
            del myDict[address]
            ipTotal += 1

    # save the dictionary back to the binary database
    f = open(ipDictDB, 'wb')
    pickle.dump(myDict, f)
    f.close()

    return ipTotal

def main():

    #Parse command line options
    parser = optparse.OptionParser('usage: python3 <path_to_script> -i <input file> -o <output file> -d <ip database> -c <database cleanup file>')
    parser.add_option('-i', dest='inputFile', type='string', help='specify ip list file')
    parser.add_option('-o', dest='outputFile', type='string', help='specify output file')
    parser.add_option('-d', dest='databaseFile', type='string', help='specify database file')
    parser.add_option('-c', dest='cleanupFile', type='string', help='specify database cleanup file')
    (options, args) = parser.parse_args()
    file = options.inputFile
    outfile = options.outputFile
    database = options.databaseFile
    clean = options.cleanupFile
    if clean != None:
        oList = cleanup(clean)
        ipTotal = dbCleanup(oList)
        print('%s IPs removed from database' % (ipTotal))
        exit(0)
    elif file == None or outfile == None:
        print(parser.usage)
        exit(0)

    if database == None:
        database = ipDictDB

    #Run the program
    oList = cleanup(file)
    ipList = compare(oList, database)
    ioScan(ipList, outfile)

main()

#Testing area
#http://api.blocklist.de/api.php?ip=8.8.8.8 -> This site seems to report everything to abuseipdb, so it may not be needed
#http://www.openbl.org/lists/base_all.txt
#https://check.torproject.org/exit-addresses -> TOR lookups
