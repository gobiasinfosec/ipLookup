#! Python3
# ipLookup.py- v1
# Author - David Sullivan
#
# Calls the ipinfo.io website api and does a basic cURL-like request on an IP and also checks the IP against abuseipdb
#
# Notes:
#   -abuseIPDB only allows 1 lookup per second, for this reason there is a 1 second sleep delay in the loop between lookups(and why threading is not implemented)
#
# Revision  1.0     -   03/15/2017- Initial creation of script
#           1.1     -   03/21/2017- Parsed data from ipinfo.io and added to the database in a format that can be used later. Because of this, I removed the full output and bad ip output. Also added a feature that will automatically strip out non-public IP addresses and erroneous text. Also fixed some bugs with unicode output and if the Verify Setting was set to false.
#
# Database fields
#   -Key    Ip Address
#   -[0]    Datetime of when the IP was looked up
#   -[1]    Hostname
#   -[2]    City
#   -[3]    Region
#   -[4]    Country
#   -[5]    Location (lat/long)
#   -[6]    Organization
#   -[7]    Bad IP (Boolean True if bad)
#
# To do:
#   -add other sites to lookup
#   -add support for input options instead of just command line (just run the script and prompt for input if run with no options?)
#   -add parsing to automatically look for blacklisted IPs (will potentially need to add support for CIDR notation)
#   -better error handling
#   -add support to lookup email-address blacklists (potentially make this a separate program?)
#   -add additional features for searching the database(maybe make this a separate program too?)
#   -cleanup code/make script more readable

import requests, optparse, pickle, datetime, os, time, ipaddress

# you can change these variables
ipdbAPI = '' #put your API for abuseipdb here
ipDictDB = r'' #this is where the binary data for the database will be saved
ipdbDays = '90' #how far back to look on abuseipdb for suspicious activity
timeDiff = 15 #number of days before looking up an IP again
verifySetting = True #should be set to true, not recommended turning off

# dont change these variables
ipdbOverQuota = False
ipdbOverload =  r'[{"id":"Too Many Requests","links":{"about":"https:\/\/www.abuseipdb.com\/api"},"status":"429","code":"1050","title":"The user has sent too many requests in a given amount of time.","detail":"You have exceeded the rate limit for this service."}]' #this is the error message from abuseipdb if you are overquota
divider = '--------------------------------------------------------------------'

# disable insecure request warning
if not verifySetting:
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def cleanup(file):
    # create empty lists
    oList = []
    oList2 = []

    # save each line from file to a string in a list
    f = open(file, 'r')
    for line in f:
        oList.append(line.split()[0])
    f.close()

    # remove duplicates and put in numerical order by IP
    oList = list(set(oList))
    oList.sort(key=lambda s: list(map(int, s.split('.'))))

    # remove private IP addresses and non-IPs from list:
    for address in oList:
        try:
            if ipaddress.IPv4Address(address).is_private == False:
                oList2.append(address)
        except Exception:
            pass

    # overwrite original IP file with ordered/deduplicated list
    out = open(file, 'w')
    for address in oList2:
        out.write(address + '\n')
    out.close()

    return oList2

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
        workingList.append(address) if datetime.date.today() - myDict[address][0] > datetime.timedelta(timeDiff) else False

    # save the dictionary back to the binary database
    f = open(ipDictDB, 'wb')
    pickle.dump(myDict, f)
    f.close()

    # return the list of IPs that need to be checked
    return workingList

def ioScan(ipList, outfile):
    global ipdbAPI, ipdbDays, ipdbOverQuota

    # create empty lists for functions
    badList = []
    suspendList = []

    # open database
    f = open(ipDictDB, 'rb')
    myDict = pickle.loads(f.read())
    f.close()

    #run the lookups and append the results to a list
    for address in ipList:
        if ipdbOverQuota:
            suspendList.append(address)
        else:
            time.sleep(1)
            print ('                                    ', end='\r')
            print ('Checking IP: %s' % address, end='\r' )

            #ipinfo.io lookup
            r = requests.request('GET',r'http://ipinfo.io/%s' % address, verify=verifySetting)
            myString = r.text
            myList = myString.split('"')
            myDict.update({address: [datetime.date.today(), myList[7], myList[11], myList[15], myList[19], myList[23],myList[27],False]})

            #abuseIPDB lookup
            ipdbRequest = (requests.request('Get', r'https://www.abuseipdb.com/check/%s/json?key=%s&days=%s' % (address, ipdbAPI, ipdbDays), verify=verifySetting).text)
            ipdbBool = (ipdbRequest != '[]')
            if ipdbRequest != ipdbOverload:
                if ipdbBool == True:
                    myDict[address][7] = True
                    badList.append((r.text).rstrip('\n'))
                    badList.append((r'Address found in IPDB (https://www.abuseipdb.com/check/%s)' % address).rstrip())
            else:
                suspendList.append(address)
                ipdbOverQuota = True
                print('Your abuseipdb API is over-quota, suspending lookups')

    #write bad results to a file
    if badList != []:
        out = open(('%s_bad.txt' % outfile), 'w', encoding='utf-8')
        for x in range(len(badList)):
            out.write(badList[x] + '\n')
            out.write(divider+'\n')
        out.close()
        print('Bad results saved to %s_bad.txt' % outfile)
    else:
        print('No bad IPs')

    # write suspended IPs to a file
    if suspendList != []:
        out = open(('%s_suspendedIPs.txt' % outfile), 'w', encoding='utf-8')
        for address in suspendList:
            out.write(address + '\n')
        out.close()
        print('Over quota IPs saved to %s_suspendIPs.txt, try running these again in 24 hours' % outfile)

        #remove suspended IPs from database
        dbCleanup(suspendList)

    # save the dictionary back to the binary database
    f = open(ipDictDB, 'wb')
    pickle.dump(myDict, f)
    f.close()

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
