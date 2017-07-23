from optparse import OptionParser
import sys
import os
import requests
from pprint import pprint
import fnmatch
import time
import hashlib


class FStatus(object):
    INFECTED = "Infected"
    MODIFIED = "Modified"
    UNKNOWN = "Unknown"
    UNMODIFIED = "Unmodified"


def sha256_checksum(filename, block_size=65536):
    sha256 = hashlib.sha256()
    with open(filename, 'rb') as f:
        for block in iter(lambda: f.read(block_size), b''):
            sha256.update(block)
    return sha256.hexdigest()


def check_files(host, port, api_key, api_secret, filename, filehash, filepath):
    url = "http://{}:{}/api/checkfiles".format(host, port)
    headers = {
        'Content-Type': "application/json"
    }
    payload = {
        "abs_path": filepath,
                    "api_key": api_key,
                    "api_secret": api_secret,
                    "platform": "wordpress",
                    "file": {
                        "filename": filename,
                        "filehash": filehash
                    }
                }

    return requests.request("POST", url, json=payload, headers=headers)


def upload_files(host, port, api_key, api_secret, file_path):
    url = "http://{}:{}/api/upload".format(host, port)
    files = {'file': open(file_path, 'rb')}
    payload = {
        "abs_path": file_path,
        "api_key": api_key,
        "api_secret": api_secret,
        "platform": "wordpress"
    }
    return requests.request("POST", url, files=files, data=payload)


def find_files(directory, pattern):
    for root, dirs, files in os.walk(directory):
        for basename in files:
            if pattern == "all":
                filename = os.path.join(root, basename)
                yield filename
            elif fnmatch.fnmatch(basename, pattern):
                filename = os.path.join(root, basename)
                yield filename


def check_all_files(directory, pattern, host, port, api_key, api_secret):
    start_time = time.time()
    checked_data = list()
    for file_path in find_files(directory, pattern):
        file_status = {"filename":"",
                       "filehash": "",
                       "abs_path": "",
                       "is_infected":False,
                       "is_unknown":False,
                       "infected_by":False,
                       "ismodified":False,
                       "isunmodified":False,
                       "errors":""}
        file_name = file_path.split("/wordpress/")
        if len(file_name) < 2:
            continue
        filename = file_name[1]
        filehash = sha256_checksum(file_path)
        print "Checking FILE -", file_name, "\t"
        file_status["filename"] = filename
        file_status["filehash"] = filehash
        file_status["abs_path"] = file_path
        response = check_files(host, port, api_key, api_secret, filename, filehash, file_path)
        if response:
            json_data = response.json()
            details = json_data.get("details")
            if details:
                fstatus = details.get("status")
                if fstatus and (fstatus == FStatus.MODIFIED or fstatus == FStatus.UNKNOWN):
                    up_response = upload_files(host, port, api_key, api_secret, file_path)
                    if up_response:
                        up_json_data = up_response.json()
                        up_details = up_json_data.get("details")
                        if up_details:
                            up_fstatus = up_details.get("status")
                            if up_fstatus:
                                if up_fstatus == FStatus.INFECTED:
                                    file_status["is_infected"] = True
                                    file_status["infected_by"] = up_details.get("infected_by")
                                elif fstatus == FStatus.UNKNOWN:
                                    file_status["is_unknown"] = True
                                elif fstatus == FStatus.MODIFIED:
                                    file_status["ismodified"] = True
                            else:
                                file_status["errors"] = "Could not status from the details . " \
                                                        "Response {}".format(up_response.text)
                        else:
                            file_status["errors"] = "Could not find details from response for uploaded file" \
                                                    ". Response {}".format(up_response.text)
                    else:
                        file_status["errors"] = "Could not find response for uploaded file"
                elif fstatus and fstatus == FStatus.UNMODIFIED:
                    file_status["isunmodified"] = True
                else:
                    file_status["errors"] = "Could not find any status from the response {}".format(response.text)
            else:
                file_status["errors"] = "Could not find details from response. Response {}".format(str(response.text))
            print ("STATUS", response.text)
        else:
            print "No response", response
            file_status["errors"] = "Could not find response"

        checked_data.append(file_status)

    unknown_files = [x["abs_path"] for x in checked_data if x["is_unknown"]]
    modified_files = [x["abs_path"] for x in checked_data if x["ismodified"]]
    infected_files = [x["abs_path"] for x in checked_data if x["is_infected"]]

    print "-" * 60
    print "Unknown Files", "Total - " + str(len(unknown_files))
    print "-" * 60
    pprint(unknown_files)

    print "-" * 60
    print "Modified Files", "Total - " + str(len(modified_files))
    print "-" * 60
    pprint(modified_files)

    print "-" * 60
    print "Infected Files ", "Total - " + str(len(infected_files))
    print "-" * 60
    pprint(infected_files)

    total_time = time.time() - start_time
    print "-" * 60
    print "Completed in {} seconds".format(total_time)
    print "-" * 60

    return checked_data


def main():
    # Arguments
    parser = OptionParser(usage="""\
        Send the required details.

        Usage: %prog [options]

        """)
    parser.add_option("-p", "--directory", help="File Path/directory")
    parser.add_option("-f", "--fileformat", help="File formats .e.g - .txt .php", default="all")
    parser.add_option("-k", "--api_key", help="Provide api_key value")
    parser.add_option("-s", "--api_secret", help="Provide api_secret value")
    parser.add_option("", "--host", help="Hostname of the server", default='localhost')
    parser.add_option("", "--port", help="Application port", default='8000')
    if len(sys.argv) == 1:
        parser.print_help()
        return 1

    # process options
    (opts, args) = parser.parse_args()
    if not (opts.directory and opts.fileformat and opts.api_key and opts.api_secret and opts.host and opts.port):
        print ("Provide all option value - directory, host, port, api_key, api_secret \n\n")
        parser.print_help()
        return 1

    data = check_all_files(opts.directory, opts.fileformat,
                           opts.host, opts.port, opts.api_key, opts.api_secret)
    return 0


if __name__ == "__main__":
    sys.exit(main())