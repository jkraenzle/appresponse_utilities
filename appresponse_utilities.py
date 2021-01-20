# Python-wrapped REST API utilities for AppResponse 11

from typing import Any, IO
import yaml
import os
import sys
import requests
import time
import argparse
import json
import getpass
from datetime import datetime
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Avoid warnings for insecure certificates
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

APPRESPONSE_UTILITIES_ACTIONS = [ "list_backups", \
			   "pull_backup", \
			   "delete_backup"]
APPRESPONSE_UTILITIES_SCRIPT_TIMEOUT = 60

# ---- YAML helper functions -----
# Define YAML Loader, as default Loader is not safe
class YAMLLoader(yaml.SafeLoader):
    """YAML Loader with `!include` constructor."""

    def __init__(self, stream: IO) -> None:
        """Initialise Loader."""

        try:
            self._root = os.path.split(stream.name)[0]
        except AttributeError:
            self._root = os.path.curdir

        super().__init__(stream)


def construct_include(loader: YAMLLoader, node: yaml.Node) -> Any:
    """Include file referenced at node."""

    filename = os.path.abspath(os.path.join(loader._root, loader.construct_scalar(node)))
    extension = os.path.splitext(filename)[1].lstrip('.')

    with open(filename, 'r') as f:
        if extension in ('yaml', 'yml'):
            return yaml.load(f, YAMLLoader)


yaml.add_constructor('!include', construct_include, YAMLLoader)

def yamlread (fn):
	try:
		if fn != None:
			with open(fn) as fh:
				yamlresult = yaml.load (fh, YAMLLoader)
		else:
			yamlresult = None
	except FileNotFoundError:
		yamlresult = None

	return yamlresult

# -----

##### HELPER FUNCTIONS
### jkraenzle: Update to be used by each call
# Run REST APIs to appliance and return result
# Assume 'payload' is JSON formatted
def appresponse_rest_api (action, path, appliance, access_token, version, payload = None, data = None, additional_headers = None):

	url = "https://" + appliance + path 

	bearer = "Bearer " + access_token
	headers = {"Authorization":bearer}
	if additional_headers != None:
		headers.update (additional_headers)

	if (action == "GET"):
		r = requests.get (url, headers=headers, verify=False)
	elif (action == "POST"):
		if payload != None:
			r = requests.post (url, headers=headers, data=json.dumps (payload), verify=False)
		else:
			r = requests.post (url, headers=headers, data=data, verify=False)
	elif (action == "PUT"):
		r = requests.put (url, headers=headers, data=json.dumps (payload), verify=False)
	elif (action == "DELETE"):
		r = requests.delete (url, headers=headers, verify=False)

	if (r.status_code not in [200, 201, 202, 204]):
		print ("Status code was %s" % r.status_code)
		print ("Error: %s" % r.content)
		result = None
	else:
		if (("Content-Type" in r.headers.keys ()) and ("application/json" in r.headers ["Content-Type"])):
			result = json.loads (r.content) 
		elif (("Content-Type" in r.headers.keys ()) and ("application/x-gzip" in r.headers ["Content-Type"])):
			result = r.content
		else:
			result = r.text

	return result 


##### BACKUP #####

def appresponse_backups_list (appliance, access_token, version):

	backup_list = appresponse_rest_api ("GET", "/api/npm.backup/1.0/backups", appliance, access_token, version)
	
	return backup_list ["items"]

# REST API Python wrapper to create backup on appliance
def appresponse_backup_create (appliance, access_token, version):

	# Kick off backup and give time to process
	payload = {"description": "Automated Backup"}

	backup_in_process = appresponse_rest_api ("POST", "/api/npm.backup/1.0/backups", appliance, access_token, version, payload)

	# If backup creation failed, return upstream showing the failure
	if (backup_in_process == None):
		return None

	# Get backup id and sleep so there's time for backup to initially create
	backup_id = backup_in_process ["id"]
	time.sleep (5)

	# Keep checking if backup has completed
	backup_complete = False
	while (backup_complete == False):
		backups = appresponse_backups_list (appliance, access_token, version)

		found = False
		for backup in backups:
			if (backup ["id"] == backup_id):
				found = True
				if (backup ["status"] == "completed"):
					backup_complete = True

		# If backup "id" is not found on appliance
		if (found == False):
			print ("Error starting backup on %s" % appliance)
			return None
		elif (backup_complete == False):
			time.sleep (2)

	return backup_id

def appresponse_backup_delete (appliance, access_token, version, backup_id):

	empty_result = appresponse_rest_api ("DELETE", "/api/npm.backup/1.0/backups/items/" + str(backup_id), appliance, access_token, version)

	return empty_result

# REST API Python wrapper to download and delete automated backup
def appresponse_backup_download_and_delete (appliance, access_token, version, backup_id):
	backup_file = appresponse_rest_api ("GET", "/api/npm.backup/1.0/backups/items/" + backup_id + "/file", appliance, access_token, version)

	filename = appliance + ".backup.tgz"
	if (backup_file != None):
		with open (filename, "wb") as backup_f:
			backup_f.write (backup_file)
	
	empty_result = appresponse_backup_delete (appliance, access_token, version, backup_id)

	return empty_result, filename

# REST API Python wrapper to create and pull backup from appliance
def appresponse_backup_get (appliance, access_token, version):
	backup_id = appresponse_backup_create (appliance, access_token, version)

	if (backup_id != None):
		empty_result,filename = appresponse_backup_download_and_delete (appliance, access_token, version, backup_id)
		return True,filename
	else:
		return False,filename

def appresponse_backup_upload (appliance, access_token, version, backup_file):
	data = backup_file.read ()

	backup = appresponse_rest_api ("POST", "/api/npm.backup/1.0/backups/upload", appliance, access_token, version, additional_headers={'Content-Type': 'application/octet-stream'}, data=data)

	return backup

def appresponse_backup_restore (appliance, access_token, version, id):
	backup_restore_status = appresponse_rest_api ("POST", "/api/npm.backup/1.0/backups/items/" + id + "/restore", appliance, access_token, version)

	return backup_restore_status

def appresponse_backup_restore_status (appliance, access_token, version):
	backup_restore_status = appresponse_rest_api ("GET", "/api/npm.backup/1.0/restore_status", appliance, access_token, version)

	return backup_restore_status

##### GENERAL FUNCTIONS

# REST API Python wrapper to authenticate to the server (Login)
# URL: https://<appliance>/api/mgmt.aaa/1.0/token ; pre-version 11.6
# URL: https://<appliance>/api/mgmt.aaa/2.0/token ; version 11.6 or later
# Header: Content-Type:application/json
# Body: {"user_credentials":{"username":<username>, "password":<password>},"generate_refresh_token":"true"}
def appresponse_authenticate (appliance, username, password, version):

	if (version in ["11.4", "11.5"]):
		url = "https://" + appliance + "/api/mgmt.aaa/1.0/token"
	else:
		url = "https://" + appliance + "/api/mgmt.aaa/2.0/token"
	credentials = {"username":username, "password":password}
	payload = {"user_credentials":credentials, "generate_refresh_token":False}
	headers = {"Content-Type":"application/json"}

	r = requests.post(url, data=json.dumps(payload), headers=headers, verify=False)

	if (r.status_code != 201):
		print ("Status code was %s" % r.status_code)
		print ("Error %s" % r.content)
		return None
	else:
		result = json.loads(r.content)

	return result["access_token"]

# Helper function to get list of hostnames from input
def hostnamelist_get (hostnamelist):
	hostnamelist_f = open (hostnamelist, 'r')

	output = []
	for row in hostnamelist_f:
		hostname = row.rstrip()
		output.append (hostname)

	hostnamelist_f.close ()

	return output

# REST API Python wrapper to request version information
# URL: https://<appliance>/api/common/1.0/info
# Header: AUthorization: Bearer <access_token>
def appresponse_version_get (appliance, access_token, version):
	url = "https://" + appliance + "/api/common/1.0/info"
	
	r = requests.get (url, verify=False)

	result = json.loads(r.content)

	version_str = result["sw_version"]
	
	return version_str


def run_action(hostnamelist, username, password, action, actionfile):

	# Check inputs for required data and prep variables
	if (hostnamelist == None or hostnamelist == ""):
		print ("Please specify a hostname using --hostname or a set of hostnames using --hostnamelist")
		return
	if (username == None or username == ""):
		print ("Please specify a username using --username")
		return
	if (action == None or action == ""):
		print ("Please specify an action using --action")
		return

	# Check that action exist in set of known actions
	if not action in APPRESPONSE_UTILITIES_ACTIONS:
		print ("Action %s is unknown" % action)

	if (password == None or password == ""):
		print ("Please provide password for account %s on %s" % username, hostname)
		password = getpass.getpass ()

	
	for hostname in hostnamelist:

		# Loop through hosts, applying 'action'
		version = appresponse_version_get (hostname, username, password)

		access_token = appresponse_authenticate (hostname, username, password, version)

		if (access_token == None or access_token == ""):	
			print ("Failed to login to %s. Terminating action ..." % hostname)
			return
	
		# ACTION - list_backups
		if (action == "list_backups"):
			backups_list = appresponse_backups_list (hostname, access_token, version)
			print (backups_list)
	
		# ACTION - pull_backup
		elif (action == "pull_backup"):
			backup,filename = appresponse_backup_get (hostname, access_token, version)

			if (backup == True):
				print ("Backup for %s was successful!" % (hostname))
			else:
				print ("Backup for %s was unsuccessful!" % (hostname))

		# ACTION - delete backup
		elif (action == "delete_backup"):
			if (actionfile == None or actionfile == ""):
				print ("Please specify an ID for the filename on the appliance that you would like to restore in --actionfile parameter")
			else:
				id = actionfile
			backup = appresponse_backup_delete (hostname, access_token, version, id)

		# ACTION - upload_backup
		elif (action == "upload_backup"):
			if (actionfile == None or actionfile == ""):
				print ("Please specify a filename for backup upload in --actionfile parameter")
		
			backup = None
			with open(actionfile, 'rb') as backup_file:
				backup = appresponse_backup_upload (hostname, access_token, version, backup_file)

			print (backup)

	return

def appresponse_credentials_get (filename):

	credentials = yamlread (filename)	
	
	hostname = None
	if 'hostname' in credentials:
		hostname = credentials['hostname'] 
	list = None
	if 'list' in credentials:
		list = credentials['list']
	username = None
	if 'username' in credentials:
		username = credentials['username'] 

	# Allow for testing, but the expectation is that this is not included in YAML
	password = None
	if 'password' in credentials:
		password = credentials['password']

	try:
		hostnamelist = hostnamelist_get (list)
	except:
		hostnamelist = None

	return hostname, hostnamelist, username, password 

def run_from_yaml(config):

	print("")
	print("Step 1 of 3: Confirming accounts and pre-requisites ...")
	print("")

	hostname, hostnamelist, username, password = appresponse_credentials_get(config)

	if hostname != None and hostnamelist != None:
		print("Please specify 'hostname' or 'list' in the configuration file, but not both.")
		print("Terminating script ...")
		return
	elif hostname != None and hostnamelist == None:
		hostnamelist = []
		hostnamelist.append(hostname)
	elif hostname == None and hostnamelist == None:
		print("Please specify 'hostname' or 'list' in the configruation file.")
		print("If 'list' is specified, please ensure file exists and permissions are set appropriately.")
		print("Terminating script ...")
		return

	# Login to source and destination AppResponses to confirm the passwords are correct before proceeding
	if password == None or password == "":
		print("Please provide password for account %s on the AppResponse appliances." % username)
		password = getpass.getpass()

	num_hostnames = len(hostnamelist)

	hostnames_to_backup = []
	for hostname in hostnamelist:

		try:
			version = appresponse_version_get(hostname, username, password)
			access_token = appresponse_authenticate(hostname, username, password, version)
		except:
			access_token = None

		if access_token == None:
			print("Authentication failed to AppResponse %s. Removing from backup list ..." % hostname)
		else:
			hostnames_to_backup.append({"hostname":hostname,"access_token":access_token,"version":version})

	num_backups_to_take = len(hostnames_to_backup)
	print("Backing up %d of the %d specified AppResponse appliances." % (num_backups_to_take, num_hostnames))

	print("")
	print("Step 2 of 3: Taking backups from AppResponse appliances")
	print("")

	backup_in_progress = 1
	for appliance in hostnames_to_backup:
		hostname = appliance['hostname']
		access_token = appliance['access_token']
		version = appliance['version'] 
		print("Starting backup %d of %d ..." % (backup_in_progress, num_backups_to_take))

		print("Checking backup space availability on AppResponse %s." % hostname)
		# Check the current list of primary AppResponse backups (list_backups)
		backups_list = appresponse_backups_list (hostname, access_token, version)

		# If there are two, delete oldest as only allowed to store two at a time on the AppResponse appliance (delete_backup)
		if len(backups_list) > 0:
			if len(backups_list) == 2:
				# Get ID of oldest backup
				timestamp_0 = backups_list[0]['backup_time']
				timestamp_1 = backups_list[1]['backup_time']
				if timestamp_0 < timestamp_1:
					id = backups_list[0]['id']
				else:
					id = backups_list[1]['id']

				print("Deleting oldest backup to create available space on AppResponse %s." % hostname)
				delete_status = appresponse_backup_delete(hostname, access_token, version, id)

		# Create, download, and delete a backup of the AppResponse at a current time (pull_backup)
		backup_status,backup_filename = appresponse_backup_get(hostname, access_token, version)
		if backup_status == False:
			print("AppResponse %s backup failed. Continuing to next appliance ..." % hostname)
			backup_in_progress+=1
			continue
		else:
			print("Backup file %s created and downloaded for AppResponse %s" % (backup_filename, hostname))

		backup_in_progress+=1


	print("")
	print("Step 3 of 3: Cleaning up after script execution.")
	print("")

	return

def main():

	# set up arguments in appropriate variables
	parser = argparse.ArgumentParser (description="Python utilities to automate information collection or \
		 configuration tasks within AppResponse environments")
	parser.add_argument('--hostname', help="Hostname or IP address of the AppResponse appliance")
	parser.add_argument('--list', help="File containing hostnames or IP addresses, one per line")
	parser.add_argument('--username', help="Username for the appliance")
	parser.add_argument('--password', help="Password for the username")
	parser.add_argument('--action', help="Action to perform: %s" % APPRESPONSE_UTILITIES_ACTIONS)
	parser.add_argument('--actionfile', help="Settings file associated with action")
	parser.add_argument('--fromconfig', help="Run full workflow from YAML config")
	args = parser.parse_args()

	if args.fromconfig != None:
		run_from_yaml(args.fromconfig)
	else:
		hostnamelist = []
		if args.hostname != None and args.list != None:
			print("Please use --hostname or --hostnamelist, but not both, to specify the hostnames to backup.")
		elif args.hostname != None:
			hostamelist.append(args.hostname)
		elif args.list != None:
			try:
				hostnamelist = hostnamelist_get(args.list)
			except:
				hostnamelist = None
			
		run_action(hostnamelist, args.username, args.password, args.action, args.actionfile)


if __name__ == "__main__":
	main ()
