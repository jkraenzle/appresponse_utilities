# Python-wrapped REST API utilities for AppResponse 11

from typing import Any, IO
import yaml
import os
import glob
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

##### YAML FUNCTIONS #####
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

##### REST API INTEGRATION #####
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

	backup_list = appresponse_rest_api("GET", "/api/npm.backup/1.0/backups", appliance, access_token, version)
	
	return backup_list ["items"]

# REST API Python wrapper to create backup on appliance
def appresponse_backup_create(appliance, access_token, version):

	# Kick off backup and give time to process
	payload = {"description": "Automated Backup"}

	backup_in_process = appresponse_rest_api ("POST", "/api/npm.backup/1.0/backups", appliance, access_token, version, payload)

	# If backup creation failed, return upstream showing the failure
	if (backup_in_process == None):
		return None, None

	# Get backup id and sleep so there's time for backup to initially create
	backup_id = backup_in_process ["id"]
	time.sleep (5)

	# Keep checking if backup has completed
	backup_complete = False
	while (backup_complete == False):
		backups = appresponse_backups_list(appliance, access_token, version)

		found = False
		for backup in backups:
			if (backup ["id"] == backup_id):
				found = True
				if (backup ["status"] == "completed"):
					backup_complete = True

		# If backup "id" is not found on appliance
		if (found == False):
			print ("Error starting backup on %s" % appliance)
			return None, None
		elif (backup_complete == False):
			time.sleep (2)

	return backup_id, backup

def appresponse_backup_delete (appliance, access_token, version, backup):

	try:
		result = appresponse_rest_api("DELETE", "/api/npm.backup/1.0/backups/items/" + str(backup['id']), appliance, access_token, version)
	except:
		result = None   

	return result

# REST API Python wrapper to download and store automated backup
def appresponse_backup_download_and_store (appliance, access_token, version, backup, path=None):
	backup_file = appresponse_rest_api ("GET", "/api/npm.backup/1.0/backups/items/" + backup['id'] + "/file", appliance, access_token, version)
	
	if (backup_file != None):
		# Create folders and filenames for store
		backup_time_str = "Unknown"
		if 'backup_time' in backup:
			backup_timestamp = backup['backup_time']
			dt = datetime.fromtimestamp(backup_timestamp)
			backup_time_str = dt.strftime("%Y%m%d%I%M%S")

		backup_filename = appliance + '.' + backup_time_str + ".backup.tgz"
		if path != None:
			try:
				if not os.path.exists(path):
					os.mkdir(path)
			except:
				print("WARNING")
				print("Path provided does not exist and could not be created.")
				print("Defaulting to local folder.")
				path = None

			if path != None:
				# Likely need to ensure that path ends with appropriate path separator character at this point
				backup_filename = path + backup_filename

		try:
			with open(backup_filename, "wb") as backup_f:
				backup_f.write (backup_file)
			return backup_filename
		except:
			return None
	else:
		return None
	

# REST API Python wrapper to download and delete automated backup
def appresponse_backup_download_and_delete (appliance, access_token, version, backup, path, delete_after_download=True):

	backup_filename = appresponse_backup_download_and_store(appliance, access_token, version, backup, path)

	if delete_after_download == None or delete_after_download == True:
		delete_status = appresponse_backup_delete(appliance, access_token, version, backup)

	return delete_status, backup_filename

# REST API Python wrapper to create and pull backup from appliance
def appresponse_backup_get (appliance, access_token, version, path, delete_after_download=True):
	backup_id, backup = appresponse_backup_create (appliance, access_token, version)

	if (backup_id != None):
		empty_result,filename = appresponse_backup_download_and_delete (appliance, access_token, version, backup, path, delete_after_download)
		return True,filename
	else:
		return False,filename

def appresponse_backup_upload (appliance, access_token, version, backup_file):
	data = backup_file.read ()

	backup = appresponse_rest_api ("POST", "/api/npm.backup/1.0/backups/upload", appliance, access_token, version, additional_headers={'Content-Type': 'application/octet-stream'}, data=data)

	return backup

def appresponse_backup_restore (appliance, access_token, version, id):
	backup_restore_status = appresponse_rest_api("POST", "/api/npm.backup/1.0/backups/items/" + id + "/restore", appliance, access_token, version)

	return backup_restore_status

def appresponse_backup_restore_status (appliance, access_token, version):
	backup_restore_status = appresponse_rest_api("GET", "/api/npm.backup/1.0/restore_status", appliance, access_token, version)

	return backup_restore_status

def appresponse_backup_space_create (hostname, access_token, version, delete_options, store_options):

	# Set backup options related to locally storing and/or deleting existing backups; verify that they make sense
	download_and_store_existing_backups = store_options['download_and_store_existing_backups']

	delete_all_existing_backups_on_appliance = delete_options['delete_all_existing_backups_on_appliance']
	delete_oldest_backup = delete_options['delete_oldest_backup']
	do_not_delete_existing_backups = delete_options['do_not_delete_existing_backups']
	if do_not_delete_existing_backups == True and (delete_all_existing_backups_on_appliance == True or delete_oldest_backup == True):
		print("WARNING")
		print("Configuration file has conflicting settings, and is set to not delete any backups from appliance(s) and configured with deletion options.")
		print("Resulting configuration will not delete any files.")
		print("Please correct configuration file for subsequent runs.")
		delete_all_existing_backups_on_appliance = delete_oldest_backup = False
	elif delete_all_existing_backups_on_appliance == True and delete_oldest_backup == True:
		print("WARNING")
		print("Configuration file is set to delete all backups and oldest backups. Resulting configuration will delete only oldest files from appliance(s).")
		print("Please correct configuration file for subsequent runs.")
		delete_all_existing_backups_on_appliance = False

	print("Checking backup space availability on AppResponse %s." % hostname)

	# Check the current list of primary AppResponse backups (list_backups)
	backups_list = appresponse_backups_list (hostname, access_token, version)

	# If there are two, delete oldest as only allowed to store two at a time on the AppResponse appliance (delete_backup)
	if len(backups_list) > 0:

		if download_and_store_existing_backups == True:
			for backup in backups_list:
				filename = appresponse_backup_download_and_store(hostname, access_token, version, backup, store_options['path'])
				print("Downloaded %s from %s to store locally." % (filename, hostname))

		if delete_all_existing_backups_on_appliance == True:
			for backup in backups_list:
				delete_status = appresponse_backup_delete(hostname, access_token, version, backup)
				if delete_status != None and delete_status != "":
					print(delete_status)
					print("Deletion of backup %s from hostname %s failed." % (str(backup['id']), hostname))
					return False
		else:
			if delete_oldest_backup == True:
				if len(backups_list) == 2:	
					if do_not_delete_existing_backups == True:
						print("AppResponse %s has no available space and flag is set to not delete on-AppResponse backups." % hostname)
						return False
					else:
						# Get ID of oldest backup
						timestamp_0 = backups_list[0]['backup_time']
						timestamp_1 = backups_list[1]['backup_time']
						if timestamp_0 < timestamp_1:
							backup_to_delete = backups_list[0]
						else:
							backup_to_delete = backups_list[1]

						print("Deleting oldest backup to create available space on AppResponse %s." % hostname)
						delete_status = appresponse_backup_delete(hostname, access_token, version, backup_to_delete)
						if delete_status != None and delete_status != "":
							print(delete_status)
							return False

	return True

def appresponse_backup_clean_locally (store_options):

	if store_options['number_of_archived_backups'] != None:
		num_backups_to_keep = store_options['number_of_archived_backups']
		if not isinstance(num_backups_to_keep, int):
			print("WARNING")
			print("Configuration file has an invalid setting for the number of archived backups")
			print("Setting is %s." % str(num_backups_to_keep))
			return False
	else:
		num_backups_to_keep = 0

	# Get the list of backups and break them out into a list per appliance
	backups_list = []
	appliances_dict = {}
	if 'path' in store_options:
		backups_list = glob.glob(store_options['path'] + "*.backup.tgz")
		for backup in backups_list:
			hostname = backup.rsplit('.',3)[0]
			if hostname not in appliances_dict:
				appliances_dict[hostname] = []
			appliances_dict[hostname].append(backup)

	# Iterate over appliances and remove oldest
	cleanup_succeeded = True
	for appliance in appliances_dict:
		appliance_backups_list = appliances_dict[appliance]
		oldest_timestamp = None
		oldest_backup = None

		while len(appliance_backups_list) > num_backups_to_keep:
			for backup in appliance_backups_list:
				backup_timestamp = int(backup.rsplit('.', 3)[1]) 
				if oldest_timestamp == None or oldest_timestamp > backup_timestamp:
					oldest_timestamp = backup_timestamp
					oldest_backup = backup

			try:
				print("Removing backup %s." % oldest_backup)
				appliance_backups_list.remove(oldest_backup)
				os.remove (oldest_backup)
				oldest_timestamp = None
				oldest_backup = None
			except:
				print("WARNING")
				print("Exception while removing backup %s from local disk" % oldest_backup)
				cleanup_succeeded = False
	
	return cleanup_succeeded

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

# REST API Python wrapper to request version information
# URL: https://<appliance>/api/common/1.0/info
# Header: AUthorization: Bearer <access_token>
def appresponse_version_get (appliance, access_token, version):
	url = "https://" + appliance + "/api/common/1.0/info"
	
	r = requests.get (url, verify=False)

	result = json.loads(r.content)

	version_str = result["sw_version"]
	
	return version_str

def appresponse_authentication_check(hostname, username, password):
	
	# Login to source and destination AppResponses to confirm the passwords are correct before proceeding
	version = appresponse_version_get(hostname, username, password)
	access_token = appresponse_authenticate(hostname, username, password, version)

	return access_token, version


##### HELPER FUNCTIONS #####
# Helper function to get list of hostnames from input
def hostnamelist_get (hostnamelist):
	hostnamelist_f = open (hostnamelist, 'r')

	output = []
	for row in hostnamelist_f:
		hostname = row.rstrip()
		output.append (hostname)

	hostnamelist_f.close ()

	return output

def backup_credentials_get (filename):

	credentials = yamlread (filename)	
	
	hostname = None
	if 'hostname' in credentials:
		hostname = credentials['hostname'] 

	hostname_list = None
	if 'list' in credentials:
		list = credentials['list']
							
	username = None
	if 'username' in credentials:
		username = credentials['username'] 

	# Allow for testing, but the expectation is that this is not included in YAML
	password = None
	if 'password' in credentials:
		password = credentials['password']

	# Include options to handle what to do with existing backups and how to store locally
	delete_options = None
	if 'delete_options' in credentials:
		delete_options = credentials['delete_options']
	store_options = None
	if 'store_options' in credentials:
		store_options = credentials['store_options']

	try:
		hostnamelist = hostnamelist_get(list)
	except:
		print("Failed to read file %s to load list of hostnames specified by parameter --hostnamelist." % list)
		hostnamelist = None

	return hostname, hostnamelist, username, password, delete_options, store_options

def backup_restore_credentials_get (filename):

	credentials = yamlread (filename)	
	
	src_hostname = None
	if 'src_hostname' in credentials:
		src_hostname = credentials['src_hostname'] 
	src_username = None
	if 'src_username' in credentials:
		src_username = credentials['src_username'] 
	dst_hostname = None
	if 'dst_hostname' in credentials:
		dst_hostname = credentials['dst_hostname'] 
	dst_username = None
	if 'dst_username' in credentials:
		dst_username = credentials['dst_username'] 

	# Allow for testing, but the expectation is that this is not included in YAML
	src_password = None
	if 'src_password' in credentials:
		src_password = credentials['src_password']
	dst_password = None
	if 'dst_password' in credentials:
		dst_password = credentials['dst_password']

	# Include options to handle what to do with existing backups and how to store locally
	delete_options = None
	if 'delete_options' in credentials:
		delete_options = credentials['delete_options']
	store_options = None
	if 'store_options' in credentials:
		store_options = credentials['store_options']

	return src_hostname, src_username, src_password, dst_hostname, dst_username, dst_password, delete_options, store_optio
	

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
				print ("Please specify an ID for the filename on the appliance that you would like to delete in --actionfile parameter")
			else:
				backup_to_delete = None
				backups_list = appresponse_backups_list (hostname, access_token, version)
				for backup in backups_list:
					if actionfile == backup['id']:
						backup_to_delete = backup
						break

			backup = appresponse_backup_delete (hostname, access_token, version, backup_to_delete)

		# ACTION - upload_backup
		elif (action == "upload_backup"):
			if (actionfile == None or actionfile == ""):
				print ("Please specify a filename for backup upload in --actionfile parameter")
		
			backup = None
			with open(actionfile, 'rb') as backup_file:
				backup = appresponse_backup_upload (hostname, access_token, version, backup_file)

			print (backup)

	return

def backup_from_yaml(config):
	print("------------------------------------------------------------------------")
	print("")
	print("Step 1 of 3: Confirming accounts and pre-requisites ...")
	print("")

	hostname, hostnamelist, username, password, delete_options, store_options = backup_credentials_get(config)

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
			access_token, version = appresponse_authentication_check(hostname, username, password)
			 
		except:
			access_token = None

		if access_token == None:
			print("WARNING")
			print("Authentication failed to AppResponse %s. Removing from backup list ..." % hostname)
		else:
			hostnames_to_backup.append({"hostname":hostname,"access_token":access_token,"version":version})

	num_backups_to_take = len(hostnames_to_backup)
	print("Backing up %d of the %d specified AppResponse appliances." % (num_backups_to_take, num_hostnames))

	print("")
	print("Step 2 of 3: Taking backups from %d AppResponse appliances" % num_backups_to_take)
	print("")

	backup_in_progress = 1
	backup_success = 0
	for appliance in hostnames_to_backup:
		hostname = appliance['hostname']
		access_token = appliance['access_token']
		version = appliance['version'] 
		print("Starting backup %d of %d ..." % (backup_in_progress, num_backups_to_take))

		status = appresponse_backup_space_create (hostname, access_token, version, delete_options, store_options)

		# Create, download, and delete a backup of the AppResponse at a current time (pull_backup)
		backup_status,backup_filename = appresponse_backup_get(hostname, access_token, version, store_options['path'], delete_options['delete_automated_backup'])
		if backup_status == False:
			print("AppResponse %s backup failed. Continuing to next appliance ..." % hostname)
			backup_in_progress+=1
			continue
		else:
			backup_success+=1
			print("Backup file %s created and downloaded for AppResponse %s" % (backup_filename, hostname))

		backup_in_progress+=1
		
	print("")
	print("Step 3 of 3: Cleaning up after script execution.")
	print("")

	cleanup_status = appresponse_backup_clean_locally(store_options)
	if cleanup_status == False:
		print("Cleanup failed. Terminating script ...")
		return

	print("Backup from %d of %d configured AppResponse appliances has been completed. %d%% success!" % (backup_success, num_hostnames, int(backup_success/num_hostnames * 100)))
	print("")
	print("------------------------------------------------------------------------")

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
	parser.add_argument('--backupfromconfig', help="Run full workflow from YAML config")
	args = parser.parse_args()

	if args.backupfromconfig != None:
		backup_from_yaml(args.backupfromconfig)
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
