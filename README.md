# appresponse_utilities

Currently, a set of utilities for AppResponse backup. There are two ways to execute the utilities, either by running individual actions, or performing a set of backups from a set of configurations.

<b>Backup</b>

python appresponse_utilities.py --fromconfig config.yaml

<b>Actions</b>

<b>List backups</b>

python appresponse_utilities.py --hostname <hostname> --username admin --action list_backups

Note, only two backups are permitted on AppResponse at one time. If two exist, one backup file needs to be deleted (using the ID), if there are already two existing and you want to pull (create) or upload a backup file.

<b>Delete backup</b>

  python appresponse_utilities.py --hostname <hostname> --username admin --action delete_backup --actionfile <ID_of_backup_file_on_appliance>

<b>Create, download and delete backup</b>

  python appresponse_utilities.py --hostname <hostname> --username admin --action pull_backup
