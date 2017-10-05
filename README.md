# cisecurity

#### Table of Contents

1. [Module Description](#description)
2. [Setup - The basics of getting started with cisecurity](#setup)
    * [What cisecurity affects](#what-cisecurity-affects)
    * [Beginning with cisecurity](#beginning-with-cisecurity)
3. [Usage - Configuration options and additional functionality](#usage)
4. [Reference - An under-the-hood peek at what the module is doing and how](#reference)
5. [Limitations - OS compatibility, etc.](#limitations)
6. [Development - Guide for contributing to the module](#development)

## Module Description

This module configures and maintains controls listed in the Center for Internet Security Benchmark for Linux.  The current version of cisecurity implements v2.11 of the benchmark and provides a lot of dials and knobs to fine-tune the module to your specific needs.

More information about the benchmark and downloading a copy of it for yourself is available at the [Center for Internet Security](http://www.cisecurity.org).

## Setup

### What cisecurity affects

By default, this module implements all Level 1 and Level 2 controls and uses the defaults provided in the benchmark.  Make sure to consult the module's documentation for default settings and alter as necessary.  **The defaults should not be intended as a one-size-fits-all solution.**

cisecurity touches a wide variety of system-level settings including:

* Filesystem owners, groups, and permissions
* modprobe-enabled filesystems
* Mount point configurations
* Network subsystem
* Addition/removal of packages
* Package configurations
* PAM
* SELinux
* Grub
* User Accounts
### Beginning with cisecurity

To use the cisecurity module with default parameters, declare the cisecurity class.

```puppet
include cisecurity
```

## Usage

All parameters for the `cisecurity` module are broken down into various classes based on the components being modified.

## Reference

### Classes

* `cisecurity::filesystem`: Handles the filesystem controls.
* `cisecurity::network`: Handles the network controls.
* `cisecurity::packages`: Handles the package and yum controls.
* `cisecurity::pam`: Handles the PAM controls.
* `cisecurity::security`: Handles Grub, SELinux, and other miscellaneous controls.
* `cisecurity::services`: Handles the network controls.

### Parameters

If you modify an `Enum['enabled','disabled']` parameter to something other than the default, the module will not autocorrect the desired state of the system.  You will need to go to that system and manually change the configuration to whatever you want it to be.  cisecurity is designed to only enforce the controls in the benchmark and will not make assumptions of what you want a system's configuration to look like when you deviate.

**Exception:** For parameters in the `cisecurity::services` class, if you modify an `Enum['installed','uninstalled']` parameter, the module will honor the setting and attempt to start/stop and enable/disable the specified package.

For parameters in the `cisecurity::packages` class, if you modify an `Enum['installed','uninstalled']` parameter, the module will attempt to install or purge the specified package.

#### Class cisecurity::filesystem

##### `configure_umask_default`
* Default value: `'enabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 5.4.4
* Related: `umask_default`

Determines if the default umask will be modified.

##### `cramfs`
* Default value: `'disabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 1.1.1.1

Determines if mounting cramfs filesystems will be allowed.

##### `dev_shm_mount_options`
* Default value: `[ 'noexec', 'nodev', 'nosuid' ]`
* Data type: `Array[String]`
* Implements: Control 1.1.15

Provides mount options for /dev/shm.  Set this parameter to an empty array if you don't want the module to modify /dev/shm.

##### `freevxfs`
* Default value: `'disabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 1.1.1.2

Determines if mounting freevxfs filesystems will be allowed.

##### `harden_system_file_perms`
* Default value: `'enabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Controls 5.1.2 - 5.1.8, 5.2.1, 6.1.2 - 6.1.9

Secures certain system files and directories harder than the default operating system provides.

##### `hfs`
* Default value: `'disabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 1.1.1.4

Determines if mounting hfs filesystems will be allowed.

##### `hfsplus`
* Default value: `'disabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 1.1.1.5

Determines if mounting hfsplus filesystems will be allowed.

##### `home_mount_options`
* Default value: `[ 'nodev' ]`
* Data type: `Array[String]`
* Implements: Controls 1.1.13 - 1.1.14

Provides mount options for /home.  If /home is not configured as a separate partition, the module will throw a warning.  Set this parameter to an empty array if you don't want the module to modify /home.

##### `jffs2`
* Default value: `'disabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 1.1.1.3

Determines if mounting hfs filesystems will be allowed.

##### `remediate_log_file_perms`
* Default value: `'enabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 4.2.4

Secures log files in /var/log harder than the default operating system provides.

##### `remediate_ungrouped_files`
* Default value: `'enabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 6.1.12
* Related: `ungrouped_files_replacement_group`

Reassigns group ownership of ungrouped files and directories.

##### `remediate_unowned_files`
* Default value: `'enabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 6.1.11
* Related: `unowned_files_replacement_owner`

Reassigns user ownership of an unowned files and directories.

##### `remediate_world_writable_dirs`
* Default value: `'enabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 1.1.21

Adds sticky bit to all world writable directories.

##### `remediate_world_writable_files`
* Default value: `'enabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 6.1.10

Removes world writable permission from all world writable files.

##### `removable_media_mount_options`
* Default value: `[ 'noexec', 'nodev', 'nosuid' ]`
* Data type: `Array[String]`
* Implements: Controls 1.1.18 - 1.1.20
* Related: `removable_media_partitions`

Provides mount options for removable media partitions.

##### `removable_media_partitions`
* Default value: `[ ]`
* Data type: `Array[String]`
* Implements: Controls 1.1.18 - 1.1.20
* Related: `removable_media_mount_options`

Lists all removable partitions that exist on the system.  It is recommended you use set this on a node-by-node basis.

##### `squashfs`
* Default value: `'disabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 1.1.1.6

Determines if mounting squashfs filesystems will be allowed.

##### `tmp_mount_options`
* Default value: `[ 'mode=1777', 'astrictatime', 'noexec', 'nodev', 'nosuid' ]`
* Data type: `Array[String]`
* Implements: Controls 1.1.2 - 1.1.5
* Related: `removable_media_partitions`

Provides mount options for /tmp.  If /tmp is not configured as a separate partition, the module will throw a warning.  Set this parameter to an empty array if you don't want the module to modify /tmp.

##### `udf`
* Default value: `'disabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 1.1.1.7

Determines if mounting udf filesystems will be allowed.

##### `umask_default`
* Default value: `'027'`
* Data type: `String`
* Implements: Control 5.4.4
* Related: `configure_umask_default`

Value of the default umask.

##### `ungrouped_files_replacement_group`
* Default value: `'root'`
* Data type: `String`
* Implements: Control 6.1.12
* Related: `remediate_ungrouped_files`

Value of the group to assign to ungrouped files.  You may use GID or name.

##### `unowned_files_replacement_owner`
* Default value: `'root'`
* Data type: `String`
* Implements: Control 6.1.11
* Related: `remediate_unowned_files`

Value of the user to assign to unowned files.  You may use GID or name.

##### `var_mount_options`
* Default value: `[ 'defaults' ]`
* Data type: `Array[String]`
* Implements: Controls 1.1.6

Provides mount options for /var.  If /var is not configured as a separate partition, the module will throw a warning.  You really shouldn't need to modify this because the benchmark doesn't specify changes to the mount options (hence why it's set to defaults).

##### `var_log_audit_mount_options`
* Default value: `[ 'defaults' ]`
* Data type: `Array[String]`
* Implements: Controls 1.1.12

Provides mount options for /var/log/audit.  If /var/log/audit is not configured as a separate partition, the module will throw a warning.  You really shouldn't need to modify this because the benchmark doesn't specify changes to the mount options (hence why it's set to defaults).

##### `var_log_mount_options`
* Default value: `[ 'defaults' ]`
* Data type: `Array[String]`
* Implements: Controls 1.1.11

Provides mount options for /var/log.  If /var/log is not configured as a separate partition, the module will throw a warning.  You really shouldn't need to modify this because the benchmark doesn't specify changes to the mount options (hence why it's set to defaults).

##### `var_tmp_mount_options`
* Default value: `[ 'bind' ]`
* Data type: `Array[String]`
* Implements: Controls 1.1.6

Provides mount options for /var/tmp.  Set this parameter to an empty array if you don't want the module to modify /var/tmp.

##### `vfat`
* Default value: `'disabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 1.1.1.8

Determines if mounting vfat filesystems will be allowed.

#### Class cisecurity::network

##### `dccp`
* Default value: `'disabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 3.5.1

Determines if the DCCP protocol will be allowed.

##### `disable_wireless_interfaces`
* Default value: `'enabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 3.7

Determines if wireless interfaces should be disabled.

##### `hosts_allow`
* Default value: `'puppet:///modules/cisecurity/tcp_wrappers/hosts.allow'`
* Data type: `String`
* Implements: Control 3.4.2

Provides the source location for the /etc/hosts.allow file.  It is recommended you use set this on a node-by-node basis.

##### `hosts_deny`
* Default value: `'puppet:///modules/cisecurity/tcp_wrappers/hosts.deny'`
* Data type: `String`
* Implements: Control 3.4.3

Provides the source location for the /etc/hosts.deny file.  It is recommended you use set this on a node-by-node basis.

##### `ipv4_accept_icmp_redirects`
* Default value: `'disabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 3.2.2

Determines if ICMP redirect messages are allowed.

##### `ipv4_forwarding`
* Default value: `'disabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 3.1.1

Determines if forwarding (routing) is allowed.

##### `ipv4_ignore_icmp_bogus_responses`
* Default value: `'disabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 3.2.6

Determines if bogus (faked) ICMP reponse messages are allowed.

##### `ipv4_ignore_icmp_broadcasts`
* Default value: `'enabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 3.2.5

Determines if broadcast ICMP messages are allowed.

##### `ipv4_log_suspicious_packets`
* Default value: `'enabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 3.2.4

Determines if suspicious packets (martians) will be logged.

##### `ipv4_reverse_path_filtering`
* Default value: `'enabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 3.2.7

Determines if reverse path filtering of packets should happen.

##### `ipv4_secure_redirects`
* Default value: `'disabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 3.2.3

Determines if secure ICMP redirect messages are allowed.

##### `ipv4_send_redirects`
* Default value: `'disabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 3.1.2

Determines if the system can send ICMP redirect messages.

##### `ipv4_source_routing`
* Default value: `'disabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 3.2.1

Determines if source routed packets are accepted.

##### `ipv4_tcp_syncookies`
* Default value: `'enabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 3.2.8

Determines if TCP SYN cookies are allowed.

##### `ipv6`
* Default value: `'disabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 3.3.3

Determines if the IPv6 protocol stack is allowed.

##### `ipv6_accept_packet_redirects`
* Default value: `'disabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 3.3.2

Determines if IPv6 redirect messages are allowed.

##### `ipv6_accept_router_advertisements`
* Default value: `'disabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 3.3.1

Determines if IPv6 router advertisements are accepted.

##### `rds`
* Default value: `'disabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 3.5.3

Determines if the RDS protocol will be allowed.

##### `sctp`
* Default value: `'disabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 3.5.2

Determines if the SCTP protocol will be allowed.

##### `tipc`
* Default value: `'disabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 3.5.4

Determines if the TIPC protocol will be allowed.

#### Class cisecurity::packages

##### `aide`
* Default value: `'installed'`
* Data type: `Enum['installed','uninstalled']`
* Implements: Control 1.3.1

Determines if AIDE will be installed.

##### `aide_cron_start_hour`
* Default value: `'5'`
* Data type: `String`
* Implements: Control 1.3.2
* Related: `aide_cron_start_minute`

A cron-styled hour when AIDE will run its daily check.

##### `aide_cron_start_minute`
* Default value: `'0'`
* Data type: `String`
* Implements: Control 1.3.2
* Related: `aide_cron_start_hour`

A cron-styled minute when AIDE will run its daily check.

##### `firewalld`
* Default value: `'installed'`
* Data type: `Enum['installed','uninstalled']`
* Implements: Control 3.6.1

Determines if firewalld will be installed.

##### `logrotate`
* Default value: `'installed'`
* Data type: `Enum['installed','uninstalled']`
* Implements: Control 4.3

Determines if logrotate will be installed.

##### `mcstrans`
* Default value: `'uninstalled'`
* Data type: `Enum['installed','uninstalled']`
* Implements: Control 1.6.1.5

Determines if the MCS Translation Service will be installed.

##### `openldap_clients`
* Default value: `'uninstalled'`
* Data type: `Enum['installed','uninstalled']`
* Implements: Control 2.3.5

Determines if the LDAP client will be installed.

##### `prelink`
* Default value: `'uninstalled'`
* Data type: `Enum['installed','uninstalled']`
* Implements: Control 3.6.1

Determines if prelink will be installed.

##### `rsh`
* Default value: `'uninstalled'`
* Data type: `Enum['installed','uninstalled']`
* Implements: Control 2.2.17

Determines if the rsh server will be installed.

##### `setroubleshoot`
* Default value: `'uninstalled'`
* Data type: `Enum['installed','uninstalled']`
* Implements: Control 1.6.1.4

Determines if setroubleshoot will be installed.

##### `talk`
* Default value: `'uninstalled'`
* Data type: `Enum['installed','uninstalled']`
* Implements: Control 2.2.18

Determines if talk will be installed.

##### `tcp_wrappers`
* Default value: `'uninstalled'`
* Data type: `Enum['installed','uninstalled']`
* Implements: Control 3.4.1

Determines if the TCP Wrappers will be installed.

##### `telnet`
* Default value: `'uninstalled'`
* Data type: `Enum['installed','uninstalled']`
* Implements: Control 2.3.4

Determines if the telnet client will be installed.

##### `x11_org`
* Default value: `'uninstalled'`
* Data type: `Enum['installed','uninstalled']`
* Implements: Control 2.2.2

Determines if X Windows will be installed.

##### `ypbind`
* Default value: `'uninstalled'`
* Data type: `Enum['installed','uninstalled']`
* Implements: Control 2.3.1

Determines if the NIS Client will be installed.

##### `yum_auto_update`
* Default value: `'installed'`
* Data type: `Enum['installed','uninstalled']`
* Implements: Control 1.8
* Related: `yum_auto_update_action`, `yum_auto_update_email_from`, `yum_auto_update_email_to`, `yum_auto_update_exclude`, `yum_auto_update_notify_email`, `yum_auto_update_update_cmd`

Determines if yum-cron will be installed and configured.

##### `yum_auto_update_action`
* Default value: `'apply'`
* Data type: `Enum['check','download','apply']`
* Implements: Control 1.8
* Related: `yum_auto_update`

Determines how to deal with updates for the system.
  * `check` detects the presence of updates but takes no further action.
  * `download` downloads the files and packages necessary to perform the update and takes no further action.
  * `apply` downloads and installs the updates automatically.

##### `yum_update_email_from`
* Default value: `'root'`
* Data type: `String`
* Implements: Control 1.8
* Related: `yum_auto_update`, `yum_auto_update_notify_email`

If email notifications are enabled, this parameter defines the sender's email address.  The parameter may be a local user (as in the case with root as the default) or a fully-qualified email address (someone@somewhere.com).

##### `yum_update_email_to`
* Default value: `'root'`
* Data type: `String`
* Implements: Control 1.8
* Related: `yum_auto_update`, `yum_auto_update_notify_email`

If email notifications are enabled, this parameter defines who to send the notifications to.  The parameter may be a local user (as in the case with root as the default) or a fully-qualified email address (someone@somewhere.com).

##### `yum_auto_update_exclude`
* Default value: `[ ]`
* Data type: `Array[String]`
* Implements: Control 1.8
* Related: `yum_auto_update`

An array of packages to exclude when applying updates.

##### `yum_auto_update_notify_email`
* Default value: `true`
* Data type: `Boolean`
* Implements: Control 1.8
* Related: `yum_auto_update`, `yum_auto_update_email_from`, `yum_auto_update_email_to`

Determines whether notifications are to be sent via email.

##### `yum_auto_update_update_cmd`
* Default value: `'default'`
* Data type: `Enum['default','security','security-severity:Critical','minimal','minimal-security','minimal-security-severity:Critical']`
* Implements: Control 1.8
* Related: `yum_auto_update`

Defines what category of updates you wish applied.
  * `default` provides updates all installed packages.
  * `security` provides updates with security fixes only.
  * `security-severity:Critical` provides only critical security fixes.
  * `minimal` provides updates for bugfixes.
  * `minimal-security`provides updates to packages with security errata.
  * `minimal-security-severity:Critical` provides only critical security fixes for packages with security errata.

##### `yum_repo_enforce_gpgcheck`
* Default value: `'enabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 1.2.2

Determines whether to enforce `gpgcheck` on all available repositories.

#### Class cisecurity::security

##### `aslr`
* Default value: `'enabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 1.5.3

Determines whether Address Space Layout Randomization (ASLR) will be enabled.

##### `banner_message_text`
* Default value: `'Authorized uses only. All activity may be monitored and reported.'`
* Data type: `String`
* Implements: Control 1.7.2
* Related: `x_windows`

Banner message text to be displayed when a GNOME-based graphical login occurs.

##### `bootloader_password`
* Default value: Grub encrypted password
* Data type: `String`
* Implements: Control 1.4.2

An Grub SHA512 encrypted password string used as the bootloader password.  The encrypted password in `Redhat7.yaml` is `password`.  To change the bootloader password, use `grub2-mkpasswd-pbkdf2` as shown below:
```
$ grub2-mkpasswd-pbkdf2
Enter password: <new password>
Reenter password: <confirm new password>
PBKDF2 hash of your password is grub.pbkdf2.sha512.10000.D70F1...
```
Copy and paste the entire string into the parameter.

##### `configure_system_acct_nologin`
* Default value: `'enabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 5.4.2

Determines whether system accounts (UIDs less than 1000 by default) have their shell changed to `/sbin/nologin` in `/etc/passwd`.

##### `home_directories_perm`
* Default value: `'0750'`
* Data type: `String`
* Implements: Control 6.2.8 - 6.2.9
* Related: `remediate_home_directories`

Defines what permission should be applied to home directories.

##### `issue`
* Default value: `'puppet:///modules/cisecurity/banners/issue'`
* Data type: `String`
* Implements: Controls 1.7.1.2 and 1.7.1.5

Provides the source location for `/etc/issue` and sets owner, group, and permission.

##### `issue_net`
* Default value: `'puppet:///modules/cisecurity/banners/issue.net'`
* Data type: `String`
* Implements: Controls 1.7.1.3 and 1.7.1.6

Provides the source location for `/etc/issue.net` and sets owner, group, and permission.

##### `motd`
* Default value: `'puppet:///modules/cisecurity/banners/motd'`
* Data type: `String`
* Implements: Controls 1.7.1.1 and 1.7.1.4

Provides the source location for `/etc/motd` and sets owner, group, and permission.

##### `remediate_blank_passwords`
* Default value: `'enabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 6.2.1

Determines whether accounts with blank passwords will be locked out.

##### `remediate_home_directories_dot_files`
* Default value: `'enabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: 6.2.10

Removes group and other write permissions to users' dot files.

##### `remediate_home_directories_exist`
* Default value: `'enabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: 6.2.7

Creates users' home directories if they don't exist whether they've logged into the system or not.

##### `remediate_home_directories_forward_files`
* Default value: `'enabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: 6.2.11

Determines whether `.forward` files in home directories are forcibly removed.

##### `remediate_home_directories_netrc_files`
* Default value: `'enabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: 6.2.12

Determines whether `.netrc` files in home directories are forcibly removed.

##### `remediate_home_directories_netrc_files_perms`
* Default value: `'enabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: 6.2.13

Removes group and other write permissions to users' `.netrc` files.

##### `remediate_home_directories_owner`
* Default value: `'enabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: 6.2.9

Changes the ownership of home directories when the directory isn't owned by the correct user.

##### `remediate_home_directories_perms`
* Default value: `'enabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: 6.2.8

Changes the permissions of home directories.

##### `remediate_home_directories_rhosts_files`
* Default value: `'enabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: 6.2.14

Determines whether `.rhosts` files in home directories are forcibly removed.

##### `remediate_home_directories_start_hour`
* Default value: `'5'`
* Data type: `String`
* Implements: Controls 6.2.7 - 6.2.19

A cron-styled hour when home directory checks will run.

##### `remediate_home_directories_start_minute`
* Default value: `'0'`
* Data type: `String`
* Implements: Controls 6.2.7 - 6.2.19

A cron-styled minute when home directory checks will run.

##### `remediate_legacy_group_entries`
* Default value: `'enabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 6.2.4

Determines whether legacy entries in `/etc/group` exist.

##### `remediate_legacy_passwd_entries`
* Default value: `'enabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 6.2.2

Determines whether legacy entries in `/etc/passwd` exist.

##### `remediate_legacy_shadow_entries`
* Default value: `'enabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 6.2.3

Determines whether legacy entries in `/etc/shadow` exist.

##### `remediate_root_path`
* Default value: `'enabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 6.2.6
* Related: `root_path`

Determines whether root's path will be managed.  Besides configuring root's path in `/root/.bash_profile`, the module will go through each directory in the path and ensure the directory is owned by root, group owned by root, and removes group and other write attributes.

##### `remediate_uid_zero_accounts`
* Default value: `'enabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 6.2.5

Determines whether accounts with UID 0 (other than root) will be deleted.

##### `restricted_core_dumps`
* Default value: `'enabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 1.5.1

Determines whether core dumps are allowed.

##### `root_path`
* Default value: `'[ '$PATH', '$HOME/bin' ]`
* Data type: `Array[String]`
* Implements: Control 6.2.6
* Related: `remediate_root_path`

The path that will be configured in `/root/.bash_profile`.

##### `single_user_authentication`
* Default value: `'enabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 1.4.3

Determines whether authentication will be required when the system runs in single-user mode.

##### `selinux`
* Default value: `'enforcing'`
* Data type: `Enum['enforcing','permissive','disabled']`
* Implements: Controls 1.6.1.1, 1.6.1.2, 1.6.2

Determines how SELinux will be configured.

##### `selinux_type`
* Default value: `'targeted'`
* Data type: `Enum['targeted','minimum','mls']`
* Implements: Control 1.6.1.3

Determines how SELinux will be configured.

##### `secure_terminals`
* Default value: `[ 'console' ] `
* Data type: `Array[String]`
* Implements: Control 5.5

Provides a list of devices where root is permitted to directly log in.

##### `syslog_facility`
* Default value: `'auth'`
* Data type: `String`
* Implements: Controls 6.2.15 - 6.2.19

Provides the syslog facility that warning messages will be logged to.

##### `syslog_severity`
* Default value: `'warn'`
* Data type: `String`
* Implements: Controls 6.2.15 - 6.2.19

Provides the syslog severity that warning messages will be logged to.

##### `verify_user_groups_exist`
* Default value: `'enabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Controls 6.2.15

Verifies all groups in /etc/passwd exist in /etc/group.  If a group doesn't exist, a message is written via syslog.

##### `verify_duplicate_gids_notexist`
* Default value: `'enabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Controls 6.2.17

Verifies no duplicate GIDs exist.  If a duplicate GID is found, a message is written via syslog.

##### `verify_duplicate_groupnames_notexist`
* Default value: `'enabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Controls 6.2.19

Verifies no duplicate group names exist.  If a duplicate group name is found, a message is written via syslog.

##### `verify_duplicate_uids_notexist`
* Default value: `'enabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Controls 6.2.16

Verifies no duplicate UIDs exist.  If a duplicate UID is found, a message is written via syslog.

##### `verify_duplicate_usernames_notexist`
* Default value: `'enabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Controls 6.2.18

Verifies no duplicate usernames exist.  If a duplicate username is found, a message is written via syslog.

#### Class cisecurity::services

##### `auditd_action_mail_root`
* Default value: `'root'`
* Data type: `String`
* Implements: Control 4.1.1.2
* Related: `configure_auditd`

If email notifications are enabled, this parameter defines who receives the notification.  The parameter may be a local user (as in the case with root as the default) or a fully-qualified email address (someone@somewhere.com).

##### `auditd_space_left_action`
* Default value: `'halt'`
* Data type: `Enum['email','exec','halt','ignore','rotate','single','suspend','syslog']`
* Implements: Control 4.1.1.2
* Related: `configure_auditd`

Determines what action to take when the system detects it's starting to get low on disk space.

##### `auditd_configure_rules`
* Default value: `'enabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Controls 4.1.4 - 4.1.18
* Related: `configure_auditd`

Determines whether the rules defined in the benchmark are applied.

##### `auditd_max_log_file`
* Default value: `8`
* Data type: `Integer`
* Implements: Control 4.1.1.1
* Related: `configure_auditd`

Specifies the maximum size of an audit log file in megabytes.

##### `auditd_max_log_file_action`
* Default value: `'keep_logs'`
* Data type: `Enum['keep_logs','ignore','rotate','suspend','syslog']`
* Implements: Control 4.1.1.3
* Related: `configure_auditd`

Specifies what action will be taken when the system detects the maximum log file size has been reached.

##### `auditd_space_left_action`
* Default value: `'email'`
* Data type: `Enum['email','exec','halt','ignore','rotate','single','suspend','syslog']`
* Implements: Control 4.1.1.2
* Related: `configure_auditd`

Specifies what action will be taken when the system detects that it's starting to get low on disk space.

##### `configure_boot_auditing`
* Default value: `'enabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 4.1.3

Determines if process auditing will happen prior to auditd is enabled.

##### `autofs`
* Default value: `'disabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 1.1.22

Enables or disables the automounter.

##### `avahi_daemon`
* Default value: `'disabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 2.2.3

Enables or disables Avahi.

##### `chargen_dgram`
* Default value: `'disabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 2.1.1
* Related: `inetd`

Enables or disables chargen services.

##### `chargen_stream`
* Default value: `'disabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 2.1.1
* Related: `inetd`

Enables or disables chargen services.

##### `configure_auditd`
* Default value: `'enabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Controls 4.1.1.1 - 4.1.2
* Related: `auditd_action_mail_acct`, `auditd_admin_space_left_action`, `auditd_configure_rules`, `auditd_max_log_file`, `auditd_max_log_file_action`, `audit_space_left_action`

Determines whether the auditing subsystem will be configured.

##### `configure_postfix`
* Default value: `'enabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 2.2.15

Determines whether postfix will be configured to only listen on localhost interfaces.

##### `configure_rsyslog`
* Default value: `'enabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 4.2.1
* Related: `rsyslog_conf`, `rsyslog_remote_servers`

Determines whether rsyslog will be configured.

##### `configure_sshd`
* Default value: `'enabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Controls 5.2.1 - 5.2.16
* Related: `sshd_banner_file`, `sshd_client_alive_count_max`, `sshd_client_alive_interval`, `sshd_hostbased_authentication`, `sshd_ignore_rhosts`, `sshd_login_grace_time`, `sshd_log_level`, `sshd_max_auth_tries`, `sshd_permit_empty_passwords`, `sshd_permit_root_login`, `sshd_permitted_ciphers`, `sshd_permitted_macs`, `sshd_permit_user_environment`, `sshd_protocol`, `sshd_x11_forwarding`

Determines whether sshd will be configured.

##### `configure_time`
* Default value: `'enabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Controls 2.2.1.1 - 2.2.1.3
* Related: `time_server_provider`, `time_service_servers`

Determines whether time services (ntpd or chrony) will be configured.

##### `cron`
* Default value: `'enabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 2.1.1

Enables or disables cron.

##### `cups`
* Default value: `'disabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 2.2.4

Enables or disables the printing subsystem.

##### `daytime_dgram`
* Default value: `'disabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 2.1.2
* Related: `inetd`

Enables or disables daytime services.

##### `daytime_stream`
* Default value: `'enabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 2.1.2
* Related: `inetd`

Enables or disables daytime services.

##### `dhcpd`
* Default value: `'disabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 2.2.5

Enables or disables DHCP services.

##### `discard_dgram`
* Default value: `'disabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 2.1.3
* Related: `inetd`

Enables or disables discard services.

##### `inetd`
* Default value: `'disabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 2.1.3
* Related: `discard_dgram`

Enables or disables discard services.

##### `dovecot`
* Default value: `'disabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 2.2.11

Enables or disables POP3/IMAP services.

##### `echo_dgram`
* Default value: `'disabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 2.1.4
* Related: `inetd`

Enables or disables echo services.

##### `echo_stream`
* Default value: `'disabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 2.1.4
* Related: `inetd`

Enables or disables echo services.

##### `httpd`
* Default value: `'disabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 2.2.10

Enables or disables web services.

##### `inetd`
* Default value: `'disabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 2.1.7
* Related: `chargen_dgram`, `chargen_stream`, `daytime_dgram`, `daytime_stream`, `discard_dgram`, `discard_stream`, `echo_dgram`, `echo_stream`, `time_dgram`, `time_stream`, `tftp_server`

Enables or disables the (x)inetd super server.

##### `named`
* Default value: `'disabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 2.2.8

Enables or disables DNS services.

##### `nfs`
* Default value: `'disabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 2.2.7
* Related: `rpcbind`

Enables or disables NFS services.

##### `ntalk`
* Default value: `'disabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 2.2.18

Enables or disables talk services.

##### `ntp_service_restrictions`
* Default value: `'[ '-4 default kod nomodify notrap nopeer noquery', '-6 default kod nomodify notrap nopeer noquery', '127.0.0.1', '-6 ::1' ]`
* Data type: `Array[String]`
* Implements: Control 2.2.1.2
* Related: `configure_time`

Configures NTP restrict statements.

##### `rexec`
* Default value: `'disabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 2.2.17

Enables or disables rexec services.

##### `rhnsd`
* Default value: `'disabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 1.2.5

Enables or disables Red Hat Network Services.

##### `rlogin`
* Default value: `'disabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 2.2.17

Enables or disables rlogin services.

##### `rpcbind`
* Default value: `'disabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 2.2.7
* Related: `nfs`

Enables or disables RPC portmapper service.

##### `rsh`
* Default value: `'disabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 2.2.17

Enables or disables rsh services.

##### `rsyncd`
* Default value: `'disabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 2.2.21

Enables or disables rsync services.

##### `rsyslog_conf`
* Default value: `'puppet:///modules/cisecurity/rsyslog/rsyslog.conf'`
* Data type: `String`
* Implements: Control 4.2.1.2
* Related: `configure_rsyslog`

Provides the source location for the /etc/rsyslog.conf file.  It is recommended you reconfigure this setting to some kind of master file to be distributed to all nodes or devise another mechanism to ensure log settings are properly configured.

##### `rsyslog_remote_servers`
* Default value: `[ { 'host' => 'log.domain.com', 'port' => 514 } ]`
* Data type: `Array[Hash[String, Integer]]`
* Implements: Control 4.2.1.4

Configures what loghosts to send syslog messages to.

##### `slapd`
* Default value: `'disabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 2.2.6

Enables or disables LDAP services.

##### `smb`
* Default value: `'disabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 2.2.12

Enables or disables Samba services.

##### `snmpd`
* Default value: `'disabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 2.2.14

Enables or disables SNMP services.

##### `sshd_banner_file`
* Default value: `'/etc/issue.net'`
* Data type: `String`
* Implements: Control 5.2.16
* Related: `configure_sshd`

Provides the location where SSH will send the login banner from.

##### `sshd_client_alive_count_max`
* Default value: `4`
* Data type: `Integer`
* Implements: Control 5.2.13
* Related: `configure_sshd`

Sets the number of client alive messages sshd will send without receiving messages back from the client.

##### `sshd_client_alive_interval`
* Default value: `300`
* Data type: `Integer`
* Implements: Control 5.2.13
* Related: `configure_sshd`

Sets the timeout interval (in seconds) after which if no data has been received from the client will force sshd to send a message through the encrypted channel to request a response from the client.

##### `sshd_hostbased_authenticaton`
* Default value: `'no'`
* Data type: `Enum['yes','no']`
* Implements: Control 5.2.7
* Related: `configure_sshd`

Specifies whether `rhosts` or `/etc/hosts.equiv` authentication together with successful public key client host authentication is allowed.

##### `sshd_ignore_rhosts`
* Default value: `'yes'`
* Data type: `Enum['yes','no'`
* Implements: Control 5.2.6
* Related: `configure_sshd`

Specifies that `.rhosts` and `.shosts` will not be used in `RhostsRSAAuthentication` or `HostbasedAuthentication`.

##### `sshd_login_grace_time`
* Default value: `60`
* Data type: `Integer`
* Implements: Control 5.2.14
* Related: `configure_sshd`

Amount of time (in seconds) when the server disconnects if the user has not successfully logged in.

##### `sshd_log_level`
* Default value: `'INFO'`
* Data type: `Enum['DEBUG','DEBUG1','DEBUG2','DEBUG3','ERROR','FATAL','INFO','QUIET','VERBOSE']`
* Implements: Control 5.2.3
* Related: `configure_sshd`

Sets the verbosity level that is used when logging messages.

##### `sshd_max_auth_tries`
* Default value: `4`
* Data type: `Integer`
* Implements: Control 5.2.5
* Related: `configure_sshd`

Specifies the maximum number of authentication attempts permitted per connection.

##### `sshd_permit_empty_passwords`
* Default value: `'no'`
* Data type: `Enum['yes','no']`
* Implements: Control 5.2.9
* Related: `configure_sshd`

Specifies whether the server allows login to accounts with empty password strings.

##### `sshd_permit_root_login`
* Default value: `'no'`
* Data type: `Enum['yes','no']`
* Implements: Control 5.2.8
* Related: `configure_sshd`

Specifies whether root can log in directly with ssh.

##### `sshd_permitted_ciphers`
* Default value: `'[ 'aes256-ctr', aes192-ctr', 'aes128-ctr', 'aes256-gcm@openssh.com', 'aes128-gcm@openssh.com', 'chacha20-poly1305@openssh.com' ]`
* Data type: `Array[String]`
* Implements: Control 5.2.11
* Related: `configure_sshd`, `sshd_protocol`

Specifies the ciphers allowed for protocol version 2.

##### `sshd_permitted_macs`
* Default value: `[ 'hmac-sha2-512-etm@openssh.com', 'hmac-sha2-256-etm@openssh.com', 'umac-128-etm@openssh.com', 'hmac-sha2-512', 'hmac-sha2-256', 'umac-128@openssh.com', 'curve25519-sha256@libssh.org', 'diffie-hellman-group-exchange-sha256' ]`
* Data type: `Array[String]`
* Implements: Control 5.2.12
* Related: `configure_sshd`, `sshd_protocol`

Specifies the available MAC (message authentication code) algorithms allowed for protocol version 2.

##### `sshd_permit_user_environment`
* Default value: `'no'`
* Data type: `Enum['yes','no']`
* Implements: Control 5.2.10
* Related: `configure_sshd`

Specifies whether `~/.ssh/environment` and `environment=` options in `~/.ssh/authorized_keys` are processed.

##### `sshd_protocol`
* Default value: `'2'`
* Data type: `String`
* Implements: Control 5.2.2
* Related: `configure_sshd`

Specifies the protocol versions sshd supports.

##### `sshd_x11_forwarding`
* Default value: `'no'`
* Data type: `Enum['yes','no']`
* Implements: Control 5.2.4
* Related: `configure_sshd`

Specifies whether X11 forwarding is permitted.

##### `squid`
* Default value: `'disabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 2.2.13

Enables or disables HTTP Proxy services.

##### `telnet`
* Default value: `'disabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 2.2.19

Enables or disables telnet server services.

##### `tftp`
* Default value: `'disabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 2.2.20

Enables or disables TFTP server services.

##### `time_dgram`
* Default value: `'disabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 2.1.5
* Related: `inetd`

Enables or disables time services through (x)inetd super server.  Do not confuse this parameter with ntpd and chrony.

##### `time_service_provider`
* Default value: `'ntp'`
* Data type: `Enum['ntp','chrony']`
* Implements: Controls 2.2.1.1 - 2.2.1.3
* Related: `configure_time`

Controls whether the system will use ntpd or chrony.

##### `time_service_servers`
* Default value: `'[ '0.rhel.pool.ntp.org', '1.rhel.pool.ntp.org', '2.rhel.pool.ntp.org', '3.rhel.pool.ntp.org' ]'`
* Data type: `Array[String]`
* Implements: Control 2.2.1.1
* Related: `configure_time`

Provides a list of time servers to synchronize with.

##### `time_stream`
* Default value: `'disabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 2.1.5
* Related: `inetd`

Enables or disables time services through (x)ientd super server.  Do not confuse this parameter with ntpd or chrony.

##### `vsftpd`
* Default value: `'disabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Control 2.2.9

Enables or disables FTP server services.

##### `ypserv`
* Default value: `'disabled'`
* Data type: `Enum['enabled','disabled']`
* Implements: Controls 2.2.1.6

Enables or disables NIS server services.


## Limitations

This module has been tested on RHEL 7 and it "should" work on CentOS 7 but no testing has been performed.

## Development

### Bugs

Please use GitHub to file an issue if you run into problems with the module.

### Pull Request

If you can patch the bugs you find or want to add features and functionality, please create a pull request.
