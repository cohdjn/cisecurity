## Release 0.5.0
### Summary
Contains a few bug fixes and enhancements.  Advice on module dependencies from Release 0.4.0 still apply.

#### Bug Fixes
* Fixed bad mount options for /tmp.
* Added EFI detection as an external fact which is used to override whether the vfat filesystem is enabled or disabled.  EFI requires a vfat partition to exist and system will not boot without vfat support.
* Fixed bad variable substitution for root path.
* Modified external facts to purposely remove double-colons and dots from root path to help deal with root path remediation.
* Removed kemra102/bash as a dependency for cisecurity and flipped that functionality to use file_line resources instead.

#### Enhancements
* Added `auditd_admin_space_left`, `auditd_num_logs`, and `auditd_space_left` parameters to services module to provide a few additional nice to have knobs that can be turned as necessary.

## Release 0.4.1
### Summary
Minor bug fix.  Advice on module dependencies from Release 0.4.0 still apply.

#### Bug Fixes
* Modified gpgcheck regex to properly account for spaces that may (or may not) already exist in the files in /etc/yum.repos.d/.

## Release 0.4.0
### Summary
Multiple fixes in this release.  Pay close attention to the module dependencies!

#### Module Dependencies
* The `crayfishx/firewalld` module has been updated to v3.4.0.
* I created a fork of `herculesteam-augeasproviders_grub` that corrects a problem with EFI-based nodes.  I recommend you change your Puppetfile to use my GitHub site (https://github.com/cohdjn/augeasproviders_grub) or install the module from there depending on your environment.  Future release will point back to the Forge once the fix has been merged and uploaded.
* Puppet Labs has an updated version of `puppetlabs/stdlib` that corrects a problem with pattern matching in `file_line` resources. I recommend you change your Puppetfile to use their GitHub site (https://github.com/puppetlabs/puppetlabs-stdlib) or install the module from there depending on your environment.  Future release will point back to the Forge once the fix has been merged and uploaded.

#### Bug Fixes
* Added evaluation of `osrelease` to submodules.  Parameter declaration outside of Hiera breaks miserably when using EPP templates.
* Fixed problem with `file_line` resources constantly appending umask to the end of file.

#### Enhancements
* Moved log file remediation from `exec` resource to `cron` resource to prevent Puppet from always reporting intentional changes on every run.  Two new parameters, `log_file_perms_cron_start_hour` and `log_file_perms_cron_start_minute` have been added to schedule to your environment.

## Release 0.3.3
### Summary
Fixed bad argument in services.

## Release 0.3.2
### Summary
Fixed bad Hiera parameter for home_directories_perm.

## Release 0.3.1
### Summary
Minor modifications to metadata.json to better Puppet Forge score.

## Release 0.3.0
### Summary
Finished manual auditing and testing of the module.  No rspec tests have been done mostly because it's insanely confusing and I don't have the time to work through the process.  If you happen to be good at running these tests, drop me a line because I'd love to work with you through the process.

## Release 0.2.0
### Summary
All critical errors from puppet runs have been corrected. Troubleshooting PAM module still needs to be happen because the config isn't laid down properly. No manual audit validation has been done yet either so there's no guarantee that everything will produce the correct desired state.

## Release 0.1.0
### Summary
First iteration of the cisecurity module.
