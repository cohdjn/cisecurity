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

cisecurity touches a wide variety of system-level settings:

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

* cisecurity::filesystem: Handles the filesystem controls.
* cisecurity::network: Handles the network controls.
* cisecurity::packages: Handles the package and yum controls.
* cisecurity::pam: Handles the PAM controls.
* cisecurity::security: Handles Grub, SELinux, and other miscellaneous controls.
* cisecurity::services: Handles the network controls.

### Parameters

## Limitations

This module has been tested on RHEL 7 and it "should" work on CentOS 7 but no testing has been performed.

## Development

### Bugs

Please use GitHub to file an issue if you run into problems with the module.

### Pull Request

If you can patch the bugs you find or want to add features and functionality, please create a pull request.
