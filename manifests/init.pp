# cisecurity
#
# Metaclass to configure with all Level 1 and Level 2 controls enabled.

class cisecurity {

  $osfamily = downcase($facts['os']['family'])
  $osreleasemajor = $facts['os']['release']['major']
  $osrelease = "${osfamily}${osreleasemajor}"

  case $osrelease {
    'redhat7': {
      include 'cisecurity::redhat7::filesystem'
      include 'cisecurity::redhat7::services'
      include 'cisecurity::redhat7::packages'
      include 'cisecurity::redhat7::security'
      include 'cisecurity::redhat7::pam'
      include 'cisecurity::redhat7::network'
    }
    'redhat6': {
      include 'cisecurity::redhat6::filesystem'
      include 'cisecurity::redhat6::services'
      include 'cisecurity::redhat6::packages'
      include 'cisecurity::redhat6::security'
      include 'cisecurity::redhat6::pam'
      include 'cisecurity::redhat6::network'
    }
    default: {
      fail ("${osrelease} is not supported by cisecurity module.")
    }
  }

}
