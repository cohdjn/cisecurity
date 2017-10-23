# redhat7/packages
#
# Implements Center of Internet Security package controls.

class cisecurity::redhat7::packages (
  Enum['installed','uninstalled','ignored'] $aide,
  String $aide_cron_start_hour,
  String $aide_cron_start_minute,
  Enum['installed','uninstalled','ignored'] $firewalld,
  Enum['installed','uninstalled','ignored'] $logrotate,
  Enum['installed','uninstalled','ignored'] $mcstrans,
  Enum['installed','uninstalled','ignored'] $openldap_clients,
  Enum['installed','uninstalled','ignored'] $prelink,
  Enum['installed','uninstalled','ignored'] $rsh,
  Enum['installed','uninstalled','ignored'] $setroubleshoot,
  Enum['installed','uninstalled','ignored'] $talk,
  Enum['installed','uninstalled','ignored'] $tcp_wrappers,
  Enum['installed','uninstalled','ignored'] $telnet,
  Enum['installed','uninstalled','ignored'] $x11_org,
  Enum['installed','uninstalled','ignored'] $ypbind,
  Enum['installed','uninstalled','ignored'] $yum_auto_update,
  Enum['check','download','apply'] $yum_auto_update_action,
  String $yum_auto_update_email_from,
  String $yum_auto_update_email_to,
  Array[String] $yum_auto_update_exclude,
  Boolean $yum_auto_update_notify_email,
  Enum[
    'default',
    'minimal',
    'minimal-security',
    'minimal-security-severity:Critical',
    'security',
    'security-severity:Critical'] $yum_auto_update_update_cmd,
  Enum['enabled','disabled'] $yum_repo_enforce_gpgcheck,
) {

  if $aide == 'installed' {
    class { '::aide':
      hour   => $aide_cron_start_hour,
      minute => $aide_cron_start_minute,
    }
  } else {
    package { 'aide':
      ensure => purged,
    }
  }

  if $yum_auto_update == 'installed' {
    class { '::yum_autoupdate':
      action       => $yum_auto_update_action,
      exclude      => $yum_auto_update_exclude,
      notify_email => $yum_auto_update_notify_email,
      email_to     => $yum_auto_update_email_to,
      email_from   => $yum_auto_update_email_from,
      update_cmd   => $yum_auto_update_update_cmd,
    }
  }

  $package_list = [
    'firewalld',
    'logrotate',
    'mcstrans',
    'openldap-clients',
    'prelink',
    'rsh',
    'setroubleshoot',
    'talk',
    'tcp-wrappers',
    'telnet',
    'x11-org',
    'ypbind',
  ]
  $package_list.each | String $package | {
    $uscore_package = regsubst($package, '-', '_')
    case getvar($uscore_package) {
      'installed': {
        unless Package[$package] {
          package { $package:
            ensure  => present,
          }
        }
      }
      'uninstalled': {
        unless Package[$package] {
          package { $package:
            ensure  => purged,
          }
        }
      }
      'ignored': {
        notice ("Will not attempt to install or uninstall ${package} because it's being ignored.")
      }
      default: {
        fail ("The setting for ${package} must be either 'installed' or 'uninstalled'.")
      }
    }
  }

  if $facts['cisecurity']['yum_enabled_repos'] != undef {
    if empty($facts['cisecurity']['yum_enabled_repos']) {
      notice ('There are no enabled repositories in yum.')
    }
  } else {
    notice ('Cannot validate enabled repositories in yum because required external facts are unavailable. This may be transient.')
  }

  if $yum_repo_enforce_gpgcheck == 'enabled' {
    file { '/etc/yum.conf':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0644',
    }
    ini_setting { 'yum.conf gpgcheck':
      ensure  => present,
      path    => '/etc/yum.conf',
      section => 'main',
      setting => 'gpgcheck',
      value   => '1',
      require => File['/etc/yum.conf'],
    }
    if $facts['cisecurity']['yum_repos_gpgcheck_consistent'] != undef {
      if $facts['cisecurity']['yum_repos_gpgcheck_consistent'] == false {
        exec { 'sed -i \'s/^\(gpgcheck\s*=\s*\).*/\11/\' /etc/yum.repos.d/*.repo':
          path => [ '/bin', '/usr/bin' ],
        }
      }
    } else {
      notice ('Cannot validate if GPG checks are present because required external facts are unavailable. This may be transient.')
    }
  }

  if $facts['cisecurity']['redhat_gpg_key_present'] != undef {
    if $facts['cisecurity']['redhat_gpg_key_present'] == false {
      notice ('One or more required yum GPG keys were not found.')
    }
  } else {
    notice ('Cannot validate if required GPG keys are present because required external facts are unavailable. This may be transient.')
  }

  if $facts['cisecurity']['subscriptions'] != undef {
    if $facts['cisecurity']['subscriptions']['status'] != 'Subscribed' {
      notice ('No valid entitlement subscriptions were found.')
    }
  } else {
    notice ('Cannot validate entitlement subscriptions because required external facts are unavailable. This may be transient.')
  }

}
