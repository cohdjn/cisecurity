# redhat7/packages
#
# Implements Center of Internet Security package controls.

class cisecurity::redhat7::packages (
  Enum['enabled','disabled'] $aide,
  String $aide_cron_start_hour,
  String $aide_cron_start_minute,
  Enum['installed','uninstalled'] $firewalld,
  Enum['installed','uninstalled'] $logrotate,
  Enum['installed','uninstalled'] $mcstrans,
  Enum['installed','uninstalled'] $openldap_clients,
  Enum['installed','uninstalled'] $prelink,
  Enum['installed','uninstalled'] $rsh,
  Enum['installed','uninstalled'] $setroubleshoot,
  Enum['installed','uninstalled'] $talk,
  Enum['installed','uninstalled'] $tcp_wrappers,
  Enum['installed','uninstalled'] $telnet,
  Enum['installed','uninstalled'] $x_windows,
  Enum['installed','uninstalled'] $ypbind,
  Enum['installed','uninstalled'] $yum_auto_update,
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
  String $yum_gpg_keys_required_signers,
  Enum['enabled','disabled'] $yum_repo_enforce_gpgcheck,
) {

  if $aide == 'installed' {
    class { 'aide':
      hour   => $aide_cron_start_hour,
      minute => $aide_cron_start_minute,
    }
  } else {
    package { 'aide':
      ensure => purged,
    }
  }

  if $yum_auto_update == 'installed' {
    class { '::yum_auto_update':
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
        package { $package:
          ensure  => present,
        }
      }
      'uninstalled': {
        package { $package:
          ensure  => purged,
        }
      }
      default: {
        fail ("The setting for ${package} must be either 'installed' or 'uninstalled'.")
      }
    }
  }

  if $facts['cisecurity']['yum_enabled_repos'] != undef {
    if empty($facts['cisecurity']['yum_enabled_repos']) {
      warning ('There are no enabled repositories in yum.')
    }
  } else {
    warning ('Cannot validate enabled repositories in yum because required external facts are unavailable. This may be transient.')
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
        exec { 'sed -i s/^gpgcheck.*/gpgcheck=1/ /etc/yum.repos.d/*.repo':
          path => [ '/bin', '/usr/bin' ],
        }
      }
    } else {
      warning ('Cannot validate if GPG checks are present because required external facts are unavailable. This may be transient.')
    }
  }

  if $facts['cisecurity']['gpg_keys'] != undef {
    $found = false
    $facts['cisecurity']['gpg_keys'].each | String $keyname, String $signer | {
      if $signer =~ $yum_gpg_keys_required_signers {
        $found = true
      }
      if !$found {
        warning ('One or more required yum GPG keys were not found.')
      }
    }
  } else {
    warning ('Cannot validate if required GPG keys are present because required external facts are unavailable. This may be transient.')
  }

  if $facts['cisecurity']['subscriptions'] != undef {
    if $facts['cisecurity']['subscriptions']['status'] != 'Subscribed' {
      warning ('No valid entitlement subscriptions were found.')
    }
  } else {
    warning ('Cannot validate entitlement subscriptions because required external facts are unavailable. This may be transient.')
  }

}
