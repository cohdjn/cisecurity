# redhat7/packages
#
# Implements Center of Internet Security package controls.
#
# @param aide [Enum['enabled','disabled']] Whether aide should be installed and configured. Default value: 'enabled'.
# @param aide_cron_start_hour [String] Cron-styled hour to initiate an aide check. Default value: '5'.
# @param aide_cron_start_minute [String] Cron-styled minute to initiate an aide check.  Default value: '0'.
# @param firewalld [Enum['installed','uninstalled']] Whether firewalld should be installed on the system. Default value: 'uninstalled'.
# @param logrotate [Enum['installed','uninstalled']] Whether logrotate should be installed on the system. Default value: 'uninstalled'.
# @param mcstrans [Enum['installed','uninstalled']] Whether mcstrans should be installed on the system. Default value: 'uninstalled'.
# @param openldap_clients [Enum['installed','uninstalled']] Whether openldap_clients should be installed on the system. Default value: 'uninstalled'.
# @param prelink [Enum['installed','uninstalled']] Whether prelink should be installed on the system. Default value: 'uninstalled'.
# @param rsh [Enum['installed','uninstalled']] Whether rsh should be installed on the system. Default value: 'uninstalled'.
# @param setroubleshoot [Enum['installed','uninstalled']] Whether setroubleshoot should be installed on the system. Default value: 'uninstalled'.
# @param talk [Enum['installed','uninstalled']] Whether talk should be installed on the system. Default value: 'uninstalled'.
# @param tcp_wrappers [Enum['installed','uninstalled']] Whether tcp-wrappers should be installed on the system. Default value: 'installed'.
# @param telnet [Enum['installed','uninstalled']] Whether telnet should be installed on the system. Default value: 'uninstalled'.
# @param x_windows [Enum['installed','uninstalled']] Whether X Windows should be installed on the system. Default value: 'uninstalled'.
# @param ypbind [Enum['installed','uninstalled']] Whether ypbind Windows should be installed on the system. Default value: 'uninstalled'.
# @param yum_auto_update [Enum['installed','uninstalled']] Whether yum_auto_update Windows should be installed on the system. Default value: 'installed'.
# @param yum_auto_update_action [Enum['check','download','apply']] Determines what action to take when updates are available. Default value: 'apply'.
# @param yum_auto_update_email_from [String] Email address where notifications originate from. Default value: 'root'.
# @param yum_auto_update_email_to [String] Email address to send notifications to. Default value: 'root'.
# @param yum_auto_update_exclude [Array[String]] Packages that should not be updated. Default value: [ ].
# @param yum_auto_update_notify_email [Boolean] Whether anyone should be notified by email when updates occur. Default value: true.
# @param yum_auto_update_update_cmd [Enum['default','security','security-severity:Critical','minimal','minimal-security','minimal-security-severity:Critical']] What category of updates should be applied to the system. Default value: 'default'.
# @param yum_gpg_keys_required_signers [String] A regex specifying what to look for with respect to installed GPG keys. Default value: '/redhat/'.
# @param yum_repo_enforce_gpgcheck [Enum['enabled','disabled'a]] Whether GPG checks should be globally enabled on all repos. Default value: 'enabled'.

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

  # Private variables.
  $package_list = [
    'firewalld',
    'logrotate',
    'mcstrans',
    'openldap_clients',
    'prelink',
    'rsh',
    'setroubleshoot',
    'talk',
    'tcp-wrappers',
    'telnet',
    'x11-org',
    'ypbind',
  ]

  if $aide == 'enabled' {
    package { 'aide':
      ensure => present,
    }

    exec { 'aide_init':
      command => "/usr/sbin/aide --init -B 'database_out=file:/var/lib/aide/aide.db.gz'",
      creates => '/var/lib/aide/aide.db.gz',
      require => Package['aide']
    }

    cron { 'aide':
      ensure  => present,
      command => '/usr/sbin/aide --check',
      user    => 'root',
      hour    => $aide_cron_start_hour,
      minute  => $aide_cron_start_minute,
      require => Exec['aide_init']
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

  $package.list.each | String $package | {
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
    }
  }

  if $facts['cisecurity']['yum_enabled_repos'] != undef and !facts['cisecurity']['yum_enabled_repos'] {
    warning ('There are no enabled repositories in yum.')
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

    if $facts['cisecurity']['yum_repos_gpgcheck_consistent'] != undef and $facts['cisecurity']['yum_repos_gpgcheck_consistent'] == false {
      exec { 'sed -i s/^gpgcheck.*/gpgcheck=1/ /etc/yum.repos.d/*.repo':
        path => [ '/bin', '/usr/bin' ],
      }
    }
  }

  if $facts['cisecurity']['gpg_keys'] != undef {
    $found = false
    $facts['cisecurity']['gpg_keys'].each | String $keyname, String $signer | {
      if $signer =~ $cisecurity::yum_gpg_keys_required_signers {
        $found = true
      }
      if !$found {
        warning ('One or more required yum GPG keys were not found.')
      }
    }
  }

  if $facts['cisecurity']['subscriptions'] != undef and $facts['cisecurity']['subscriptions']['status'] == 'Subscribed' {
    warning ('No valid entitlement subscriptions were found.')
  }

}
