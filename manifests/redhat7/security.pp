# redhat7/security
#
# Implements Center of Internet Security security controls.

class cisecurity::redhat7::security (

  Enum['enabled','disabled'] $aslr,
  String $banner_message_text,
  String $bootloader_password,
  Enum['enabled','disabled'] $configure_system_acct_nologin,
  String $home_directories_perm,
  String $issue,
  String $issue_net,
  String $motd,
  Enum['enabled','disabled'] $remediate_blank_passwords,
  Enum['enabled','disabled'] $remediate_home_directories_dot_files,
  Enum['enabled','disabled'] $remediate_home_directories_exist,
  Enum['enabled','disabled'] $remediate_home_directories_forward_files,
  Enum['enabled','disabled'] $remediate_home_directories_netrc_files,
  Enum['enabled','disabled'] $remediate_home_directories_netrc_files_perms,
  Enum['enabled','disabled'] $remediate_home_directories_owner,
  Enum['enabled','disabled'] $remediate_home_directories_perms,
  Enum['enabled','disabled'] $remediate_home_directories_rhosts_files,
  String $remediate_home_directories_start_hour,
  String $remediate_home_directories_start_minute,
  Enum['enabled','disabled'] $remediate_legacy_group_entries,
  Enum['enabled','disabled'] $remediate_legacy_passwd_entries,
  Enum['enabled','disabled'] $remediate_legacy_shadow_entries,
  Enum['enabled','disabled'] $remediate_root_path,
  Enum['enabled','disabled'] $remediate_uid_zero_accounts,
  Enum['enabled','disabled'] $restricted_core_dumps,
  Array[String] $root_path,
  Enum['enabled','disabled'] $single_user_authentication,
  Enum['enforcing','permissive','disabled'] $selinux,
  Enum['targeted','minimum','mls'] $selinux_type,
  Array[String] $secure_terminals,
  String $syslog_facility,
  String $syslog_severity,
  Enum['enabled','disabled'] $verify_user_groups_exist,
  Enum['enabled','disabled'] $verify_duplicate_gids_notexist,
  Enum['enabled','disabled'] $verify_duplicate_groupnames_notexist,
  Enum['enabled','disabled'] $verify_duplicate_uids_notexist,
  Enum['enabled','disabled'] $verify_duplicate_usernames_notexist,
) {

  if $bootloader_password != '' {
    grub_user { 'root':
      ensure    => present,
      password  => $bootloader_password,
      superuser => true,
    }

    exec { 'grub2-mkconfig -o /etc/grub2/grub.cfg':
      path        => [ '/usr/sbin', '/sbin', '/usr/bin', '/bin' ],
      refreshonly => true,
      subscribe   => Grub_user['root'],
    }
  }

  if $aslr == 'enabled' {
    sysctl { 'kernel.randomize_va_space':
      ensure  => present,
      value   => '2',
      comment => 'Setting managed by Puppet.',
    }
  }

  if $motd != '' {
    file { '/etc/motd':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0644',
      source => $motd,
    }
  }

  if $issue != '' {
    file { '/etc/issue':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0644',
      source => $issue,
    }
  }

  if $issue_net != '' {
    file { '/etc/issue.net':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0644',
      source => $issue_net,
    }
  }

  if $facts['cisecurity']['installed_packages']['gdm'] != undef {
    $gdm_file = '/etc/dconf/profile/gdm'
    file { $gdm_file:
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0644',
    }
    $gdmconfig = [
      'user-db:user',
      'system-db:gdm',
      'file-db:/usr/share/gdm/greeter-dconf-defaults',
    ]
    $gdmconfig.each | String $line | {
      file_line { "${gdm_file} add ${line}":
        ensure  => present,
        path    => $gdm_file,
        line    => $line,
        require => File[$gdm_file],
        notify  => Exec['dconf update'],
      }
    }
    $gdm_banner_file = '/etc/dconf/db/gdm.d/01-banner-message'
    file { $gdm_banner_file:
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0644',
    }
    $bannerconfig = {
      'banner-message-enable' => 'true',
      'banner_message_text'   => $banner_message_text,
    }
    $bannerconfig.each | String $setting, String $value | {
      ini_setting { "${gdm_banner_file} add ${setting}":
        ensure  => present,
        path    => $gdm_banner_file,
        section => 'org/gnome/login-screen',
        setting => $setting,
        value   => $value,
        require => File[$gdm_banner_file],
        notify  => Exec['dconf update'],
      }
    }
    exec { 'dconf update':
      path        => [ '/sbin', '/bin' ],
      refreshonly => true,
    }
  }

  if $selinux == 'enforcing' {
    kernel_parameter { 'selinux':
      ensure => present,
      value  => '1',
    }
    kernel_parameter { 'enforcing':
      ensure => present,
      value  => '1',
    }
  }

  class { '::selinux':
    mode => $selinux,
    type => $selinux_type,
  }

  if $restricted_core_dumps == 'enabled' {
    file { '/etc/security/limits.d/CIS.conf':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0644',
    }
    file_line { '/etc/security/limits.d/CIS.conf':
      ensure => present,
      path   => '/etc/security/limits.d/CIS.conf',
      line   => '* hard core 0',
    }
    sysctl { 'fs.suid_dumpable':
      ensure  => present,
      value   => '0',
      comment => 'Setting managed by Puppet.',
    }
  }

  if $single_user_authentication == 'enabled' {
    ini_setting { 'emergency.service ExecStart':
      ensure  => present,
      path    => '/usr/lib/systemd/system/emergency.service',
      section => 'Service',
      setting => 'ExecStart',
      value   => '-/bin/sh -c "/sbin/sulogin; /usr/bin/systemctl --fail --no-block default"',
    }
    ini_setting { 'rescue.service ExecStart':
      ensure  => present,
      path    => '/usr/lib/systemd/system/rescue.service',
      section => 'Service',
      setting => 'ExecStart',
      value   => '-/bin/sh -c "/sbin/sulogin; /usr/bin/systemctl --fail --no-block default"',
    }
  }

  if $facts['cisecurity']['unconfined_daemons'] != undef {
    if !empty($facts['cisecurity']['unconfined_daemons']) {
      notice ('One or more unconfined daemons found running on this system.')
    }
  } else {
    notice ('Cannot validate the presence of unconfined daemons because required external facts are unavailable.')
  }

  if $facts['architecture'] != 'x86_64' {
    notice ('The system appears to be running on an x86 system.  Make sure PAE extensions are installed and NX/XD support properly configured.')
  }

  if !empty($secure_terminals) {
    $ttys = join($secure_terminals, "\n")
    file { '/etc/securetty':
      ensure  => file,
      owner   => 'root',
      group   => 'root',
      mode    => '0600',
      content => $ttys,
    }
  }

  if $configure_system_acct_nologin == 'enabled' {
    if $facts['cisecurity']['system_accounts_with_valid_shell'] != undef {
      $facts['cisecurity']['system_accounts_with_valid_shell'].each | String $username | {
        user { $username:
          ensure => present,
          shell  => '/sbin/nologin',
        }
      }
    } else {
      notice ('Cannot validate if system accounts have valid shells because required external facts are unavailable.')
    }
  }

  if $remediate_blank_passwords == 'enabled' {
    if $facts['cisecurity']['accounts_with_blank_passwords'] != undef {
      $facts['cisecurity']['accounts_with_blank_passwords'].each | String $username | {
        accounts::user { $username:
          locked => true,
        }
      }
    } else {
      notice ('Cannot validate if there are accounts with blank passwords because required external facts are unavailable.')
    }
  }

  if $remediate_legacy_passwd_entries == 'enabled' {
    file_line { 'remove legacy passwd entries':
      ensure            => absent,
      path              => '/etc/passwd',
      match             => '^+:.*',
      multiple          => true,
      match_for_absence => true,
    }
  }

  if $remediate_legacy_shadow_entries == 'enabled' {
    file_line { 'remove legacy shadow entries':
      ensure            => absent,
      path              => '/etc/shadow',
      match             => '^+:.*',
      multiple          => true,
      match_for_absence => true,
    }
  }

  if $remediate_legacy_group_entries == 'enabled' {
    file_line { 'remove legacy group entries':
      ensure            => absent,
      path              => '/etc/group',
      match             => '^+:.*',
      multiple          => true,
      match_for_absence => true,
    }
  }

  if $remediate_uid_zero_accounts == 'enabled' {
    if $facts['cisecurity']['accounts_with_uid_zero'] != undef {
      $facts['cisecurity']['accounts_with_uid_zero'].each | String $username | {
        if $username != 'root' {
          user { $username:
            ensure => absent,
          }
        }
      }
    } else {
      notice ('Cannot validate if there are duplicate UID 0 accounts because required external facts are unavailable.')
    }
  }

  if $remediate_root_path == 'enabled' {
    class { '::bash': }
    $flattened_path = join($root_path, ':')
    bash::user { 'root':
      env_variables => { 'path' => $root_path },
    }
    if $facts['cisecurity']['root_path'] != undef {
      $facts['cisecurity']['root_path'].each | String $directory | {
      unless File[$directory] {
          file { $directory:
            ensure => directory,
            owner  => 'root',
            group  => 'root',
            mode   => 'o-w,g-w',
          }
        }
      }
    } else {
      notice ('Cannot validate root\'s path because required external facts are unavailable.')
    }
  }

  file { '/opt/cisecurity':
    ensure => directory,
    owner  => 'root',
    group  => 'root',
    mode   => '0555',
  }
  file { '/opt/cisecurity/scripts':
    ensure  => directory,
    owner   => 'root',
    group   => 'root',
    mode    => '0555',
    require => File['/opt/cisecurity'],
  }
  $script = epp("cisecurity/${cisecurity::osrelease}__remediate_home_directories.sh")
  file { '/opt/cisecurity/scripts/remediate_home_directories.sh':
    ensure  => file,
    owner   => 'root',
    group   => 'root',
    mode    => '0555',
    content => $script,
    require => File['/opt/cisecurity/scripts'],
  }
  cron { 'remediate_home_directories.sh':
    ensure  => present,
    command => '/opt/cisecurity/scripts/remediate_home_directories.sh',
    user    => 'root',
    hour    => $remediate_home_directories_start_hour,
    minute  => $remediate_home_directories_start_minute,
    require => File['/opt/cisecurity/scripts/remediate_home_directories.sh'],
  }

}
