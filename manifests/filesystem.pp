# filesystem
#
# Implements Center of Internet Security filesystem controls.
#
# @param configure_umask_default [Enum['enabled','disabled'] Whether the system-wide default umask should be configured. Default value: 'enabled'.
# @param cramfs [Enum['enabled','disabled']] Whether cramfs should be enabled. Default value: 'disabled'.
# @param dev_shm_mount_options [Array[String]] Specifies the mount options for /dev/shm. Default value: ['noexec','nodev','nosuid'].
# @param freevxfs [Enum['enabled','disabled']] Whether freevxfs should be enabled. Default value: 'disabled'.
# @param harden_system_file_perms [Enum['enabled','disabled'] Whether to harden all system files in the specification to recommended values. Default value: 'enabled'.
# @param hfs [Enum['enabled','disabled']] Whether hfs should be enabled. Default value: 'disabled'.
# @param hfsplus [Enum['enabled','disabled']] Whether hfsplus should be enabled. Default value: 'disabled'.
# @param home_mount_options [Array[String]] Specifies the mount options for /home. Default value: ['nodev'].
# @param jffs2 [Enum['enabled','disabled']] Whether jffs2 should be enabled. Default value: 'disabled'.
# @param remediate_log_file_perms [Enum['enabled','disabled']] Whether files in /var/log should be trimmed back. Default value: 'enabled'.
# @param remediate_ungrouped_files [Enum['enabled','disabled'] Whether the module should assign a valid group to ungrouped files. Default value: 'enabled'.
# @param remediate_unowned_files [Enum['enabled','disabled'] Whether the module should assign a valid owner to unowned files. Default value: 'enabled'.
# @param remediate_world_writable_dirs [Enum['enabled','disabled'] Whether the module should remove world writable permissions from directories with it set. Default value: 'enabled'.
# @param remediate_world_writable_files [Enum['enabled','disabled'] Whether the module should remove world writable permissions from files with it set. Default value: 'enabled'.
# @param removable_media_mount_options [Array[String]] Specifies the mount options for removable media. Default value: ['noexec','nodev','nosuid'].
# @param removable_media_partitions [Array[String]] Specifies a list of removable media devices. Default value: [ ].
# @param squashfs [Enum['enabled','disabled']] Whether squashfs should be enabled. Default value: 'disabled'.
# @param tmp_mount_options [Array[String]] Specifies the mount options for /tmp. Default value: ['mode=1777','astrictatime','noexec','nodev','nosuid'].
# @param udf [Enum['enabled','disabled']] Whether udf should be enabled. Default value: 'disabled'.
# @param umask_default [String[3]] The system-wide default umask to be configured. Default value: '027'.
# @param ungrouped_files_replacement_group [String] The group to assign to files that are unowned. Default value: 'root'.
# @param unowned_files_replacement_owner [String] The user to assign to files that are unowned. Default value: 'root'.
# @param var_mount_options [Array[String]] Specifies the mount options for /var. Default value: ['defaults'].
# @param var_log_audit_mount_options [Array[String]] Specifies the mount options for /var/log/audit. Default value: ['defaults'].
# @param var_log_mount_options [Array[String]] Specifies the mount options for /var/log. Default value: ['defaults'].
# @param var_tmp_mount_options [Array[String]] Specifies the mount options for /var/tmp. Default value: ['bind'].
# @param vfat [Enum['enabled','disabled']] Whether vfat should be enabled. Default value: 'disabled'.

class cisecurity::filesystem (
  Enum['enabled','disabled'] $configure_umask_default        = 'enabled',
  Enum['enabled','disabled'] $cramfs                         = 'disabled',
  Array[String] $dev_shm_mount_options                       = ['noexec','nodev','nosuid'],
  Enum['enabled','disabled'] $freevxfs                       = 'disabled',
  Enum['enabled','disabled'] $harden_system_file_perms       = 'enabled',
  Enum['enabled','disabled'] $hfs                            = 'disabled',
  Enum['enabled','disabled'] $hfsplus                        = 'disabled',
  Array[String] $home_mount_options                          = ['nodev'],
  Enum['enabled','disabled'] $jffs2                          = 'disabled',
  Enum['enabled','disabled'] $remediate_log_file_perms       = 'enabled',
  Enum['enabled','disabled'] $remediate_ungrouped_files      = 'enabled',
  Enum['enabled','disabled'] $remediate_unowned_files        = 'enabled',
  Enum['enabled','disabled'] $remediate_world_writable_dirs  = 'enabled',
  Enum['enabled','disabled'] $remediate_world_writable_files = 'enabled',
  Array[String] $removable_media_mount_options               = ['noexec','nodev','nosuid'],
  Array[String] $removable_media_partitions                  = [],
  Enum['enabled','disabled'] $squashfs                       = 'disabled',
  Array[String] $tmp_mount_options                           = ['mode=1777','astrictatime','noexec','nodev','nosuid'],
  Enum['enabled','disabled'] $udf                            = 'disabled',
  String[3] $umask_default                                   = '027',
  String $ungrouped_files_replacement_group                  = 'root',
  String $unowned_files_replacement_owner                    = 'root',
  Array[String] $var_mount_options                           = ['defaults'],
  Array[String] $var_log_audit_mount_options                 = ['defaults'],
  Array[String] $var_log_mount_options                       = ['defaults'],
  Array[String] $var_tmp_mount_options                       = ['bind'],
  Enum['enabled','disabled'] $vfat                           = 'disabled',
) {

  # Private variables.
  $filesystem_list = [
    'cramfs',
    'freevxfs',
    'jffs2',
    'hfs',
    'hfsplus',
    'squashfs',
    'udf',
    'vfat',
  ]
  $cronfiles = [ '/etc/crontab', '/etc/cron.allow', '/etc/at.allow' ]
  $crondirs = [ '/etc/cron.hourly', '/etc/cron.daily', '/etc/cron.weekly', '/etc/cron.monthly', '/etc/cron.d' ]
  $crondenies = [ '/etc/cron.deny', '/etc/at.deny' ]

  file { '/etc/modprobe.d':
    ensure => directory,
    mode   => '0755',
    owner  => 'root',
    group  => 'root',
  }

  file { '/etc/modprobe.d/CIS.conf':
    ensure => file,
    mode   => '0644',
    owner  => 'root',
    group  => 'root',
  }

  $filesystem_list.each | String $filesystem | {
    case getvar($filesystem) {
      'enabled': {
        file_line { $filesystem:
          ensure  => absent,
          path    => '/etc/modprobe.d/CIS.conf',
          line    => "install $filesystem /bin/true",
          require => [ File['/etc/modprobe.d' ], File['/etc/modprobe.d/CIS.conf'] ]
        }
      }
      'disabled': {
        file_line { $filesystem:
          ensure  => present,
          path    => '/etc/modprobe.d/CIS.conf',
          line    => "install $filesystem /bin/true",
          require => [ File['/etc/modprobe.d' ], File['/etc/modprobe.d/CIS.conf'] ]
        }
      }
    }
  }

  if $facts['mountpoints']['/tmp'] == undef {
    warning ('Cannot configure mount options for /tmp because it\'s not a valid partition.')
  } else {
    if $facts['mountpoints']['/tmp']['filesystem'] == 'tmpfs' {
      exec { 'systemctl unmask tmp.mount':
        path      => [ 'bin', '/usr/bin' ],
        logoutput => on_failure,
        unless    => 'ls /etc/systemd/system/local-fs.target.wants/tmp.mount',
      }

      ini_setting { 'tmp mount options':
        ensure  => present,
        path    => '/etc/systemd/system/local-fs.target.wants/tmp.mount',
        section => 'Mount',
        setting => 'Options',
        value   => $tmp_mount_options,
        require => Exec['systemctl unmask tmp.mount'],
      }

      service { 'tmp.mount':
        ensure   => running,
        enable   => true,
        remounts => false,
        require  => Ini_setting['tmp mount options'],
      }

    } else {
      mount { '/tmp':
        ensure   => present,
        options  => $tmp_mount_options,
        remounts => false,
      }
    }
  }

  if $facts['mountpoints']['/var'] == undef {
    warning ('Cannot configure mount options for /var because it\'s not a valid partition.')
  } else {
    mount { '/var':
      ensure   => present,
      options  => $var_mount_options,
      remounts => false,
    }
  }

  if $facts['mountpoints']['/var/tmp'] == undef {
    warning ('Cannot configure mount options for /var/tmp because it\'s not a valid partition.')
  } else {
    mount { '/var/tmp':
      ensure   => mounted,
      device   => '/tmp',
      fstype   => 'none',
      options  => $var_tmp_mount_options,
      remounts => false,
    }
  }

  if $facts['mountpoints']['/var/log'] == undef {
    warning ('Cannot configure mount options for /var/log because it\'s not a valid partition.')
  } else {
    mount { '/var/log':
      ensure   => present,
      options  => $var_log_mount_options,
      remounts => false,
    }
  }

  if $facts['mountpoints']['/var/log/audit'] == undef {
    warning ('Cannot configure mount options for /var/log/audit because it\'s not a valid partition.')
  } else {
    mount { '/var/log/audit':
      ensure   => present,
      options  => $var_log_audit_mount_options,
      remounts => false,
    }
  }

  if $facts['mountpoints']['/home'] == undef {
    warning ('Cannot configure mount options for /home because it\'s not a valid partition.')
  } else {
    mount { '/home':
      ensure   => present,
      options  => $home_mount_options,
      remounts => false,
    }
  }

  if $facts['mountpoints']['/dev/shm'] == undef {
    warning ('Cannot configure mount options for /dev/shm because it\'s not a valid partition.')
  } else {
    mount { '/dev/shm':
      ensure   =>  'mounted',
      name     => '/dev/shm',
      device   => 'shmfs',
      fstype   => 'tmpfs',
      options  => $dev_shm_mount_options,
      remounts => false,
    }
  }
  
  $removable_media_partitions.each | String $partition | {
    mount { $partition:
      ensure   => present,
      options  => $removable_media_mount_options,
      remounts => false,
      atboot   => false,
    }
  }

  if $remediate_world_writable_dirs == 'enabled' {
    $facts['cisecurity']['world_writable_dirs'].each | String $directory | {
      file { $directory:
        ensure => directory,
        mode   => 'o+t',
      }
    }
  }

  if $remediate_world_writable_files == 'enabled' {
    $facts['cisecurity']['world_writable_files'].each | String $file | {
      file { $file:
        ensure => file,
        mode   => 'o-w',
      }
    }
  }

  if $remediate_unowned_files == 'enabled' {
    $facts['cisecurity']['unowned_files'].each | String $file | {
      file { $file:
        ensure => file,
        owner  => $unowned_files_replacement_owner,
      }
    }
  }

  if $remediate_ungrouped_files == 'enabled' {
    $facts['cisecurity']['ungrouped_files'].each | String $file | {
      file { $file:
        ensure => file,
        gid    => $ungrouped_files_replacement_group,
      }
    }
  }

  if $configure_umask_default == 'enabled' {
    file { '/etc/bashrc':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0644',
    }

    file { '/etc/profile':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0644',
    }

    file_line { '/etc/bashrc':
      ensure  => present,
      path    => '/etc/bashrc',
      line    => "umask ${umask_default}",
      require => File['/etc/bashrc'],
    }

    file_line { '/etc/profile':
      ensure  => present,
      path    => '/etc/profile',
      line    => "umask ${umask_default}",
      require => File['/etc/profile'],
    }
  }

  if $harden_system_file_perms == 'enabled' {
    file { '/etc/passwd':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0644',
    }

    file { '/etc/shadow':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0000',
    }

    file { '/etc/group':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0644',
    }

    file { '/etc/gshadow':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0600',
    }

    file { '/etc/passwd-':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0600',
    }

    file { '/etc/shadow-':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0600',
    }

    file { '/etc/group-':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0600',
    }

    file { '/etc/gshadow-':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0600',
    }

    $cronfiles.each | String $file | {
      file { $file:
        ensure => file,
        group  => 'root',
        owner  => 'root',
        mode   => '0600',
      }
    }

    $crondirs.each | String $directory | {
      file { $directory:
        ensure => directory,
        group  => 'root',
        owner  => 'root',
        mode   => '0700',
      }
    }

    $crondenies.each | String $file | {
      file { $file:
        ensure => absent,
      }
    }

    file { '/etc/ssh/sshd_config':
      ensure => file,
      mode   => '0600',
      owner  => 'root',
      group  => 'root',
    }
  }

  if $remediate_log_file_perms == 'enabled' {
    cron { 'logfile_perms':
      ensure  => present,
      command => 'find /var/log -type f -exec chmod g-wx,o-rwx {} \;',
      user    => 'root',
      minute  => '*/30',
    }
  } else {
    cron { 'logfile_perms':
      ensure  => absent,
      command => 'find /var/log -type f -exec chmod g-wx,o-rwx {} \;',
      user    => 'root',
      minute  => '*/30',
    }
  }

}
