# redhat7/network
#
# Implements Center of Internet Security network controls.

class cisecurity::redhat7::network (
  Enum['enabled','disabled'] $dccp,
  String $hosts_allow,
  String $hosts_deny,
  Enum['enabled','disabled'] $ipv4_forwarding,
  Enum['enabled','disabled'] $ipv4_accept_icmp_redirects,
  Enum['enabled','disabled'] $ipv4_ignore_icmp_bogus_responses,
  Enum['enabled','disabled'] $ipv4_ignore_icmp_broadcasts,
  Enum['enabled','disabled'] $ipv4_log_suspicious_packets,
  Enum['enabled','disabled'] $ipv4_reverse_path_filtering,
  Enum['enabled','disabled'] $ipv4_secure_redirects,
  Enum['enabled','disabled'] $ipv4_send_redirects,
  Enum['enabled','disabled'] $ipv4_source_routing,
  Enum['enabled','disabled'] $ipv4_tcp_syncookies,
  Enum['enabled','disabled'] $ipv6,
  Enum['enabled','disabled'] $ipv6_accept_router_advertisements,
  Enum['enabled','disabled'] $ipv6_accept_packet_redirects,
  Enum['enabled','disabled'] $rds,
  Enum['enabled','disabled'] $sctp,
  Enum['enabled','disabled'] $tipc,
  Enum['enabled','disabled'] $disable_wireless_interfaces,
) {

  $protocol_list = [
    'dccp',
    'sctp',
    'rds',
    'tipc',
  ]
  $protocol_list.each | String $protocol | {
    if getvar($protocol) == 'disabled' {
      file_line { $protocol:
        ensure => present,
        path   => '/etc/modprobe.d/CIS.conf',
        line   => "install ${protocol} /bin/true",
      }
    }
  }

  if $ipv4_forwarding == 'disabled' {
    sysctl { 'net.ipv4.ip_forward':
      ensure  => present,
      value   => '0',
      comment => 'Setting managed by Puppet.',
    }
  }

  if $ipv4_ignore_icmp_bogus_responses == 'enabled' {
    sysctl { 'net.ipv4.icmp_ignore_bogus_error_responses':
      ensure  => present,
      value   => '1',
      comment => 'Setting managed by Puppet.',
    }
  }

  if $ipv4_ignore_icmp_broadcasts == 'enabled' {
    sysctl { 'net.ipv4.icmp_echo_ignore_broadcasts':
      ensure  => present,
      value   => '1',
      comment => 'Setting managed by Puppet.',
    }
  }

  if $ipv4_accept_icmp_redirects == 'disabled' {
    sysctl { 'net.ipv4.conf.all.accept_redirects':
      ensure  => present,
      value   => '0',
      comment => 'Setting managed by Puppet.',
    }
    sysctl { 'net.ipv4.conf.default.accept_redirects':
      ensure  => present,
      value   => '0',
      comment => 'Setting managed by Puppet.',
    }
  }

  if $ipv4_log_suspicious_packets == 'enabled' {
    sysctl { 'net.ipv4.conf.all.log_martians':
      ensure  => present,
      value   => '1',
      comment => 'Setting managed by Puppet.',
    }
    sysctl { 'net.ipv4.conf.default.log_martians':
      ensure  => present,
      value   => '1',
      comment => 'Setting managed by Puppet.',
    }
  }

  if $ipv4_send_redirects == 'disabled' {
    sysctl { 'net.ipv4.conf.all.send_redirects':
      ensure  => present,
      value   => '0',
      comment => 'Setting managed by Puppet.',
    }
    sysctl { 'net.ipv4.conf.default.send_redirects':
      ensure  => present,
      value   => '0',
      comment => 'Setting managed by Puppet.',
    }
  }

  if $ipv4_reverse_path_filtering == 'enabled' {
    sysctl { 'net.ipv4.conf.all.rp_filter':
      ensure  => present,
      value   => '1',
      comment => 'Setting managed by Puppet.',
    }
    sysctl { 'net.ipv4.conf.default.rp_filter':
      ensure  => present,
      value   => '1',
      comment => 'Setting managed by Puppet.',
    }
  }

  if $ipv4_secure_redirects == 'disabled' {
    sysctl { 'net.ipv4.conf.all.secure_redirects':
      ensure  => present,
      value   => '0',
      comment => 'Setting managed by Puppet.',
    }
    sysctl { 'net.ipv4.conf.default.secure_redirects':
      ensure  => present,
      value   => '0',
      comment => 'Setting managed by Puppet.',
    }
  }

  if $ipv4_source_routing == 'disabled' {
    sysctl { 'net.ipv4.conf.all.accept_source_route':
      ensure  => present,
      value   => '0',
      comment => 'Setting managed by Puppet.',
    }
    sysctl { 'net.ipv4.conf.default.accept_source_route':
      ensure  => present,
      value   => '0',
      comment => 'Setting managed by Puppet.',
    }
  }

  if $ipv4_tcp_syncookies == 'enabled' {
    sysctl { 'net.ipv4.tcp_syncookies':
      ensure  => present,
      value   => '1',
      comment => 'Setting managed by Puppet.',
    }
  }

  if $ipv6_accept_router_advertisements == 'disabled' {
    sysctl { 'net.ipv6.conf.all.accept_ra':
      ensure  => present,
      value   => '0',
      comment => 'Setting managed by Puppet.',
    }
    sysctl { 'net.ipv6.conf.default.accept_ra':
      ensure  => present,
      value   => '0',
      comment => 'Setting managed by Puppet.',
    }
  }

  if $ipv6_accept_packet_redirects == 'disabled' {
    sysctl { 'net.ipv6.conf.all.accept_redirects':
      ensure  => present,
      value   => '0',
      comment => 'Setting managed by Puppet.',
    }
    sysctl { 'net.ipv6.conf.default.accept_redirects':
      ensure  => present,
      value   => '0',
      comment => 'Setting managed by Puppet.',
    }
  }

  if $ipv6 == 'disabled' {
    file_line { 'ipv6':
      ensure => present,
      path   => '/etc/modprobe.d/CIS.conf',
      line   => 'options ipv6 disable=1',
    }
  }

  if $disable_wireless_interfaces == 'enabled' {
    $facts['networking']['interfaces'].each | String $interface, Hash $info | {
      if $interface =~ 'wlan' {
        exec { "ip link set ${interface} down":
          path => [ '/sbin', '/bin' ],
        }
      }
    }
  }

  if $hosts_allow != '' {
    file { '/etc/hosts.allow':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0644',
      source => $hosts_allow,
    }
  }

  if $hosts_deny != '' {
    file { '/etc/hosts.deny':
      ensure => file,
      owner  => 'root',
      group  => 'root',
      mode   => '0644',
      source => $hosts_deny,
    }
  }

}
