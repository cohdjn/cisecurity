# == Fact: cisecurity
#
# A custom fact that sets values needed by cisecurity
#
Facter.add("cisecurity") do
  require 'etc'

  # Figure out os-specific stuff up top
  if Facter.value(:puppetversion).to_i >= 4
    os_name = Facter.value(:os)[:name]
  else
    os_name = Facter.value(:operatingsystem)
  end

  cisecurity = {}
  cisecurity['efi'] = File.directory?('/sys/firmware/efi') ? true : false

  # accounts_with_blank_passwords
  cisecurity['accounts_with_blank_passwords'] = []
  File.readlines('/etc/shadow').collect do |line|
    if( line =~ /^(\w+)::/ )
      cisecurity['accounts_with_blank_passwords'].push($1)
    end
  end

  # accounts_with_uid_zero and system_accounts_with_valid_shell
  cisecurity['system_accounts_with_valid_shell'] = []
  cisecurity['accounts_with_uid_zero'] = []
  Etc.passwd do |entry|
    cisecurity['accounts_with_uid_zero'].push(entry.name) if entry.uid == 0
    unless entry.uid >= 1000 || ['root','sync','shutdown','halt'].include?(entry.name) || ['/sbin/nologin','/bin/false'].include?(entry.shell)
      cisecurity['system_accounts_with_valid_shell'].push(entry.name)
    end
  end

  # installed_packages
  cisecurity['installed_packages'] = {}
  packages = %x{rpm -qa --queryformat '[%{NAME}===%{VERSION}-%{RELEASE}\n]'}.split(/$/)
  if packages
    packages.each do |pkg|
      name, version = pkg.lstrip.split('===')
      cisecurity['installed_packages'][name] = version
    end
  end

  # package_system_file_variances
  cisecurity['package_system_file_variances'] = {}
  variances = %x{rpm -Va --nomtime --nosize --nomd5 --nolinkto}.split(/$/)
  if variances
    variances.each do |line|
       if( line =~ /^(\S+)\s+(c?)\s*(\/[\w\/\-\.]+)$/ )
        cisecurity['package_system_file_variances'][$3] = $1 if $2 != 'c'
      end
    end
  end

  # redhat_gpg_key_present
  gpg_keys = %x{rpm -q gpg-pubkey --qf '%{SUMMARY}\n' | grep 'release key'}
  gpgkey_mail = case os_name
  when 'CentOS'
    'security@centos.org'
  else
    'security@redhat.com'
  end
  cisecurity['redhat_gpg_key_present'] = gpg_keys.match(gpgkey_mail) ? true : false

  # root_path
  cisecurity['root_path'] = []
  ENV['PATH'].split(/:/).each do |path|
    cisecurity['root_path'].push(path)
  end

  # subscriptions
  cisecurity['subscriptions'] = {}
  if File.exists?('/usr/bin/subscription-manager')
    subs = %x{subscription-manager list}.split(/$/)[4,-1]
    if subs
      subs.each do |subscription|
        name, value = subscription.split(/:/)
        cisecurity['subscriptions'][ name.downcase.gsub(/\s/,'') ] = value.lstrip
      end
    end
  end

  # suid_sgid_files and ungrouped_files
  cisecurity['suid_sgid_files'] = []
  cisecurity['unowned_files'] = []
  cisecurity['ungrouped_files'] = []
  cisecurity['world_writable_files'] = []
  cisecurity['world_writable_dirs'] = []
  %x{df -l --exclude-type=tmpfs -P}.split(/$/).each do |fs|
    next if fs =~ /^Filesystem/ # header line
    root_path = fs.split[5]
    %x{find #{root_path} -xdev -nouser}.split(/$/).each do |line|
      cisecurity['unowned_files'].push(line.split[-1])
    end
    %x{find #{root_path} -xdev -nogroup}.split(/$/).each do |line|
      cisecurity['ungrouped_files'].push(line.split[-1])
    end
    %x{find #{root_path} -xdev -type f \\( -perm -4000 -o -perm -2000 \\)}.split(/$/).each do |line|
      cisecurity['suid_sgid_files'].push(line.split[-1])
    end
    %x{find #{root_path} -xdev -type f -perm -0002}.split(/$/).each do |line|
      cisecurity['world_writable_files'].push(line.split[-1])
    end
    %x{find #{root_path} -xdev -type d \\( -perm -0002 -a ! -perm -1000 \\)}.split(/$/).each do |line|
      cisecurity['world_writable_dirs'].push(line.split[-1])
    end
  end

  # unconfined_daemons
  cisecurity['unconfined_daemons'] = []
  %x{ps -eZ}.split(/$/).each do |line|
    next unless line =~ /initlc/
    cisecurity['unconfined_daemons'].push(line.split[-1])
  end

  # yum_enabled_repos
  cisecurity['yum_enabled_repos'] = []
  %x{yum repolist enabled}.split(/$/).each do |line|
    next if line =~ /^Loaded / || line =~ /^Loading / # headers
    next if line =~ /^repo id *repo name / # column header
    next if line =~ /^ \* / # mirror list
    next if line =~ /^repolist: / # footer
    cisecurity['yum_enabled_repos'].push(line.split[0])
  end

  # yum_repos_gpg_check_consistent
  disabled_gpg = system('grep gpgcheck /etc/yum.repos.d/*.repo | grep 0 > /dev/null')
  cisecurity['yum_repos_gpgcheck_consistent'] = disabled_gpg ? false : true

  setcode do
    cisecurity
  end
end
