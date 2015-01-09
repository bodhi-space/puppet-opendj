#   == Class: opendj
#
# Module for deployment and configuration of ForgeRock OpenDJ.
#
#   === Authors
#
# Eivind Mikkelsen <eivindm@conduct.no>
#
#   === Copyright
#
# Copyright (c) 2013 Conduct AS
#

class opendj (
  $ldap_port          = hiera('opendj::ldap_port', '1389'),
  $ldaps_port         = hiera('opendj::ldaps_port', '1636'),
  $admin_port         = hiera('opendj::admin_port', '4444'),
  $repl_port          = hiera('opendj::repl_port', '8989'),
  $jmx_port           = hiera('opendj::jmx_port', '1689'),
  $admin_user         = hiera('opendj::admin_user', 'cn=Directory Manager'),
  $admin_password     = hiera('opendj::admin_password'),
  $admin_pass_file    = hiera('opendj::admin_pass_file', ''),
  $base_dn            = hiera('opendj::base_dn', 'dc=example,dc=com'),
  $home               = hiera('opendj::home', '/opt/opendj'),
  $user               = hiera('opendj::user', 'opendj'),
  $group              = hiera('opendj::group', 'opendj'),
  $manage_user        = hiera('opendj::manage_user', true),
  $host               = hiera('opendj::host', $::fqdn),
  $tmp                = hiera('opendj::tmpdir', '/tmp'),
  $packages           = hiera('opendj::packages', { 'opendj' => { 'ensure' => 'present', }, 'jre' => { 'ensure' => 'present', }, }),
  $enable_tls         = hiera('opendj::enable_tls', true),
  $pkcs12_keystore    = hiera('opendj::pkcs12_keystore', ''),
  $pkcs12_keydata     = hiera('opendj::pkcs12_keydata', ''),
  $keystore_pass      = hiera('opendj::keystore_pass', undef),
  $keystore_pass_file = hiera('opendj::keystore_pass_file', ''),
  $config_options     = hiera('opendj::config_options', {}),
  $global_acis        = hiera('opendj::global_acis', {}),
  $ldiffile           = hiera('opendj::ldiffile', ''),
  $custom_schemas     = hiera('opendj::schemas', {}),
  $master             = hiera('opendj::master', undef),
  $java_properties    = hiera('opendj::java_properties', undef),
) {

  if $admin_pass_file == '' {
    $passwd_data      = "-w \"${admin_password}\""
    $oldap_passwd_data = "-w \"${admin_password}\""
  } else {
    $passwd_data      = "-j \"${admin_pass_file}\""
    $oldap_passwd_data = "-y \"${admin_pass_file}\""
  }
  if $enable_tls {
    $starttls         = '-ZZ'
  } else {
    $starttls         = ''
  }
  if "$ldap_port" != "389" {
    $port             = ":$ldap_port"
  } else {
    $port             = ''
  }
  $common_opts        = "-h localhost -D \"${admin_user}\" ${passwd_data}"
  $oldap_common_opts  = "-x ${starttls} -H ldap://${host}${port}/ -D \"${admin_user}\" $oldap_passwd_data"
  $status             = "${home}/bin/status -D \"${admin_user}\" ${passwd_data}"
  # OpenDJ ldapsearch does not work for me for some reason - we'll use OpenLDAP's instead
  $ldapsearch         = "/usr/bin/ldapsearch -LLL ${oldap_common_opts} -p ${ldap_port}"
  $ldapmodify         = "${home}/bin/ldapmodify ${common_opts} -p ${ldap_port}"
  $dsconfig           = "${home}/bin/dsconfig ${common_opts} -p ${admin_port} -X -n"
  $dsreplication      = "${home}/bin/dsreplication --adminUID admin ${passwd_data} -X -n"
  # props_file contains passwords, thus (temporarily) stored in /dev/shm
  $props_file         = "/dev/shm/opendj.properties"

  # XXX for the moment, we make no effort to ensure the parent directories exist...
  # If you don't like this, then bump the (over 9 years old and counting) ticket on the
  # PuppetLabs tracker requesting 'mkdir -p' functionality... http://projects.puppetlabs.com/issues/86
  if $admin_pass_file != '' {
    file { "${admin_pass_file}":
      ensure          => file,
      owner           => $user,
      group           => $group,
      mode            => 0600,
      content         => "$admin_password",
      before          => Exec['configure opendj'],
    }
  }
  if $keystore_pass_file != '' {
    file { "${keystore_pass_file}":
      ensure          => file,
      owner           => $user,
      group           => $group,
      mode            => 0600,
      content         => "$keystore_pass",
      before          => Exec['configure opendj'],
    }
  }
  # If $pkcs12_keydata is NOT populated, then you MUST put the keystore in place by hand before applying this module.
  if $pkcs12_keystore != '' {
    if $pkcs12_keydata  != ''{
      $keystore_dir     = dirname("${pkcs12_keystore}")
      file { "${keystore_dir}":
        ensure          => directory,
        owner           => $user,
        group           => $group,
        mode            => 0700,
      }
      file { "${pkcs12_keystore}":
        ensure          => file,
        owner           => $user,
        group           => $group,
        mode            => 0600,
        content         => "${pkcs12_keydata}",
        before          => Exec['configure opendj'],
      }
    }
  }

  validate_hash($packages)
  define force_package($package=$title, $ensure=$ensure) {
    validate_string ($package)
    validate_string ($ensure)
    package { "$package":
      ensure          => "$ensure",
    }
  }

  create_resources(force_package, $packages)

  group { "${group}":
    ensure            => "present",
  }

  if $manage_user {
    user { "${user}":
      ensure          => "present",
      gid             => $group,
      comment         => 'OpenDJ LDAP daemon user',
      home            => "${home}",
      shell           => '/sbin/nologin',
      managehome      => true,
      require         => Package[ keys($packages) ],
      before          => File[ "${home}" ],
    }
  }

  file { "${home}":
    ensure            => directory,
    owner             => $user,
    group             => $group,
    require           => Package[ keys($packages) ],
  } ->

  file { "${props_file}":
    ensure            => file,
    content           => template("${module_name}/setup.erb"),
    owner             => $user,
    group             => $group,
    mode              => 0600,
  } ~>

  exec { "configure opendj":
    command           => "/bin/su ${user} -s /bin/sh -c '${home}/setup --acceptLicense --propertiesFilePath ${props_file}'",
    creates           => "${home}/config",
  } ~>

  exec { "create RC script":
    command           => "${home}/bin/create-rc-script --userName ${user} --outputFile /etc/init.d/opendj",
    creates           => "/etc/init.d/opendj",
  } ~>

  service { 'opendj':
    enable            => true,
    ensure            => running,
    hasrestart        => true,
    hasstatus         => false,
    status            => "${status} | fgrep -qw Started",
  }

  if $manage_user {
    file_line { 'file_limits_soft':
      path            => '/etc/security/limits.conf',
      line            => "${user} soft nofile 65536",
      require         => User["${user}"],
      notify          => Service['opendj'],
    }
    file_line { 'file_limits_hard':
      path            => '/etc/security/limits.conf',
      line            => "${user} hard nofile 131072",
      require         => User["${user}"],
      notify          => Service['opendj'],
    }
  }

  # Now install any custom schemas defined in hiera
  validate_hash($custom_schemas)
  define install_schema_file($filename=$title, $content=$content) {
    file { "$filename":
      content         => "$content",
      notify          => Service['opendj'],
    }
  }

  create_resources (install_schema_file, $custom_schemas)

  # Default values - hacky way of passing in global variables since define()s can't see surrounding scope :-/
  Opendj::Config_option {
    dsconfig          => $dsconfig,
    user              => $user,
  }

  # 'extra_opts' can be any valid dsconfig option(s) - the most common use is to pass in '--advanced' for those opts which require it...
  define config_option ($myopt=$title, $configopt='', $configclass='global-configuration', $details='', $value=$value, $extra_opts='', $dsconfig, $user) {
    validate_string($myopt)
    # By default the config option name will be directly in $title, but since hashes can't have duplicate keys, and
    # sometimes we need to create more than one setting with the same opt name, we provide a back-door variable to send another...
    validate_string($configopt)
    validate_string($configclass)
    validate_string($details)
    validate_string($value)
    validate_string($extra_opts)
    if $configopt != '' {
      $opt            = "$configopt"
    } else {
      $opt            = "$myopt"
    }
    if $details != '' {
      $mytitle        = "set_${configclass}_${details}_${opt}_to_${value}"
    } else {
      $mytitle        = "set_${configclass}_${opt}_to_${value}"
    }
    exec { "${mytitle}":
      require         => Service['opendj'],
      command         => "/bin/su ${user} -c '${dsconfig} ${extra_opts} set-${configclass}-prop ${details} --set ${opt}:${value}'",
      unless          => "/bin/su ${user} -c '${dsconfig} ${extra_opts} -s get-${configclass}-prop ${details} --property ${opt} | fgrep -q \"${value}\"'",
    }
  }

  create_resources (config_option, $config_options)

  Opendj::Set_aci {
    dsconfig          => $dsconfig,
    user              => $user,
    ldapsearch        => $ldapsearch,
    schema_deps       => keys($custom_schemas),
  }

  # Wanted to work this into the above config_option() logic but had to use OpenLDAP ldapsearch for 'unless' check
  # instead of either OpenDJ's dsconfig or ldapsearch.  $operation must be one of 'add' or 'remove'.
  define set_aci ($description=$title, $operation='add', $scope='global-aci', $aci=$aci, $dsconfig, $user, $ldapsearch, $schema_deps) {
    # ACIs must have a unique description tag - leverage that for our hash
    validate_string($description)
    validate_string($operation)
    validate_string($scope)
    validate_string($aci)
    $reqs               = [ Service['opendj'], File[$schema_deps], ]
    $cmd                = "/bin/su ${user} -c '${dsconfig} set-access-control-handler-prop --${operation} ${scope}:${aci}'"
    $test               = "${ldapsearch} -b '${bdn}' '(ds-cfg-${scope}=*${description}*)' ds-cfg-${scope} | sed ':a;/^[^ ]/{N;s/\n //;ba}' | fgrep -q '${aci}'"
    $nam                = "${operation}_${scope}_aci_${description}"
    $bdn                = 'cn=Access Control Handler,cn=config'
    if $operation == 'add' {
      exec { "${nam}":
        require         => $reqs,
        command         => $cmd,
        unless          => $test,
      }
    } else {
      exec { "${nam}":
        require         => $reqs,
        command         => $cmd,
        onlyif          => $test,
      }
    }
  }

  create_resources (set_aci, $global_acis)

  if ($master != '' and $host != $master) {
    exec { "enable replication":
      require         => [ Service['opendj'], File[keys($custom_schemas)], ],
      command         => "/bin/su ${user} -s /bin/sh -c \"${dsreplication} enable --baseDN '${base_dn}' \
          --host1 ${master} --port1 ${admin_port} --replicationPort1 ${repl_port} \
          --host2 ${host}   --port2 ${admin_port} --replicationPort2 ${repl_port} \"",
      unless          => "/bin/su ${user} -s /bin/sh -c '$dsreplication status | fgrep ${host} | cut -d : -f 5 | fgrep true'",
      notify          => Exec["initialize replication"],
    }

    exec { "initialize replication":
      command         => "/bin/su ${user} -s /bin/sh -c \"$dsreplication initialize -h ${master} -p ${admin_port} -O ${host} --baseDN '${base_dn}'\"",
      require         => Exec["enable replication"],
      refreshonly     => true,
    }
  }

  if !empty($java_properties) {
    validate_hash($java_properties)
    create_resources('opendj::java_property', $java_properties)

    exec { "apply java properties":
      command         => "/bin/su ${user} -s /bin/sh -c '${home}/bin/dsjavaproperties'",
      notify          => Service['opendj'],
    }
  }
}
