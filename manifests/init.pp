# == Class: opendj
#
# Module for deployment and configuration of ForgeRock OpenDJ.
#
# === Authors
#
# Eivind Mikkelsen <eivindm@conduct.no>
#
# === Copyright
#
# Copyright (c) 2013 Conduct AS
#

class opendj (
  $ldap_port        = hiera('opendj::ldap_port', '1389'),
  $ldaps_port       = hiera('opendj::ldaps_port', '1636'),
  $admin_port       = hiera('opendj::admin_port', '4444'),
  $repl_port        = hiera('opendj::repl_port', '8989'),
  $jmx_port         = hiera('opendj::jmx_port', '1689'),
  $admin_user       = hiera('opendj::admin_user', 'cn=Directory Manager'),
  $admin_password   = hiera('opendj::admin_password'),
  $base_dn          = hiera('opendj::base_dn', 'dc=example,dc=com'),
  $home             = hiera('opendj::home', '/opt/opendj'),
  $user             = hiera('opendj::user', 'opendj'),
  $group            = hiera('opendj::group', 'opendj'),
  $manage_user      = hiera('opendj::manage_user', true),
  $host             = hiera('opendj::host', $fqdn),
  $tmp              = hiera('opendj::tmpdir', '/tmp'),
  $master           = hiera('opendj::master', undef),
  $java_properties  = hiera('opendj::java_properties', undef),
  $packages         = hiera('opendj::packages', { 'opendj' => { 'ensure' => 'present', }, 'jre' => { 'ensure' => 'present', }, }),
  $config_options   = hiera('opendj::config_options', {}),
) {

  $common_opts      = "-h localhost -D '${admin_user}' -w ${admin_password}"
  $ldapsearch       = "${home}/bin/ldapsearch ${common_opts} -p ${ldap_port}"
  $ldapmodify       = "${home}/bin/ldapmodify ${common_opts} -p ${ldap_port}"
  $dsconfig         = "${home}/bin/dsconfig ${common_opts} -p ${admin_port} -X -n"
  $dsreplication    = "${home}/bin/dsreplication --adminUID admin --adminPassword ${admin_password} -X -n"
# props_file Contains passwords, thus (temporarily) stored in /dev/shm
  $props_file       = "/dev/shm/opendj.properties"
  $base_dn_file     = "${tmp}/base_dn.ldif"
  $pkgs             = keys($packages)

  validate_hash($packages)
  define force_package($package=$title, $ensure=$ensure) {
    validate_string ($package)
    validate_string ($ensure)
    package { "$package":
      ensure        => "$ensure",
    }
  }

  create_resources(force_package, $packages)

  group { "${group}":
    ensure          => "present",
  }

  if $manage_user {
    user { "${user}":
      ensure        => "present",
      gid           => $group,
      comment       => 'OpenDJ LDAP daemon user',
      home          => "${home}",
      shell         => '/sbin/nologin',
      managehome    => true,
      require       => Package[ $pkgs ],
      before        => File[ "${home}" ],
    }
  }

  file { "${home}":
    ensure          => directory,
    owner           => $user,
    group           => $group,
    require         => Package[ $pkgs ],
  } ->

  file { "${base_dn_file}":
    ensure          => file,
    content         => template("${module_name}/base_dn.ldif.erb"),
    owner           => $user,
    group           => $group,
    mode            => 0600,
  } ->

  file { "${props_file}":
    ensure          => file,
    content         => template("${module_name}/setup.erb"),
    owner           => $user,
    group           => $group,
    mode            => 0600,
  } ~>

  exec { "configure opendj":
    command         => "/bin/su ${user} -s /bin/sh -c '${home}/setup -i -n -Q --acceptLicense --doNotStart --propertiesFilePath ${props_file}'",
    creates         => "${home}/config",
  } ~>

  exec { "create RC script":
    command         => "${home}/bin/create-rc-script --userName ${user} --outputFile /etc/init.d/opendj",
    creates         => "/etc/init.d/opendj",
  } ~>

  service { 'opendj':
    enable          => true,
    ensure          => running,
    hasrestart      => true,
    hasstatus       => false,
    status          => "${home}/bin/status -D '${admin_user}' --bindPassword '${admin_password}' | fgrep -qw Started",
  }

  if $manage_user {
    file_line { 'file_limits_soft':
      path          => '/etc/security/limits.conf',
      line          => "${user} soft nofile 65536",
      require       => User["${user}"],
      notify        => Service['opendj'],
    }
    file_line { 'file_limits_hard':
      path          => '/etc/security/limits.conf',
      line          => "${user} hard nofile 131072",
      require       => User["${user}"],
      notify        => Service['opendj'],
    }
  }

### FIXME - rework to only create baseDN when first initiallizing the DIT
#  exec { "create base dn":
#    require         => File["${base_dn_file}"],
#    command         => "/bin/su ${user} -s /bin/sh -c \"${ldapmodify} -a -f '${base_dn_file}'\"",
#    refreshonly     => true,
#  }

  define config_option ($configopt=$title, $value=$value, $extra_opts='') {
    validate_string($configopt)
    validate_string($value)
    validate_string($extra_opts)
    exec { "set_${configopt}_to_${value}":
      require       => Service['opendj'],
      command       => "/bin/su ${user} -c '${dsconfig} ${extra_opts} set-global-configuration-prop --set ${configopt}:${value}'",
      unless        => "/bin/su ${user} -c '${dsconfig} ${extra_opts} -s get-global-configuration-prop --property ${configopt} | fgrep ${value}'",
    }
  }

  create_resources (config_option, $config_options)

#  exec { 'reject unauthenticated requests':
#    require       => Service['opendj'],
#    command       => "/bin/su ${user} -c '$dsconfig set-global-configuration-prop --set reject-unauthenticated-requests:true'",
#    unless        => "/bin/su ${user} -c '$dsconfig get-global-configuration-prop | fgrep reject-unauthenticated-requests | fgrep true'",
#  }

#  exec { "set single structural objectclass behavior":
#    command         => "${dsconfig} --advanced set-global-configuration-prop --set single-structural-objectclass-behavior:accept",
#    unless          => "${dsconfig} --advanced get-global-configuration-prop | fgrep 'single-structural-objectclass-behavior' | fgrep accept",
#    require         => Service['opendj'],
#  }

  if ($master != '' and $host != $master) {
    exec { "enable replication":
      require       => Service['opendj'],
      command       => "/bin/su ${user} -s /bin/sh -c \"$dsreplication enable --host1 ${master} --port1 ${admin_port} \
        --replicationPort1 ${repl_port} --bindDN1 '${admin_user}' --bindPassword1 ${admin_password} --host2 ${host} --port2 ${admin_port} \
        --replicationPort2 ${repl_port} --bindDN2 '${admin_user}' --bindPassword2 ${admin_password} --baseDN '${base_dn}'\"",
      unless        => "/bin/su ${user} -s /bin/sh -c '$dsreplication status | fgrep ${host} | cut -d : -f 5 | fgrep true'",
      notify        => Exec["initialize replication"]
    }

    exec { "initialize replication":
      command       => "/bin/su ${user} -s /bin/sh -c \"$dsreplication initialize -h ${master} -p ${admin_port} -O ${host} --baseDN '${base_dn}'\"",
      require       => Exec["enable replication"],
      refreshonly   => true,
    }
  }

  if !empty($java_properties) {
    validate_hash($java_properties)
    create_resources('opendj::java_property', $java_properties)

    exec { "apply java properties":
      command       => "/bin/su ${user} -s /bin/sh -c '${home}/bin/dsjavaproperties'",
      notify        => Service['opendj'],
    }
  }
}
