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
  $ldap_port        = hiera('opendj::ldap_port', '389'),
  $ldaps_port       = hiera('opendj::ldaps_port', '636'),
  $admin_port       = hiera('opendj::admin_port', '4444'),
  $repl_port        = hiera('opendj::repl_port', '8989'),
  $jmx_port         = hiera('opendj::jmx_port', '1689'),
  $admin_user       = hiera('opendj::admin_user', 'cn=Directory Manager'),
  $admin_password   = hiera('opendj::admin_password'),
  $base_dn          = hiera('opendj::base_dn', 'dc=example,dc=com'),
  $home             = hiera('opendj::home', '/opt/opendj'),
  $user             = hiera('opendj::user', 'opendj'),
  $group            = hiera('opendj::group', 'opendj'),
  $host             = hiera('opendj::host', $fqdn),
  $tmp              = hiera('opendj::tmpdir', '/tmp'),
  $master           = hiera('opendj::master', undef),
  $java_properties  = hiera('opendj::java_properties', undef),
  $packages         = hiera('opendj::packages', { 'opendj' => { 'ensure' => 'present', }, }),
  $config_options   = hiera('opendj::config_options', []),
) {

  $common_opts      = "-h localhost -D '${opendj::admin_user}' -w ${opendj::admin_password}"
  $ldapsearch       = "${opendj::home}/bin/ldapsearch ${common_opts} -p ${opendj::ldap_port}"
  $ldapmodify       = "${opendj::home}/bin/ldapmodify ${common_opts} -p ${opendj::ldap_port}"
  $dsconfig         = "${opendj::home}/bin/dsconfig ${common_opts} -p ${opendj::admin_port} -X -n"
  $dsreplication    = "${opendj::home}/bin/dsreplication --adminUID admin --adminPassword ${admin_password} -X -n"
# props_file Contains passwords, thus (temporarily) stored in /dev/shm
  $props_file       = "/dev/shm/opendj.properties"
  $base_dn_file     = "${tmp}/base_dn.ldif"
  $pkgs              = keys($packages)

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

  user { "${user}":
    ensure          => "present",
    gid             => $group,
    comment         => 'OpenDJ LDAP daemon',
    home            => "${opendj::home}",
    shell           => '/sbin/nologin',
    managehome      => true,
    require         => Package[ $pkgs ],
  } ->

  file { "${home}":
    ensure          => directory,
    owner           => $user,
    group           => $group,
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
    command         => "/bin/su opendj -s /bin/bash -c '${home}/setup -i -n -Q --acceptLicense --doNotStart --propertiesFilePath ${props_file}'",
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
    status          => "${home}/bin/status -D \"${admin_user}\" --bindPassword ${admin_password} | grep --quiet Started",
  }

  file_line { 'file_limits_soft':
    path            => '/etc/security/limits.conf',
    line            => '${user} soft nofile 65536',
    require         => User["${user}"],
    notify          => Service['opendj'],
  }

  file_line { 'file_limits_hard':
    path            => '/etc/security/limits.conf',
    line            => '${user} hard nofile 131072',
    require         => User["${user}"],
    notify          => Service['opendj'],
  }

### FIXME - rework to only create baseDN when first initiallizing the DIT
#  exec { "create base dn":
#    require         => File["${base_dn_file}"],
#    command         => "/bin/su ${user} -s /bin/bash -c \"${ldapmodify} -a -f '${base_dn_file}'\"",
#    refreshonly     => true,
#  }

  # $configopt should be of the form 'config-option:value[:--advanced]' where '[:--advanced]' is optional and
  # can actually be ANY valid dsconfig option(s), not just '--advanced'.
  define set_config_option ($configopt=$title) {
    validate_string($configopt)
    # UGLY pseudo-hash looping hack - if ONLY puppet would've implemented - oh, say - a f*cking FOREACH construct by f*cking version 3.4...!!!
    $opt            = split($configopt, ':')
    $o              = $opt[0]
    $v              = $opt[1]
    if size($opt) == 3 {
      $a            = $opt[2]
    } else {
      $a            = ''
    }
    exec { "set_${o}_to_${v}":
      require       => Service['opendj'],
      command       => "/bin/su ${user} -c '${dsconfig} ${a} set-global-configuration-prop --set ${o}:${v}}'",
      unless        => "/bin/su ${user} -c '${dsconfig} ${a} -s get-global-configuration-prop --property ${o} | fgrep -i ${v}'",
    }
  }

  set_config_option { $config_options }

#  exec { 'reject unauthenticated requests':
#    require       => Service['opendj'],
#    command       => "/bin/su ${user} -c '$dsconfig set-global-configuration-prop --set reject-unauthenticated-requests:true'",
#    unless        => "/bin/su ${user} -c '$dsconfig get-global-configuration-prop | grep reject-unauthenticated-requests | grep true'",
#  }

#  exec { "set single structural objectclass behavior":
#    command         => "${dsconfig} --advanced set-global-configuration-prop --set single-structural-objectclass-behavior:accept",
#    unless          => "${dsconfig} --advanced get-global-configuration-prop | grep 'single-structural-objectclass-behavior' | grep accept",
#    require         => Service['opendj'],
#  }

  if ($master != '' and $host != $master) {
    exec { "enable replication":
      require       => Service['opendj'],
      command       => "/bin/su ${user} -s /bin/bash -c \"$dsreplication enable --host1 ${master} --port1 ${admin_port} \
        --replicationPort1 ${repl_port} --bindDN1 '${admin_user}' --bindPassword1 ${admin_password} --host2 ${host} --port2 ${admin_port} \
        --replicationPort2 ${repl_port} --bindDN2 '${admin_user}' --bindPassword2 ${admin_password} --baseDN '${base_dn}'\"",
      unless        => "/bin/su ${user} -s /bin/bash -c \"$dsreplication status | grep ${host} | cut -d : -f 5 | grep true\"",
      notify        => Exec["initialize replication"]
    }

    exec { "initialize replication":
      command       => "/bin/su ${user} -s /bin/bash -c \"$dsreplication initialize -h ${master} -p ${admin_port} -O ${host} --baseDN '${base_dn}'\"",
      require       => Exec["enable replication"],
      refreshonly   => true,
    }
  }

  if !empty($java_properties) {
    validate_hash($java_properties)
    create_resources('opendj::java_property', $java_properties)

    exec { "apply java properties":
      command       => "/bin/su ${user} -s /bin/bash -c \"${home}/bin/dsjavaproperties\"",
      notify        => Service['opendj'],
    }
  }
}
