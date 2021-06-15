## LibreGraph Identity Management

The idm daemon provides a LDAP server which is easy to configure, does not have external dependencies and is tailored to work perfectly with other LibreGraph software.

The goal is that everyone who does not already have or needs an LDAP server, uses idmd.

Thus, idmd is a (read-only) drop in replacement for an existing LDAP server and does provide an LDAP interface if none is there already.

Idmd supports LDAP search, bind and unbind.

### Configuration

The default base DN of idmd is `dc=lg,dc=local`. There is usually no need to change it if you don't use the LDAP data for anything else. The value needs to match what the clients have configured.

Similarly, the default mail domain is `lg.local`. Change it as needed in `/etc/libregraph/idmd.cfg` to match the SMTP setup.

idmd uses ldif files for its data source and those files are by default in the `/etc/libregraph/kidm/ldif` directory.

#### Add service user for LDAP access

By default, idmd does not have any users and anonymous bind is disabled. You can enable anonymous bind support for local requests in `idmd.cfg` or add a service user like this.

```bash
cat <<EOF > /etc/libregraph/kidm/ldif/config.ldif
dn: cn=readonly,{{.BaseDN}}
cn: readonly
description: LDAP read only service user
objectClass: simpleSecurityObject
objectClass: organizationalRole
userPassword: readonly
EOF
```

Afterwards reload idmd by running `systemctl reload libregraph-idmd`.

The `config.ldif` is for service users only and the data in there is used for bind requests only, but never returned for search requests.

#### Main configuration

The main directory data comes from the `main.d` folder. All `.ldif` files in there are loaded in lexical order and parsed as templates to create the data provided by the idmd LDAP endpoint.

Whenever any of the ldif files are changed, added or removed, make sure to reload idmd with `systemctl reload libregraph-idmd`.

idmd listens on `127.0.0.1:10389` by default and does not ship with any default users. Example configuration is installed (commented) and also available in the `/usr/share/doc/libregraph-idmd/examples` directory.

##### Add new users using the `gen newusers` command

idmd provides a way to create ldif data for new users using batch mode similar to the unix `newusers` command using the following standard password file format:

```bash
uid:userPassword:uidNumber:gidNumber:cn,[mail][,libregraphAliases...]:ignored:ignored
```

For example, like this:

```bash
cat << EOF | libregraph-idmd gen newusers - --min-password-strength=4 > /etc/libregraph/kidm/ldif/main.d/50-users.ldif
jonas:passwordOfJonas123:::Jonas Brekke,jonas@lg.local::
timmothy:passwordOfTimmothy456:::Timmothy Schöwalter::
EOF
```

This outputs an LDIF template file which you can modify as needed. When done run `systemctl reload libregraph-idmd` to make the new users available. Keep in mind that some of the attributes must be unique.

##### Quick start with demo users

To add standardize demo users the following command can be used (you might want to remove existing ldif configuration with `rm /etc/libregraph/idm/ldif/main.d/*.ldif` before generating the demo users to avoid conflicts).

```bash
/usr/share/libregraph-idmd/generate-demo-users-ldif > /etc/libregraph/idm/ldif/main.d/10-main.ldif
```

This script generates a ldif template, which uses the global configuration values for base DN and mail domain automatically.

##### Replace existing OpenLDAP with idmd

On the LDAP server export all its data using `slapcat` and write the resulting ldif to `/etc/libregraph/idm/ldif/main.d/10-main.ldif`. This is a drop in replacement and all what was in OpenLDAP is now also in idmd.

Either stop slapd and change the idmd configuration to listen where slapd used to listen or change the clients to connect to where idmd listens to migrate.

Assuming its all on the same server, this goes like this (you might want to remove existing ldif configuration with `rm /etc/libregraph/idm/ldif/main.d/*.ldif` before, to avoid conflicts).

```bash
slapcat > /etc/libregraph/idm/ldif/main.d/10-main.ldif
systemctl stop slapd
systemctl disable slapd
sed -i 's/^#ldap_listen = .*/ldap_listen = 127.0.0.1:389/' /etc/libregraph/idmd.cfg
systemctl restart libregraph-idmd
```

### Extra goodies

#### Template support

All ldif files loaded by kdidmd support template syntax as defined in https://golang.org/pkg/text/template to allow auto generation and replacement of various values. You can find example templates in the `/usr/share/doc/libregraph-idmd/examples/` directory as well. All the `gen` commands output template syntax if applicable.

#### Generate secure password hash using the `gen passwd` command

idmd supports secure password hashing using ARGON2. To create such password hashes either use `gen newusers` or the interactive `gen passwd` which is very similar to `slappasswd` from OpenLDAP.

```bash
libregraph-idmd gen passwd
New password:
Re-enter new password:
{ARGON2}$argon2id$v=19$m=65536,t=1,p=2$MaB5gX2BI484dATbGFyEIg$h2X8rbPowzZ/Exsz4W20Z/Zk54C30YnY+YbivSIRpcI
```

#### Test idmd

Since idmd provides a standard LDAP interface, also standard LDAP tools can be used to interact with it for testing. Run `apt install ldap-utils` to install LDAP commandline tools.

```bash
ldapsearch -x -H ldap://127.0.0.1:10389 -b "dc=lg,dc=local" -D "cn=readonly,dc=lg,dc=local" -w 'readonly'
```
