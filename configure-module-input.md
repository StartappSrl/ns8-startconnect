# Configure StartConnect Schema

```txt
http://schema.nethserver.org/startconnect/configure-module-input.json
```

Configure StartConnect

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                     |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :--------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [configure-module-input.json](startconnect/configure-module-input.json "open original schema") |

## Configure StartConnect Type

`object` ([Configure StartConnect](configure-module-input.md))

## Configure StartConnect Examples

```json
{
  "host": "connect.example.org",
  "http2https": true,
  "lets_encrypt": true,
  "ldap_domain": "ad.example.org",
  "admin_group": "domain admins",
  "rustdesk": {
    "id_server": "rustdesk.example.org",
    "api_server": "https://rustdesk.example.org",
    "key": "BASE64KEY=",
    "api_user": "startconnect-sync",
    "api_password": "secret"
  }
}
```

# Configure StartConnect Properties

| Property                                      | Type      | Required | Nullable       | Defined by                                                                                                                                                                                   |
| :-------------------------------------------- | :-------- | :------- | :------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [host](#host)                                 | `string`  | Required | cannot be null | [Configure StartConnect](configure-module-input-properties-host.md "http://schema.nethserver.org/startconnect/configure-module-input.json#/properties/host")                                 |
| [lets_encrypt](#lets_encrypt)                 | `boolean` | Optional | cannot be null | [Configure StartConnect](configure-module-input-properties-lets_encrypt.md "http://schema.nethserver.org/startconnect/configure-module-input.json#/properties/lets_encrypt")                 |
| [http2https](#http2https)                     | `boolean` | Optional | cannot be null | [Configure StartConnect](configure-module-input-properties-http2https.md "http://schema.nethserver.org/startconnect/configure-module-input.json#/properties/http2https")                     |
| [ldap_domain](#ldap_domain)                   | `string`  | Required | cannot be null | [Configure StartConnect](configure-module-input-properties-ldap_domain.md "http://schema.nethserver.org/startconnect/configure-module-input.json#/properties/ldap_domain")                   |
| [admin_group](#admin_group)                   | `string`  | Optional | cannot be null | [Configure StartConnect](configure-module-input-properties-admin_group.md "http://schema.nethserver.org/startconnect/configure-module-input.json#/properties/admin_group")                   |
| [audit_retention_days](#audit_retention_days) | `integer` | Optional | cannot be null | [Configure StartConnect](configure-module-input-properties-audit_retention_days.md "http://schema.nethserver.org/startconnect/configure-module-input.json#/properties/audit_retention_days") |
| [rustdesk](#rustdesk)                         | `object`  | Optional | cannot be null | [Configure StartConnect](configure-module-input-properties-rustdesk.md "http://schema.nethserver.org/startconnect/configure-module-input.json#/properties/rustdesk")                         |

## host

Fully qualified domain name of the StartConnect server

`host`

* is required

* Type: `string`

* cannot be null

* defined in: [Configure StartConnect](configure-module-input-properties-host.md "http://schema.nethserver.org/startconnect/configure-module-input.json#/properties/host")

### host Type

`string`

### host Constraints

**(international) hostname**: the string must be an (IDN) hostname, according to [RFC 5890, section 2.3.2.3](https://tools.ietf.org/html/rfc5890 "check the specification")

## lets_encrypt

Request a Let's Encrypt certificate

`lets_encrypt`

* is optional

* Type: `boolean`

* cannot be null

* defined in: [Configure StartConnect](configure-module-input-properties-lets_encrypt.md "http://schema.nethserver.org/startconnect/configure-module-input.json#/properties/lets_encrypt")

### lets_encrypt Type

`boolean`

## http2https

Redirect HTTP requests to HTTPS

`http2https`

* is optional

* Type: `boolean`

* cannot be null

* defined in: [Configure StartConnect](configure-module-input-properties-http2https.md "http://schema.nethserver.org/startconnect/configure-module-input.json#/properties/http2https")

### http2https Type

`boolean`

## ldap_domain

NS8 user domain used to authenticate StartConnect users

`ldap_domain`

* is required

* Type: `string`

* cannot be null

* defined in: [Configure StartConnect](configure-module-input-properties-ldap_domain.md "http://schema.nethserver.org/startconnect/configure-module-input.json#/properties/ldap_domain")

### ldap_domain Type

`string`

### ldap_domain Constraints

**minimum length**: the minimum number of characters for this string is: `1`

## admin_group

Members of this group manage every folder, connection and permission

`admin_group`

* is optional

* Type: `string`

* cannot be null

* defined in: [Configure StartConnect](configure-module-input-properties-admin_group.md "http://schema.nethserver.org/startconnect/configure-module-input.json#/properties/admin_group")

### admin_group Type

`string`

### admin_group Constraints

**minimum length**: the minimum number of characters for this string is: `1`

## audit_retention_days

Days the activity log is kept

`audit_retention_days`

* is optional

* Type: `integer`

* cannot be null

* defined in: [Configure StartConnect](configure-module-input-properties-audit_retention_days.md "http://schema.nethserver.org/startconnect/configure-module-input.json#/properties/audit_retention_days")

### audit_retention_days Type

`integer`

### audit_retention_days Constraints

**maximum**: the value of this number must smaller than or equal to: `3650`

**minimum**: the value of this number must greater than or equal to: `30`

## rustdesk

RustDesk server whose devices are listed in StartConnect (optional)

`rustdesk`

* is optional

* Type: `object` ([Details](configure-module-input-properties-rustdesk.md))

* cannot be null

* defined in: [Configure StartConnect](configure-module-input-properties-rustdesk.md "http://schema.nethserver.org/startconnect/configure-module-input.json#/properties/rustdesk")

### rustdesk Type

`object` ([Details](configure-module-input-properties-rustdesk.md))
