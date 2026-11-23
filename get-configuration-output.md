# get-configuration output Schema

```txt
http://schema.nethserver.org/startconnect/get-configuration-output.json
```

Get StartConnect configuration

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                         |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :------------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Allowed               | none                | [get-configuration-output.json](startconnect/get-configuration-output.json "open original schema") |

## get-configuration output Type

`object` ([get-configuration output](get-configuration-output.md))

# get-configuration output Properties

| Property                                      | Type      | Required | Nullable       | Defined by                                                                                                                                                                                         |
| :-------------------------------------------- | :-------- | :------- | :------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [host](#host)                                 | `string`  | Optional | cannot be null | [get-configuration output](get-configuration-output-properties-host.md "http://schema.nethserver.org/startconnect/get-configuration-output.json#/properties/host")                                 |
| [http2https](#http2https)                     | `boolean` | Optional | cannot be null | [get-configuration output](get-configuration-output-properties-http2https.md "http://schema.nethserver.org/startconnect/get-configuration-output.json#/properties/http2https")                     |
| [lets_encrypt](#lets_encrypt)                 | `boolean` | Optional | cannot be null | [get-configuration output](get-configuration-output-properties-lets_encrypt.md "http://schema.nethserver.org/startconnect/get-configuration-output.json#/properties/lets_encrypt")                 |
| [ldap_domain](#ldap_domain)                   | `string`  | Optional | cannot be null | [get-configuration output](get-configuration-output-properties-ldap_domain.md "http://schema.nethserver.org/startconnect/get-configuration-output.json#/properties/ldap_domain")                   |
| [admin_group](#admin_group)                   | `string`  | Optional | cannot be null | [get-configuration output](get-configuration-output-properties-admin_group.md "http://schema.nethserver.org/startconnect/get-configuration-output.json#/properties/admin_group")                   |
| [audit_retention_days](#audit_retention_days) | `integer` | Optional | cannot be null | [get-configuration output](get-configuration-output-properties-audit_retention_days.md "http://schema.nethserver.org/startconnect/get-configuration-output.json#/properties/audit_retention_days") |
| [domains_list](#domains_list)                 | `array`   | Optional | cannot be null | [get-configuration output](get-configuration-output-properties-domains_list.md "http://schema.nethserver.org/startconnect/get-configuration-output.json#/properties/domains_list")                 |
| [rustdesk](#rustdesk)                         | `object`  | Optional | cannot be null | [get-configuration output](get-configuration-output-properties-rustdesk.md "http://schema.nethserver.org/startconnect/get-configuration-output.json#/properties/rustdesk")                         |

## host



`host`

* is optional

* Type: `string`

* cannot be null

* defined in: [get-configuration output](get-configuration-output-properties-host.md "http://schema.nethserver.org/startconnect/get-configuration-output.json#/properties/host")

### host Type

`string`

## http2https



`http2https`

* is optional

* Type: `boolean`

* cannot be null

* defined in: [get-configuration output](get-configuration-output-properties-http2https.md "http://schema.nethserver.org/startconnect/get-configuration-output.json#/properties/http2https")

### http2https Type

`boolean`

## lets_encrypt



`lets_encrypt`

* is optional

* Type: `boolean`

* cannot be null

* defined in: [get-configuration output](get-configuration-output-properties-lets_encrypt.md "http://schema.nethserver.org/startconnect/get-configuration-output.json#/properties/lets_encrypt")

### lets_encrypt Type

`boolean`

## ldap_domain



`ldap_domain`

* is optional

* Type: `string`

* cannot be null

* defined in: [get-configuration output](get-configuration-output-properties-ldap_domain.md "http://schema.nethserver.org/startconnect/get-configuration-output.json#/properties/ldap_domain")

### ldap_domain Type

`string`

## admin_group



`admin_group`

* is optional

* Type: `string`

* cannot be null

* defined in: [get-configuration output](get-configuration-output-properties-admin_group.md "http://schema.nethserver.org/startconnect/get-configuration-output.json#/properties/admin_group")

### admin_group Type

`string`

## audit_retention_days



`audit_retention_days`

* is optional

* Type: `integer`

* cannot be null

* defined in: [get-configuration output](get-configuration-output-properties-audit_retention_days.md "http://schema.nethserver.org/startconnect/get-configuration-output.json#/properties/audit_retention_days")

### audit_retention_days Type

`integer`

## domains_list



`domains_list`

* is optional

* Type: `array`

* cannot be null

* defined in: [get-configuration output](get-configuration-output-properties-domains_list.md "http://schema.nethserver.org/startconnect/get-configuration-output.json#/properties/domains_list")

### domains_list Type

`array`

## rustdesk



`rustdesk`

* is optional

* Type: `object` ([Details](get-configuration-output-properties-rustdesk.md))

* cannot be null

* defined in: [get-configuration output](get-configuration-output-properties-rustdesk.md "http://schema.nethserver.org/startconnect/get-configuration-output.json#/properties/rustdesk")

### rustdesk Type

`object` ([Details](get-configuration-output-properties-rustdesk.md))
