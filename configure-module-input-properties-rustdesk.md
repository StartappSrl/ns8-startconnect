# Untitled object in Configure StartConnect Schema

```txt
http://schema.nethserver.org/startconnect/configure-module-input.json#/properties/rustdesk
```

RustDesk server whose devices are listed in StartConnect (optional)

| Abstract            | Extensible | Status         | Identifiable | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                       |
| :------------------ | :--------- | :------------- | :----------- | :---------------- | :-------------------- | :------------------ | :----------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | No           | Forbidden         | Forbidden             | none                | [configure-module-input.json\*](startconnect/configure-module-input.json "open original schema") |

## rustdesk Type

`object` ([Details](configure-module-input-properties-rustdesk.md))

# rustdesk Properties

| Property                      | Type     | Required | Nullable       | Defined by                                                                                                                                                                                                           |
| :---------------------------- | :------- | :------- | :------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [id_server](#id_server)       | `string` | Optional | cannot be null | [Configure StartConnect](configure-module-input-properties-rustdesk-properties-id_server.md "http://schema.nethserver.org/startconnect/configure-module-input.json#/properties/rustdesk/properties/id_server")       |
| [relay_server](#relay_server) | `string` | Optional | cannot be null | [Configure StartConnect](configure-module-input-properties-rustdesk-properties-relay_server.md "http://schema.nethserver.org/startconnect/configure-module-input.json#/properties/rustdesk/properties/relay_server") |
| [api_server](#api_server)     | `string` | Optional | cannot be null | [Configure StartConnect](configure-module-input-properties-rustdesk-properties-api_server.md "http://schema.nethserver.org/startconnect/configure-module-input.json#/properties/rustdesk/properties/api_server")     |
| [key](#key)                   | `string` | Optional | cannot be null | [Configure StartConnect](configure-module-input-properties-rustdesk-properties-key.md "http://schema.nethserver.org/startconnect/configure-module-input.json#/properties/rustdesk/properties/key")                   |
| [api_user](#api_user)         | `string` | Optional | cannot be null | [Configure StartConnect](configure-module-input-properties-rustdesk-properties-api_user.md "http://schema.nethserver.org/startconnect/configure-module-input.json#/properties/rustdesk/properties/api_user")         |
| [api_password](#api_password) | `string` | Optional | cannot be null | [Configure StartConnect](configure-module-input-properties-rustdesk-properties-api_password.md "http://schema.nethserver.org/startconnect/configure-module-input.json#/properties/rustdesk/properties/api_password") |

## id_server

ID server (host or host:port) used by RustDesk clients

`id_server`

* is optional

* Type: `string`

* cannot be null

* defined in: [Configure StartConnect](configure-module-input-properties-rustdesk-properties-id_server.md "http://schema.nethserver.org/startconnect/configure-module-input.json#/properties/rustdesk/properties/id_server")

### id_server Type

`string`

### id_server Constraints

**maximum length**: the maximum number of characters for this string is: `255`

## relay_server

Relay server; empty = same as id_server

`relay_server`

* is optional

* Type: `string`

* cannot be null

* defined in: [Configure StartConnect](configure-module-input-properties-rustdesk-properties-relay_server.md "http://schema.nethserver.org/startconnect/configure-module-input.json#/properties/rustdesk/properties/relay_server")

### relay_server Type

`string`

### relay_server Constraints

**maximum length**: the maximum number of characters for this string is: `255`

## api_server

rustdesk-api URL (HTTPS)

`api_server`

* is optional

* Type: `string`

* cannot be null

* defined in: [Configure StartConnect](configure-module-input-properties-rustdesk-properties-api_server.md "http://schema.nethserver.org/startconnect/configure-module-input.json#/properties/rustdesk/properties/api_server")

### api_server Type

`string`

### api_server Constraints

**maximum length**: the maximum number of characters for this string is: `255`

**pattern**: the string must match the following regular expression:&#x20;

```regexp
^(https://.+)?$
```

[try pattern](https://regexr.com/?expression=%5E\(https%3A%2F%2F.%2B\)%3F%24 "try regular expression with regexr.com")

## key

Public key of the RustDesk server (id_ed25519.pub)

`key`

* is optional

* Type: `string`

* cannot be null

* defined in: [Configure StartConnect](configure-module-input-properties-rustdesk-properties-key.md "http://schema.nethserver.org/startconnect/configure-module-input.json#/properties/rustdesk/properties/key")

### key Type

`string`

### key Constraints

**maximum length**: the maximum number of characters for this string is: `128`

## api_user

rustdesk-api administrator used to read the device list

`api_user`

* is optional

* Type: `string`

* cannot be null

* defined in: [Configure StartConnect](configure-module-input-properties-rustdesk-properties-api_user.md "http://schema.nethserver.org/startconnect/configure-module-input.json#/properties/rustdesk/properties/api_user")

### api_user Type

`string`

### api_user Constraints

**maximum length**: the maximum number of characters for this string is: `128`

## api_password

Password of api_user; omit to keep the current one

`api_password`

* is optional

* Type: `string`

* cannot be null

* defined in: [Configure StartConnect](configure-module-input-properties-rustdesk-properties-api_password.md "http://schema.nethserver.org/startconnect/configure-module-input.json#/properties/rustdesk/properties/api_password")

### api_password Type

`string`

### api_password Constraints

**maximum length**: the maximum number of characters for this string is: `512`
