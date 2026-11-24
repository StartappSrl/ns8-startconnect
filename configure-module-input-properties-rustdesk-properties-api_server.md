# Untitled string in Configure StartConnect Schema

```txt
http://schema.nethserver.org/startconnect/configure-module-input.json#/properties/rustdesk/properties/api_server
```

rustdesk-api URL (HTTPS)

| Abstract            | Extensible | Status         | Identifiable            | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                       |
| :------------------ | :--------- | :------------- | :---------------------- | :---------------- | :-------------------- | :------------------ | :----------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | Unknown identifiability | Forbidden         | Allowed               | none                | [configure-module-input.json\*](startconnect/configure-module-input.json "open original schema") |

## api_server Type

`string`

## api_server Constraints

**maximum length**: the maximum number of characters for this string is: `255`

**pattern**: the string must match the following regular expression:&#x20;

```regexp
^(https://.+)?$
```

[try pattern](https://regexr.com/?expression=%5E\(https%3A%2F%2F.%2B\)%3F%24 "try regular expression with regexr.com")
