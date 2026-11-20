# Untitled integer in Configure StartConnect Schema

```txt
http://schema.nethserver.org/startconnect/configure-module-input.json#/properties/audit_retention_days
```

Days the activity log is kept

| Abstract            | Extensible | Status         | Identifiable            | Custom Properties | Additional Properties | Access Restrictions | Defined In                                                                                       |
| :------------------ | :--------- | :------------- | :---------------------- | :---------------- | :-------------------- | :------------------ | :----------------------------------------------------------------------------------------------- |
| Can be instantiated | No         | Unknown status | Unknown identifiability | Forbidden         | Allowed               | none                | [configure-module-input.json\*](startconnect/configure-module-input.json "open original schema") |

## audit_retention_days Type

`integer`

## audit_retention_days Constraints

**maximum**: the value of this number must smaller than or equal to: `3650`

**minimum**: the value of this number must greater than or equal to: `30`
