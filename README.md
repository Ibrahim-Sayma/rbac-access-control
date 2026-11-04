# Role-Based Access Control (PHP)

Software Security (SDEV 4303) - Chapter 04: Access Control
Ibrahim Sayma - 120221807

A small PHP program that implements RBAC: permissions (access rights) are assigned
to roles, and users are assigned to roles. Every operation on the `Account` object
is checked by the RBAC module before it runs (deny by default).

| Role     | Create | View | Update | Delete |
|----------|:------:|:----:|:------:|:------:|
| Admin    | yes    | yes  | yes    | yes    |
| Manager  |        | yes  | yes    |        |
| Customer |        | yes  |        |        |

## Files
- `src/RBAC.php` - `RBAC` class (roles, permissions, user-role assignment, access check) and `AccountService` (the protected object)
- `rbac.php` - step-by-step demo
- `tests/test_rbac.php` - automated checks

## How to run
```
php rbac.php
php tests/test_rbac.php
```
Requires PHP 8.0 or newer (no extensions needed).
