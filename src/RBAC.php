<?php
// Role-Based Access Control (RBAC) - core classes
// Software Security (SDEV 4303) - Chapter 04: Access Control
// Ibrahim Sayma - 120221807

class RBAC
{
    // role name => list of permissions, e.g. "Admin" => ["Account:Create", ...]
    private array $rolePermissions = [];

    // user name => list of role names (many-to-many: a user may have several roles)
    private array $userRoles = [];

    // Create a role (with no permissions yet)
    public function addRole(string $role): void
    {
        if (!isset($this->rolePermissions[$role])) {
            $this->rolePermissions[$role] = [];
        }
    }

    // Assign a permission (access right on an object) to a role
    public function assignPermission(string $role, string $object, string $right): void
    {
        $this->addRole($role);
        $permission = "$object:$right";
        if (!in_array($permission, $this->rolePermissions[$role], true)) {
            $this->rolePermissions[$role][] = $permission;
        }
    }

    // Assign a user to a role
    public function assignRole(string $user, string $role): void
    {
        if (!isset($this->rolePermissions[$role])) {
            throw new InvalidArgumentException("Role '$role' does not exist.");
        }
        $this->userRoles[$user] ??= [];
        if (!in_array($role, $this->userRoles[$user], true)) {
            $this->userRoles[$user][] = $role;
        }
    }

    // Remove a user from a role
    public function revokeRole(string $user, string $role): void
    {
        if (isset($this->userRoles[$user])) {
            $this->userRoles[$user] = array_values(array_filter(
                $this->userRoles[$user],
                fn($r) => $r !== $role
            ));
        }
    }

    public function getUserRoles(string $user): array
    {
        return $this->userRoles[$user] ?? [];
    }

    public function getRolePermissions(string $role): array
    {
        return $this->rolePermissions[$role] ?? [];
    }

    public function getRoles(): array
    {
        return array_keys($this->rolePermissions);
    }

    // Access decision: allowed only if one of the user's roles holds the permission.
    // Unknown users, users without roles, and unknown rights are denied (fail-safe default).
    public function checkAccess(string $user, string $object, string $right): bool
    {
        foreach ($this->getUserRoles($user) as $role) {
            if (in_array("$object:$right", $this->rolePermissions[$role], true)) {
                return true;
            }
        }
        return false;
    }
}

// The protected object: a simple in-memory store of accounts.
// Every operation first asks the RBAC module for permission (complete mediation).
class AccountService
{
    private array $accounts = [];
    private int $nextId = 1;

    public function __construct(private RBAC $rbac) {}

    private function guard(string $user, string $right): void
    {
        if (!$this->rbac->checkAccess($user, 'Account', $right)) {
            $roles = implode(', ', $this->rbac->getUserRoles($user)) ?: 'no role';
            throw new RuntimeException("ACCESS DENIED: '$user' ($roles) cannot $right accounts");
        }
    }

    public function create(string $user, string $owner, float $balance): int
    {
        $this->guard($user, 'Create');
        $id = $this->nextId++;
        $this->accounts[$id] = ['owner' => $owner, 'balance' => $balance];
        return $id;
    }

    public function view(string $user, int $id): array
    {
        $this->guard($user, 'View');
        if (!isset($this->accounts[$id])) {
            throw new OutOfBoundsException("Account #$id not found");
        }
        return $this->accounts[$id];
    }

    public function update(string $user, int $id, float $newBalance): void
    {
        $this->guard($user, 'Update');
        if (!isset($this->accounts[$id])) {
            throw new OutOfBoundsException("Account #$id not found");
        }
        $this->accounts[$id]['balance'] = $newBalance;
    }

    public function delete(string $user, int $id): void
    {
        $this->guard($user, 'Delete');
        if (!isset($this->accounts[$id])) {
            throw new OutOfBoundsException("Account #$id not found");
        }
        unset($this->accounts[$id]);
    }

    public function count(): int
    {
        return count($this->accounts);
    }
}
