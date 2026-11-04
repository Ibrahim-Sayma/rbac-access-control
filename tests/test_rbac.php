<?php
// Automated checks for the RBAC program: php tests/test_rbac.php
require __DIR__ . '/../src/RBAC.php';

$passed = 0; $failed = 0;
function check(string $name, bool $cond): void
{
    global $passed, $failed;
    if ($cond) { $passed++; echo "PASS  $name" . PHP_EOL; }
    else { $failed++; echo "FAIL  $name" . PHP_EOL; }
}

$rbac = new RBAC();
foreach (['Create', 'View', 'Update', 'Delete'] as $r) { $rbac->assignPermission('Admin', 'Account', $r); }
$rbac->assignPermission('Manager', 'Account', 'View');
$rbac->assignPermission('Manager', 'Account', 'Update');
$rbac->assignPermission('Customer', 'Account', 'View');
$rbac->assignRole('a', 'Admin');
$rbac->assignRole('m', 'Manager');
$rbac->assignRole('c', 'Customer');

// Expected matrix from the assignment
$expected = [
    'a' => ['Create' => true,  'View' => true, 'Update' => true,  'Delete' => true],
    'm' => ['Create' => false, 'View' => true, 'Update' => true,  'Delete' => false],
    'c' => ['Create' => false, 'View' => true, 'Update' => false, 'Delete' => false],
];
foreach ($expected as $u => $row) {
    foreach ($row as $right => $allowed) {
        check("$u " . ($allowed ? "can" : "cannot") . " $right", $rbac->checkAccess($u, 'Account', $right) === $allowed);
    }
}

// Fail-safe defaults
check("unknown user is denied", $rbac->checkAccess('nobody', 'Account', 'View') === false);
check("unknown right is denied", $rbac->checkAccess('a', 'Account', 'Transfer') === false);
check("other object is denied", $rbac->checkAccess('a', 'Report', 'View') === false);

// Many-to-many and revocation
$rbac->assignRole('c', 'Manager');
check("user with two roles gets the union (c can Update)", $rbac->checkAccess('c', 'Account', 'Update'));
$rbac->revokeRole('c', 'Manager');
check("revoking a role removes its rights", !$rbac->checkAccess('c', 'Account', 'Update'));

// Duplicate assignment is ignored
$rbac->assignPermission('Customer', 'Account', 'View');
check("duplicate permission not stored twice", count($rbac->getRolePermissions('Customer')) === 1);

// Unknown role cannot be assigned
try { $rbac->assignRole('x', 'Ghost'); check("assigning unknown role throws", false); }
catch (InvalidArgumentException $e) { check("assigning unknown role throws", true); }

// The service enforces the decision (complete mediation)
$svc = new AccountService($rbac);
$id = $svc->create('a', 'Ali', 100);
check("admin created account", $svc->count() === 1);
try { $svc->update('c', $id, 1); check("customer update blocked", false); }
catch (RuntimeException $e) { check("customer update blocked", true); }
check("balance unchanged after blocked update", $svc->view('a', $id)['balance'] == 100);
try { $svc->delete('m', $id); check("manager delete blocked", false); }
catch (RuntimeException $e) { check("manager delete blocked", true); }
$svc->update('m', $id, 250);
check("manager update applied", $svc->view('c', $id)['balance'] == 250);
$svc->delete('a', $id);
check("admin delete applied", $svc->count() === 0);

echo PHP_EOL . "Result: $passed passed, $failed failed" . PHP_EOL;
exit($failed === 0 ? 0 : 1);
