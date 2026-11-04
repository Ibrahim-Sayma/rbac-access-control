<?php
// Role-Based Access Control (RBAC) demo in PHP
// Software Security (SDEV 4303) - Chapter 04: Access Control
// Ibrahim Sayma - 120221807

require __DIR__ . '/src/RBAC.php';

function title(string $text): void
{
    echo PHP_EOL . str_repeat("=", 60) . PHP_EOL;
    echo $text . PHP_EOL;
    echo str_repeat("=", 60) . PHP_EOL;
}

// Run one operation and print ALLOWED / DENIED with the result
function attempt(string $label, callable $operation): void
{
    try {
        $result = $operation();
        echo str_pad($label, 36) . " -> ALLOWED" . ($result !== null ? "  ($result)" : "") . PHP_EOL;
    } catch (RuntimeException $e) {
        echo str_pad($label, 36) . " -> DENIED" . PHP_EOL;
    }
}

$rbac = new RBAC();
$accounts = new AccountService($rbac);
$rights = ['Create', 'View', 'Update', 'Delete'];

// STEP 1: Assign permissions (access rights on the Account object) to roles
title("STEP 1: Assign permissions to roles (object: Account)");
foreach ($rights as $r) {
    $rbac->assignPermission('Admin', 'Account', $r);
}
$rbac->assignPermission('Manager', 'Account', 'View');
$rbac->assignPermission('Manager', 'Account', 'Update');
$rbac->assignPermission('Customer', 'Account', 'View');

foreach ($rbac->getRoles() as $role) {
    echo str_pad($role, 10) . ": " . implode(', ', $rbac->getRolePermissions($role)) . PHP_EOL;
}

// STEP 2: Assign users to roles
title("STEP 2: Assign users to roles");
$rbac->assignRole('ibrahim', 'Admin');
$rbac->assignRole('sara', 'Manager');
$rbac->assignRole('ahmad', 'Customer');
$rbac->assignRole('lina', 'Customer');
foreach (['ibrahim', 'sara', 'ahmad', 'lina'] as $u) {
    echo str_pad($u, 10) . ": " . implode(', ', $rbac->getUserRoles($u)) . PHP_EOL;
}

// STEP 3: Admin performs all operations
title("STEP 3: Admin (ibrahim) - Create, View, Update, Delete");
attempt("ibrahim creates account (Ali, 500)", fn() => "account #" . $accounts->create('ibrahim', 'Ali', 500));
attempt("ibrahim creates account (Mona, 900)", fn() => "account #" . $accounts->create('ibrahim', 'Mona', 900));
attempt("ibrahim views account #1", fn() => json_encode($accounts->view('ibrahim', 1)));
attempt("ibrahim updates account #1 -> 750", function () use ($accounts) { $accounts->update('ibrahim', 1, 750); return "balance = 750"; });
attempt("ibrahim deletes account #2", function () use ($accounts) { $accounts->delete('ibrahim', 2); return "accounts left = " . $accounts->count(); });

// STEP 4: Manager can only view and update
title("STEP 4: Manager (sara) - View and Update only");
attempt("sara views account #1", fn() => json_encode($accounts->view('sara', 1)));
attempt("sara updates account #1 -> 800", function () use ($accounts) { $accounts->update('sara', 1, 800); return "balance = 800"; });
attempt("sara creates account (Omar, 100)", fn() => "account #" . $accounts->create('sara', 'Omar', 100));
attempt("sara deletes account #1", function () use ($accounts) { $accounts->delete('sara', 1); return null; });

// STEP 5: Customer can only view
title("STEP 5: Customer (ahmad) - View only");
attempt("ahmad views account #1", fn() => json_encode($accounts->view('ahmad', 1)));
attempt("ahmad updates account #1 -> 9999", function () use ($accounts) { $accounts->update('ahmad', 1, 9999); return null; });
attempt("ahmad creates account (Hacker, 1)", fn() => "account #" . $accounts->create('ahmad', 'Hacker', 1));
attempt("ahmad deletes account #1", function () use ($accounts) { $accounts->delete('ahmad', 1); return null; });
attempt("unknown user 'guest' views #1", fn() => json_encode($accounts->view('guest', 1)));

// STEP 6: Changing a role changes the rights without touching the user's permissions
title("STEP 6: Re-assign ahmad from Customer to Manager");
$rbac->revokeRole('ahmad', 'Customer');
$rbac->assignRole('ahmad', 'Manager');
echo "ahmad roles now: " . implode(', ', $rbac->getUserRoles('ahmad')) . PHP_EOL;
attempt("ahmad updates account #1 -> 820", function () use ($accounts) { $accounts->update('ahmad', 1, 820); return "balance = 820"; });
attempt("ahmad deletes account #1", function () use ($accounts) { $accounts->delete('ahmad', 1); return null; });

// STEP 7: Final access matrix (users x rights on Account)
title("STEP 7: Access matrix for the Account object");
echo str_pad("User (role)", 22);
foreach ($rights as $r) { echo str_pad($r, 9); }
echo PHP_EOL . str_repeat("-", 58) . PHP_EOL;
foreach (['ibrahim', 'sara', 'ahmad', 'lina', 'guest'] as $u) {
    $roles = implode(',', $rbac->getUserRoles($u)) ?: 'none';
    echo str_pad("$u ($roles)", 22);
    foreach ($rights as $r) {
        echo str_pad($rbac->checkAccess($u, 'Account', $r) ? 'YES' : 'no', 9);
    }
    echo PHP_EOL;
}
