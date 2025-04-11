<?php
require_once __DIR__ . '/src/Auth.php';
require_once __DIR__ . '/config/database.php';

// Create a new Auth instance
$auth = new Auth();

// Connect to the database
$db = (new Database())->getConnection();

// Check if permissions already exist
$stmt = $db->query("SELECT COUNT(*) FROM permissions");
$permissionCount = $stmt->fetchColumn();

if ($permissionCount == 0) {
  // Insert some default permissions
  $permissionsToAdd = [
    ['name' => 'edit_content', 'description' => 'Can edit content'],
    ['name' => 'delete_content', 'description' => 'Can delete content'],
    ['name' => 'create_user', 'description' => 'Can create new users'],
    ['name' => 'view_reports', 'description' => 'Can view reports']
  ];

  foreach ($permissionsToAdd as $permission) {
    $stmt = $db->prepare("INSERT INTO permissions (name, description) VALUES (?, ?)");
    $stmt->execute([$permission['name'], $permission['description']]);
    echo "Added permission: " . $permission['name'] . "<br>";
  }

  // Assign permissions to roles
  // Get the Admin role ID (should be 2 based on the database.sql)
  $adminRoleId = 2;

  // Assign all permissions to Admin role
  $stmt = $db->query("SELECT id FROM permissions");
  $permissionIds = $stmt->fetchAll(PDO::FETCH_COLUMN);

  foreach ($permissionIds as $permissionId) {
    $auth->assignPermissionToRole($adminRoleId, $permissionId);
    echo "Assigned permission ID $permissionId to Admin role<br>";
  }

  // Assign edit_content permission to User role
  $userRoleId = 1;
  $stmt = $db->prepare("SELECT id FROM permissions WHERE name = ?");
  $stmt->execute(['edit_content']);
  $editContentPermissionId = $stmt->fetchColumn();

  if ($editContentPermissionId) {
    $auth->assignPermissionToRole($userRoleId, $editContentPermissionId);
    echo "Assigned edit_content permission to User role<br>";
  }

  echo "<p>Permission setup completed!</p>";
} else {
  echo "<p>Permissions already set up. No changes made.</p>";
}

echo "<p><a href='index.php'>Return to homepage</a></p>";
