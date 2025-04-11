<?php
require_once __DIR__ . '/../src/Auth.php';

$auth = new Auth();

// Check if user is authenticated and has Admin role
if (!$auth->isAuthenticated()) {
  header('Location: login.php');
  exit;
}

$userId = $auth->getUser()->getUserId();
if (!$auth->hasRole($userId, 'Admin')) {
  // Redirect non-admin users
  header('Location: dashboard.php');
  exit;
}

// Check if form was submitted
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  // Verify CSRF token
  if (!$auth->verifyCsrfToken($_POST['csrf_token'])) {
    die('Invalid CSRF token');
  }

  // Get form data
  $roleId = intval($_POST['role_id']);
  $permissions = $_POST['permissions'] ?? [];

  // Update role permissions
  $db = (new Database())->getConnection();

  try {
    // Begin transaction
    $db->beginTransaction();

    // Remove all existing permissions for this role
    $stmt = $db->prepare("DELETE FROM role_permissions WHERE role_id = ?");
    $stmt->execute([$roleId]);

    // Add new permissions
    if (!empty($permissions)) {
      $stmt = $db->prepare("INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)");
      foreach ($permissions as $permissionId) {
        $stmt->execute([$roleId, $permissionId]);
      }
    }

    // Commit transaction
    $db->commit();

    // Set success message
    if (session_status() === PHP_SESSION_NONE) {
      session_start();
    }
    $_SESSION['admin_message'] = "Role permissions updated successfully.";
  } catch (PDOException $e) {
    // Rollback transaction on error
    $db->rollBack();

    // Set error message
    if (session_status() === PHP_SESSION_NONE) {
      session_start();
    }
    $_SESSION['admin_error'] = "Error updating role permissions: " . $e->getMessage();
  }

  // Redirect back to roles page
  header('Location: admin_roles.php');
  exit;
}

// If not a POST request, redirect to roles page
header('Location: admin_roles.php');
exit;
