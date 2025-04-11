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
  $roleName = trim($_POST['role_name']);
  $roleDescription = trim($_POST['role_description']);

  // Validate role name
  if (empty($roleName)) {
    if (session_status() === PHP_SESSION_NONE) {
      session_start();
    }
    $_SESSION['admin_error'] = "Role name cannot be empty.";
    header('Location: admin_roles.php');
    exit;
  }

  // Update the role
  $db = (new Database())->getConnection();

  try {
    // Don't allow renaming system default roles (User and Admin)
    if ($roleId <= 2) {
      $stmt = $db->prepare("UPDATE roles SET description = ? WHERE id = ?");
      $stmt->execute([$roleDescription, $roleId]);
    } else {
      $stmt = $db->prepare("UPDATE roles SET name = ?, description = ? WHERE id = ?");
      $stmt->execute([$roleName, $roleDescription, $roleId]);
    }

    // Set success message and redirect
    if (session_status() === PHP_SESSION_NONE) {
      session_start();
    }
    $_SESSION['admin_message'] = "Role updated successfully.";
  } catch (PDOException $e) {
    // Set error message
    if (session_status() === PHP_SESSION_NONE) {
      session_start();
    }
    $_SESSION['admin_error'] = "Error updating role: " . $e->getMessage();
  }

  // Redirect back to roles page
  header('Location: admin_roles.php');
  exit;
}

// If not a POST request, redirect to roles page
header('Location: admin_roles.php');
exit;
