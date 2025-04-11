<?php
require_once __DIR__ . '/../src/Auth.php';

$auth = new Auth();

if (!$auth->isAuthenticated()) {
  header('Location: login.php');
  exit;
}

$userId = $auth->getUser()->getUserId();

// Check if user is admin and redirect automatically
if ($auth->hasRole($userId, 'Admin')) {
  header('Location: admin_dashboard.php');
  exit;
}

// If we get here, user is not an admin
echo "Welcome, " . htmlspecialchars($auth->getSession()->get('username')) . "! ";
echo "You are a User.";

// Check for specific permissions
if ($auth->hasPermission($userId, 'edit_content')) {
  echo "<p>You can edit content.</p>";
}
?>

<a href="logout.php">Logout</a>