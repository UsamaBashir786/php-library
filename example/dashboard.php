<?php
require_once __DIR__ . '/../src/Auth.php';

$auth = new Auth();

if (!$auth->isAuthenticated()) {
  header('Location: login.php');
  exit;
}

$userId = $auth->getUser()->getUserId();

echo "Welcome, " . htmlspecialchars($auth->getSession()->get('username')) . "! ";

if ($auth->hasRole($userId, 'Admin')) {
  echo "You are an Admin. <a href='admin_panel.php'>Go to Admin Panel</a>";
} else {
  echo "You are a User.";
}

if ($auth->hasPermission($userId, 'edit_content')) {
  echo "<p>You can edit content.</p>";
}
?>

<a href="logout.php">Logout</a>