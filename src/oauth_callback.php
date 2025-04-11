<?php
require_once __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/../src/OAuthHandler.php';
require_once __DIR__ . '/../src/Session.php';
require_once __DIR__ . '/../src/User.php';

// Ensure session is started
session_start();

$session = new Session();
$user = new User($session);
$oauth = new OAuthHandler($session, $user);

try {
  if (isset($_GET['provider']) && $_GET['provider'] === 'google' && isset($_GET['code'])) {
    // Debug: Log the state and code
    error_log("OAuth Callback - State: " . ($_GET['state'] ?? 'not set') . ", Code: " . ($_GET['code'] ?? 'not set'));

    $userId = $oauth->handleCallback('google', [
      'code' => $_GET['code'],
      'state' => $_GET['state']
    ]);

    // Debug: Verify session data
    error_log("User ID set in session: " . $session->get('user_id'));
    error_log("Username set in session: " . $session->get('username'));

    // Assign default role (User, role_id = 1) if new user
    $db = (new Database())->getConnection();
    $stmt = $db->prepare("SELECT COUNT(*) FROM user_roles WHERE user_id = ?");
    $stmt->execute([$userId]);
    if ($stmt->fetchColumn() == 0) {
      $stmt = $db->prepare("INSERT INTO user_roles (user_id, role_id) VALUES (?, 1)");
      $stmt->execute([$userId]);
      error_log("Assigned User role to user ID: " . $userId);
    }

    // Redirect to dashboard
    header('Location: dashboard.php');
    exit;
  } else {
    throw new Exception('Invalid callback parameters');
  }
} catch (Exception $e) {
  // Debug: Log the error
  error_log("OAuth Callback Error: " . $e->getMessage());
  // Redirect to login with error message
  session_start();
  $_SESSION['error'] = "OAuth login failed: " . htmlspecialchars($e->getMessage());
  header('Location: login.php');
  exit;
}
