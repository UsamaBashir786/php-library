<?php
require_once __DIR__ . '/../src/Auth.php';

$auth = new Auth();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  if (!$auth->verifyCsrfToken($_POST['csrf_token'])) {
    die('Invalid CSRF token');
  }

  $email = $_POST['email'];
  $password = $_POST['password'];

  if ($auth->login($email, $password)) {
    header('Location: dashboard.php');
    exit;
  } else {
    echo "Invalid credentials.";
  }
}
?>

<form method="POST">
  <input type="hidden" name="csrf_token" value="<?php echo $auth->generateCsrfToken(); ?>">
  <input type="email" name="email" placeholder="Email" required>
  <input type="password" name="password" placeholder="Password" required>
  <button type="submit">Login</button>
</form>