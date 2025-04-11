<?php
require_once __DIR__ . '/../src/Auth.php';

$auth = new Auth();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  if (!$auth->verifyCsrfToken($_POST['csrf_token'])) {
    die('Invalid CSRF token');
  }

  $username = filter_input(INPUT_POST, 'username', FILTER_SANITIZE_STRING);
  $email = filter_input(INPUT_POST, 'email', FILTER_VALIDATE_EMAIL);
  $password = $_POST['password'];
  $confirmPassword = $_POST['confirm_password'];
  $contactNumber = filter_input(INPUT_POST, 'contact_number', FILTER_SANITIZE_STRING);
  $cnic = filter_input(INPUT_POST, 'cnic', FILTER_SANITIZE_STRING);

  if (!$username || strlen($username) < 3) {
    die('Invalid username: Must be at least 3 characters.');
  }
  if (!$email) {
    die('Invalid email address.');
  }
  if (strlen($password) < 8) {
    die('Password must be at least 8 characters.');
  }
  if ($password !== $confirmPassword) {
    die('Passwords do not match.');
  }
  if ($contactNumber && !preg_match('/^\+?[1-9]\d{1,14}$/', $contactNumber)) {
    die('Invalid contact number: Use format like +1234567890.');
  }
  if ($cnic && !preg_match('/^\d{5}-\d{7}-\d{1}$/', $cnic)) {
    die('Invalid CNIC: Use format like 12345-1234567-1.');
  }

  try {
    $userId = $auth->register($username, $email, $password, $contactNumber ?: null, $cnic ?: null);
    if ($userId !== false) {
      $auth->assignRole($userId, 1);
      session_start();
      $_SESSION['message'] = 'Registration successful! Please log in.';
      header('Location: login.php');
      exit;
    } else {
      echo "Registration failed. Username, email, or CNIC may already be taken.";
    }
  } catch (Exception $e) {
    echo "Error: " . htmlspecialchars($e->getMessage());
  }
}
?>

<!DOCTYPE html>
<html>

<head>
  <title>Register</title>
</head>

<body>
  <form method="POST">
    <input type="hidden" name="csrf_token" value="<?php echo $auth->generateCsrfToken(); ?>">
    <div>
      <label>Username</label>
      <input type="text" name="username" placeholder="Username" required>
    </div>
    <div>
      <label>Email</label>
      <input type="email" name="email" placeholder="Email" required>
    </div>
    <div>
      <label>Password</label>
      <input type="password" name="password" placeholder="Password" required>
    </div>
    <div>
      <label>Confirm Password</label>
      <input type="password" name="confirm_password" placeholder="Confirm Password" required>
    </div>
    <div>
      <label>Contact Number</label>
      <input type="text" name="contact_number" placeholder="e.g., +1234567890" pattern="\+?[1-9]\d{1,14}">
    </div>
    <div>
      <label>CNIC</label>
      <input type="text" name="cnic" placeholder="e.g., 12345-1234567-1" pattern="\d{5}-\d{7}-\d{1}">
    </div>
    <button type="submit">Register</button>
  </form>
</body>

</html>