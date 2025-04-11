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
  $userIdToEdit = intval($_POST['user_id']);
  $username = trim($_POST['username'] ?? '');
  $email = trim($_POST['email'] ?? '');
  $contactNumber = trim($_POST['contact_number'] ?? '');
  $cnic = trim($_POST['cnic'] ?? '');
  $newPassword = trim($_POST['new_password'] ?? '');
  $roles = $_POST['roles'] ?? [];

  // Validate input
  $errors = [];

  if (empty($username) || strlen($username) < 3) {
    $errors[] = 'Username must be at least 3 characters long.';
  }

  if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
    $errors[] = 'Email address is invalid.';
  }

  if (!empty($contactNumber) && !preg_match('/^\+92\s\d{10}$/', $contactNumber)) {
    $errors[] = 'Contact number format should be like: +92 3196977218';
  }

  if (!empty($cnic) && !preg_match('/^\d{5}-\d{7}-\d{1}$/', $cnic)) {
    $errors[] = 'CNIC format should be like: 36502-6011487-8';
  }

  // If there are no errors, update the user
  if (empty($errors)) {
    $db = (new Database())->getConnection();

    try {
      // Begin transaction
      $db->beginTransaction();

      // Update user details
      $stmt = $db->prepare("
        UPDATE users 
        SET username = ?, email = ?, contact_number = ?, cnic = ? 
        WHERE id = ?
      ");
      $stmt->execute([$username, $email, $contactNumber ?: null, $cnic ?: null, $userIdToEdit]);

      // Update password if provided
      if (!empty($newPassword)) {
        $hashedPassword = password_hash($newPassword, PASSWORD_DEFAULT);
        $stmt = $db->prepare("UPDATE users SET password = ? WHERE id = ?");
        $stmt->execute([$hashedPassword, $userIdToEdit]);
      }

      // Update roles
      // First delete all existing roles
      $stmt = $db->prepare("DELETE FROM user_roles WHERE user_id = ?");
      $stmt->execute([$userIdToEdit]);

      // Then add new roles
      if (!empty($roles)) {
        $stmt = $db->prepare("INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)");
        foreach ($roles as $roleId) {
          $stmt->execute([$userIdToEdit, $roleId]);
        }
      }

      // Commit transaction
      $db->commit();

      // Redirect back to admin dashboard with success message
      if (session_status() === PHP_SESSION_NONE) {
        session_start();
      }
      $_SESSION['admin_message'] = "User updated successfully.";
      header('Location: admin_dashboard.php');
      exit;
    } catch (PDOException $e) {
      // Rollback transaction on error
      $db->rollBack();
      $errors[] = "Database error: " . $e->getMessage();
    }
  }

  // If there are errors, store them in session and redirect back
  if (!empty($errors)) {
    if (session_status() === PHP_SESSION_NONE) {
      session_start();
    }
    $_SESSION['admin_errors'] = $errors;
    $_SESSION['admin_form_data'] = $_POST;
    header('Location: admin_dashboard.php');
    exit;
  }
}

// If not a POST request, redirect to dashboard
header('Location: admin_dashboard.php');
exit;
