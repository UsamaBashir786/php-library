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
  header('Location: dashboard.php');
  exit;
}

// Check if user ID is provided
if (!isset($_GET['id']) || !filter_var($_GET['id'], FILTER_VALIDATE_INT)) {
  header('Location: admin_users.php');
  exit;
}

$editUserId = (int)$_GET['id'];

// Get database connection
$db = (new Database())->getConnection();

// Get user data
try {
  $stmt = $db->prepare("SELECT * FROM users WHERE id = ?");
  $stmt->execute([$editUserId]);
  $user = $stmt->fetch(PDO::FETCH_ASSOC);

  if (!$user) {
    header('Location: admin_users.php');
    exit;
  }
} catch (PDOException $e) {
  die("Database error: " . $e->getMessage());
}

// Get all available roles
try {
  $stmt = $db->query("SELECT id, name FROM roles ORDER BY name");
  $roles = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
  die("Database error: " . $e->getMessage());
}

// Get roles assigned to this user
try {
  $stmt = $db->prepare("
    SELECT role_id 
    FROM user_roles 
    WHERE user_id = ?
  ");
  $stmt->execute([$editUserId]);
  $assignedRoles = $stmt->fetchAll(PDO::FETCH_COLUMN);
} catch (PDOException $e) {
  die("Database error: " . $e->getMessage());
}

$errors = [];
$success = '';

// Initialize form values
$username = $user['username'];
$email = $user['email'];
$contactNumber = $user['contact_number'] ?? '';
$cnic = $user['cnic'] ?? '';
$selectedRoles = $assignedRoles;

// Process form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  if (!$auth->verifyCsrfToken($_POST['csrf_token'])) {
    $errors[] = 'Invalid CSRF token. Please try again.';
  } else {
    // Validate and sanitize input
    $username = htmlspecialchars(trim($_POST['username'] ?? ''));
    $email = filter_input(INPUT_POST, 'email', FILTER_VALIDATE_EMAIL);
    $password = $_POST['password'] ?? ''; // Optional - only if changing password
    $confirmPassword = $_POST['confirm_password'] ?? '';
    $contactNumber = htmlspecialchars(trim($_POST['contact_number'] ?? ''));
    $cnic = htmlspecialchars(trim($_POST['cnic'] ?? ''));
    $selectedRoles = isset($_POST['roles']) ? (array)$_POST['roles'] : [];

    // Validation
    if (empty($username) || strlen($username) < 3) {
      $errors[] = 'Username must be at least 3 characters long.';
    }

    if (!$email) {
      $errors[] = 'Please enter a valid email address.';
    }

    // Password validation - only if user is changing the password
    if (!empty($password)) {
      if (strlen($password) < 8) {
        $errors[] = 'Password must be at least 8 characters long.';
      }

      if ($password !== $confirmPassword) {
        $errors[] = 'Passwords do not match.';
      }
    }

    // Validate contact number format if provided
    if (!empty($contactNumber) && !preg_match('/^\+92\s\d{10}$/', $contactNumber)) {
      $errors[] = 'Invalid contact number format. Use format: +92 3196977218';
    }

    // Validate CNIC format if provided
    if (!empty($cnic) && !preg_match('/^\d{5}-\d{7}-\d{1}$/', $cnic)) {
      $errors[] = 'Invalid CNIC format. Use format: 36502-6011487-8';
    }

    // Check if username or email already exists (but not for this user)
    if (empty($errors)) {
      $stmt = $db->prepare("
        SELECT COUNT(*) FROM users 
        WHERE (username = ? OR email = ?) 
        AND id != ?
      ");
      $stmt->execute([$username, $email, $editUserId]);
      if ($stmt->fetchColumn() > 0) {
        $errors[] = 'Username or email already exists.';
      }
    }

    // If no errors, update the user
    if (empty($errors)) {
      try {
        // Begin transaction
        $db->beginTransaction();

        // Build the update query based on whether password is being changed
        if (!empty($password)) {
          $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
          $stmt = $db->prepare("
            UPDATE users 
            SET username = ?, email = ?, password = ?, contact_number = ?, cnic = ? 
            WHERE id = ?
          ");
          $stmt->execute([$username, $email, $hashedPassword, $contactNumber ?: null, $cnic ?: null, $editUserId]);
        } else {
          $stmt = $db->prepare("
            UPDATE users 
            SET username = ?, email = ?, contact_number = ?, cnic = ? 
            WHERE id = ?
          ");
          $stmt->execute([$username, $email, $contactNumber ?: null, $cnic ?: null, $editUserId]);
        }

        // Update roles
        // First delete all existing role assignments
        $stmt = $db->prepare("DELETE FROM user_roles WHERE user_id = ?");
        $stmt->execute([$editUserId]);

        // Then insert new role assignments
        foreach ($selectedRoles as $roleId) {
          $stmt = $db->prepare("INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)");
          $stmt->execute([$editUserId, $roleId]);
        }

        // Commit transaction
        $db->commit();

        $success = "User '$username' has been updated successfully.";
      } catch (PDOException $e) {
        $db->rollBack();
        $errors[] = 'Database error: ' . $e->getMessage();
      }
    }
  }
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Edit User | Admin Dashboard</title>
  <!-- Bootstrap CSS -->
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
  <!-- Font Awesome -->
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
  <!-- Google Fonts -->
  <link href="https://fonts.googleapis.com/css2?family=Nunito:wght@400;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --primary-color: #6366F1;
      --primary-hover: #4F46E5;
      --secondary-color: #EC4899;
      --dark-color: #1F2937;
      --light-color: #F9FAFB;
      --success-color: #10B981;
      --danger-color: #EF4444;
      --warning-color: #F59E0B;
    }

    body {
      font-family: 'Nunito', sans-serif;
      background-color: #F3F4F6;
    }

    .navbar-brand {
      font-weight: 700;
      display: flex;
      align-items: center;
    }

    .navbar-brand svg {
      margin-right: 0.5rem;
    }

    .card {
      border-radius: 0.75rem;
      box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
      border: none;
    }

    .card-header {
      background-color: white;
      border-bottom: 1px solid #E5E7EB;
      font-weight: 700;
      padding: 1rem 1.5rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-radius: 0.75rem 0.75rem 0 0 !important;
    }

    .sidebar {
      background-color: white;
      border-right: 1px solid #E5E7EB;
      min-height: calc(100vh - 56px);
    }

    .sidebar-link {
      display: flex;
      align-items: center;
      padding: 0.75rem 1.25rem;
      color: #4B5563;
      text-decoration: none;
      border-left: 3px solid transparent;
    }

    .sidebar-link:hover {
      background-color: #F3F4F6;
      color: var(--primary-color);
    }

    .sidebar-link.active {
      background-color: #EEF2FF;
      color: var(--primary-color);
      border-left-color: var(--primary-color);
      font-weight: 600;
    }

    .sidebar-icon {
      margin-right: 0.75rem;
      font-size: 1.1rem;
    }

    .content-wrapper {
      padding: 1.5rem;
    }

    .btn-primary {
      background-color: var(--primary-color);
      border-color: var(--primary-color);
    }

    .btn-primary:hover {
      background-color: var(--primary-hover);
      border-color: var(--primary-hover);
    }

    .form-label {
      font-weight: 600;
      color: #4B5563;
    }

    .required::after {
      content: " *";
      color: var(--danger-color);
    }

    .form-check-input:checked {
      background-color: var(--primary-color);
      border-color: var(--primary-color);
    }

    .alert-validation {
      background-color: #FEF2F2;
      border-color: #F87171;
      color: #B91C1C;
      border-radius: 0.5rem;
    }

    .form-text {
      color: #6B7280;
      font-size: 0.85rem;
    }

    .password-toggle-icon {
      position: absolute;
      right: 1rem;
      top: 50%;
      transform: translateY(-50%);
      cursor: pointer;
      color: #6B7280;
    }

    .optional-section {
      border-top: 1px solid #E5E7EB;
      margin-top: 1.5rem;
      padding-top: 1.5rem;
    }

    .optional-section-title {
      color: #4B5563;
      font-weight: 600;
      margin-bottom: 1rem;
    }
  </style>
</head>

<body>

  <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
    <div class="container-fluid">
      <a class="navbar-brand" href="dashboard.php">
        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="#6366F1" stroke="#6366F1" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          <path d="M9 12l2 2 4-4" stroke="white" />
        </svg>
        RoleAuth Admin
      </a>
      <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
        <span class="navbar-toggler-icon"></span>
      </button>
      <div class="collapse navbar-collapse" id="navbarNav">
        <ul class="navbar-nav ms-auto">
          <li class="nav-item">
            <a class="nav-link" href="dashboard.php">Dashboard</a>
          </li>
          <li class="nav-item dropdown">
            <a class="nav-link dropdown-toggle" href="#" id="navbarDropdown" role="button" data-bs-toggle="dropdown">
              <?php echo htmlspecialchars($auth->getSession()->get('username')); ?>
            </a>
            <ul class="dropdown-menu dropdown-menu-end">
              <li><a class="dropdown-item" href="profile.php">Profile</a></li>
              <li>
                <hr class="dropdown-divider">
              </li>
              <li><a class="dropdown-item" href="logout.php">Logout</a></li>
            </ul>
          </li>
        </ul>
      </div>
    </div>
  </nav>

  <div class="container-fluid">
    <div class="row">
      <!-- Sidebar -->
      <div class="col-lg-2 col-md-3 p-0 sidebar">
        <div class="pt-3">
          <a href="admin_panel.php" class="sidebar-link">
            <i class="fas fa-tachometer-alt sidebar-icon"></i> Dashboard
          </a>
          <a href="admin_users.php" class="sidebar-link active">
            <i class="fas fa-users sidebar-icon"></i> Users
          </a>
          <a href="admin_roles.php" class="sidebar-link">
            <i class="fas fa-user-tag sidebar-icon"></i> Roles
          </a>
          <a href="admin_permissions.php" class="sidebar-link">
            <i class="fas fa-key sidebar-icon"></i> Permissions
          </a>
          <a href="admin_settings.php" class="sidebar-link">
            <i class="fas fa-cog sidebar-icon"></i> Settings
          </a>
        </div>
      </div>

      <!-- Main content -->
      <div class="col-lg-10 col-md-9 content-wrapper">
        <nav aria-label="breadcrumb">
          <ol class="breadcrumb">
            <li class="breadcrumb-item"><a href="admin_panel.php">Dashboard</a></li>
            <li class="breadcrumb-item"><a href="admin_users.php">Users</a></li>
            <li class="breadcrumb-item active">Edit User</li>
          </ol>
        </nav>

        <?php if (!empty($success)): ?>
          <div class="alert alert-success alert-dismissible fade show" role="alert">
            <?php echo htmlspecialchars($success); ?>
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
          </div>
        <?php endif; ?>

        <?php if (!empty($errors)): ?>
          <div class="alert alert-danger alert-dismissible fade show" role="alert">
            <strong>There were some problems with your input:</strong>
            <ul class="mb-0 mt-2">
              <?php foreach ($errors as $error): ?>
                <li><?php echo htmlspecialchars($error); ?></li>
              <?php endforeach; ?>
            </ul>
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
          </div>
        <?php endif; ?>

        <div class="card mb-4">
          <div class="card-header">
            <h5 class="card-title mb-0">Edit User: <?php echo htmlspecialchars($user['username']); ?></h5>
          </div>
          <div class="card-body">
            <form method="POST" action="">
              <input type="hidden" name="csrf_token" value="<?php echo $auth->generateCsrfToken(); ?>">

              <div class="row">
                <div class="col-md-6 mb-3">
                  <label for="username" class="form-label required">Username</label>
                  <input type="text" class="form-control" id="username" name="username" value="<?php echo htmlspecialchars($username); ?>" required>
                  <div class="form-text">Must be at least 3 characters long.</div>
                </div>

                <div class="col-md-6 mb-3">
                  <label for="email" class="form-label required">Email Address</label>
                  <input type="email" class="form-control" id="email" name="email" value="<?php echo htmlspecialchars($email); ?>" required>
                </div>
              </div>

              <div class="row">
                <div class="col-md-6 mb-3">
                  <label for="contact_number" class="form-label">Contact Number</label>
                  <input type="text" class="form-control" id="contact_number" name="contact_number" value="<?php echo htmlspecialchars($contactNumber); ?>" placeholder="+92 3196977218">
                  <div class="form-text">Optional. Format: +92 3196977218</div>
                </div>

                <div class="col-md-6 mb-3">
                  <label for="cnic" class="form-label">CNIC</label>
                  <input type="text" class="form-control" id="cnic" name="cnic" value="<?php echo htmlspecialchars($cnic); ?>" placeholder="36502-6011487-8">
                  <div class="form-text">Optional. Format: 36502-6011487-8</div>
                </div>
              </div>

              <div class="mb-4">
                <label class="form-label">Roles</label>
                <div class="row">
                  <?php foreach ($roles as $role): ?>
                    <div class="col-md-3 mb-2">
                      <div class="form-check">
                        <input class="form-check-input" type="checkbox" name="roles[]" value="<?php echo $role['id']; ?>" id="role<?php echo $role['id']; ?>"
                          <?php if (in_array($role['id'], $selectedRoles)) echo 'checked'; ?>>
                        <label class="form-check-label" for="role<?php echo $role['id']; ?>">
                          <?php echo htmlspecialchars($role['name']); ?>
                        </label>
                      </div>
                    </div>
                  <?php endforeach; ?>
                </div>
                <div class="form-text">At least one role should be assigned.</div>
              </div>

              <!-- Optional Password Change Section -->
              <div class="optional-section">
                <div class="optional-section-title">Change Password (Optional)</div>
                <p class="text-muted mb-3">Leave blank to keep the current password.</p>

                <div class="row">
                  <div class="col-md-6 mb-3 position-relative">
                    <label for="password" class="form-label">New Password</label>
                    <input type="password" class="form-control" id="password" name="password">
                    <i class="fas fa-eye-slash password-toggle-icon" id="togglePassword"></i>
                    <div class="form-text">Must be at least 8 characters long.</div>
                  </div>

                  <div class="col-md-6 mb-3 position-relative">
                    <label for="confirm_password" class="form-label">Confirm New Password</label>
                    <input type="password" class="form-control" id="confirm_password" name="confirm_password">
                    <i class="fas fa-eye-slash password-toggle-icon" id="toggleConfirmPassword"></i>
                  </div>
                </div>
              </div>

              <div class="d-flex justify-content-between mt-4">
                <a href="admin_users.php" class="btn btn-secondary">Cancel</a>
                <button type="submit" class="btn btn-primary">Update User</button>
              </div>
            </form>
          </div>
        </div>

        <?php if ($editUserId != $userId): // Don't show delete section for the current admin user 
        ?>
          <div class="card mb-4 border-danger">
            <div class="card-header text-danger">
              <h5 class="card-title mb-0">Danger Zone</h5>
            </div>
            <div class="card-body">
              <p>Permanently delete this user and all their data. This action cannot be undone.</p>
              <button type="button" class="btn btn-danger" data-bs-toggle="modal" data-bs-target="#deleteModal">
                <i class="fas fa-trash-alt me-2"></i> Delete User
              </button>
            </div>
          </div>
        <?php endif; ?>
      </div>
    </div>
  </div>

  <!-- Delete Confirmation Modal -->
  <?php if ($editUserId != $userId): // Don't show delete modal for the current admin user 
  ?>
    <div class="modal fade" id="deleteModal" tabindex="-1" aria-labelledby="deleteModalLabel" aria-hidden="true">
      <div class="modal-dialog">
        <div class="modal-content">
          <div class="modal-header">
            <h5 class="modal-title" id="deleteModalLabel">Confirm User Deletion</h5>
            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
          </div>
          <div class="modal-body">
            <p>Are you sure you want to delete the user <strong><?php echo htmlspecialchars($username); ?></strong>?</p>
            <p class="text-danger"><strong>Warning:</strong> This action cannot be undone. All data associated with this user will be permanently deleted.</p>
          </div>
          <div class="modal-footer">
            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
            <a href="admin_users.php?action=delete&id=<?php echo $editUserId; ?>" class="btn btn-danger">Delete User</a>
          </div>
        </div>
      </div>
    </div>
  <?php endif; ?>

  <!-- Bootstrap JS -->
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
  <script>
    // Password toggle visibility
    document.getElementById('togglePassword').addEventListener('click', function() {
      const passwordInput = document.getElementById('password');
      const icon = this;

      if (passwordInput.type === 'password') {
        passwordInput.type = 'text';
        icon.classList.remove('fa-eye-slash');
        icon.classList.add('fa-eye');
      } else {
        passwordInput.type = 'password';
        icon.classList.remove('fa-eye');
        icon.classList.add('fa-eye-slash');
      }
    });

    document.getElementById('toggleConfirmPassword').addEventListener('click', function() {
      const confirmPasswordInput = document.getElementById('confirm_password');
      const icon = this;

      if (confirmPasswordInput.type === 'password') {
        confirmPasswordInput.type = 'text';
        icon.classList.remove('fa-eye-slash');
        icon.classList.add('fa-eye');
      } else {
        confirmPasswordInput.type = 'password';
        icon.classList.remove('fa-eye');
        icon.classList.add('fa-eye-slash');
      }
    });

    // Auto-formatting for Contact Number
    const contactInput = document.getElementById('contact_number');
    contactInput.addEventListener('input', function(e) {
      let input = e.target.value.replace(/\D/g, ''); // Remove all non-digits

      // If the user is trying to enter a number and hasn't typed +92 yet
      if (input.length > 0 && !e.target.value.startsWith('+92')) {
        // Add the +92 prefix
        input = '+92 ' + input;
      } else if (input.length > 0) {
        // If it already has +92, format as +92 followed by the digits
        input = '+92 ' + input.substring(2);
      }

      // Update the input field
      e.target.value = input;
    });

    // Auto-formatting for CNIC
    const cnicInput = document.getElementById('cnic');
    cnicInput.addEventListener('input', function(e) {
      let input = e.target.value.replace(/\D/g, ''); // Remove all non-digits
      let formatted = '';

      if (input.length > 0) {
        // Format first 5 digits
        if (input.length <= 5) {
          formatted = input;
        }
        // Format first 5 digits plus hyphen plus next digits
        else if (input.length <= 12) {
          formatted = input.substring(0, 5) + '-' + input.substring(5);
        }
        // Format complete CNIC with both hyphens
        else {
          formatted = input.substring(0, 5) + '-' + input.substring(5, 12) + '-' + input.substring(12, 13);
        }
      }

      // Update the input field
      e.target.value = formatted;
    });
  </script>

</body>

</html>