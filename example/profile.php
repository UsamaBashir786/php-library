<?php
require_once __DIR__ . '/../src/Auth.php';

$auth = new Auth();

// Check if user is authenticated
if (!$auth->isAuthenticated()) {
  header('Location: login.php');
  exit;
}

// Get the current user's ID
$userId = $auth->getUser()->getUserId();

// Get database connection
$db = (new Database())->getConnection();

// Get user data
try {
  $stmt = $db->prepare("SELECT * FROM users WHERE id = ?");
  $stmt->execute([$userId]);
  $user = $stmt->fetch(PDO::FETCH_ASSOC);

  if (!$user) {
    // This shouldn't happen, but just in case
    header('Location: logout.php');
    exit;
  }
} catch (PDOException $e) {
  die("Database error: " . $e->getMessage());
}

// Get user roles
try {
  $stmt = $db->prepare("
    SELECT r.name 
    FROM roles r
    JOIN user_roles ur ON r.id = ur.role_id
    WHERE ur.user_id = ?
  ");
  $stmt->execute([$userId]);
  $userRoles = $stmt->fetchAll(PDO::FETCH_COLUMN);
} catch (PDOException $e) {
  die("Database error: " . $e->getMessage());
}

// Get user permissions (through roles)
try {
  $stmt = $db->prepare("
    SELECT DISTINCT p.name 
    FROM permissions p
    JOIN role_permissions rp ON p.id = rp.permission_id
    JOIN user_roles ur ON rp.role_id = ur.role_id
    WHERE ur.user_id = ?
    ORDER BY p.name
  ");
  $stmt->execute([$userId]);
  $userPermissions = $stmt->fetchAll(PDO::FETCH_COLUMN);
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

// Process form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  if (!$auth->verifyCsrfToken($_POST['csrf_token'])) {
    $errors[] = 'Invalid CSRF token. Please try again.';
  } else {
    $formAction = $_POST['form_action'] ?? '';

    // Profile update form
    if ($formAction === 'update_profile') {
      // Validate and sanitize input
      $email = filter_input(INPUT_POST, 'email', FILTER_VALIDATE_EMAIL);
      $contactNumber = htmlspecialchars(trim($_POST['contact_number'] ?? ''));
      $cnic = htmlspecialchars(trim($_POST['cnic'] ?? ''));

      // Validation
      if (!$email) {
        $errors[] = 'Please enter a valid email address.';
      }

      // Validate contact number format if provided
      if (!empty($contactNumber) && !preg_match('/^\+92\s\d{10}$/', $contactNumber)) {
        $errors[] = 'Invalid contact number format. Use format: +92 3196977218';
      }

      // Validate CNIC format if provided
      if (!empty($cnic) && !preg_match('/^\d{5}-\d{7}-\d{1}$/', $cnic)) {
        $errors[] = 'Invalid CNIC format. Use format: 36502-6011487-8';
      }

      // Check if email already exists (but not for this user)
      if (empty($errors)) {
        $stmt = $db->prepare("
          SELECT COUNT(*) FROM users 
          WHERE email = ? AND id != ?
        ");
        $stmt->execute([$email, $userId]);
        if ($stmt->fetchColumn() > 0) {
          $errors[] = 'Email address is already in use by another account.';
        }
      }

      // If no errors, update the user profile
      if (empty($errors)) {
        try {
          $stmt = $db->prepare("
            UPDATE users 
            SET email = ?, contact_number = ?, cnic = ? 
            WHERE id = ?
          ");
          $stmt->execute([$email, $contactNumber ?: null, $cnic ?: null, $userId]);

          $success = 'Your profile has been updated successfully.';

          // Update the stored user data
          $user['email'] = $email;
          $user['contact_number'] = $contactNumber;
          $user['cnic'] = $cnic;
        } catch (PDOException $e) {
          $errors[] = 'Database error: ' . $e->getMessage();
        }
      }
    }
    // Password change form
    elseif ($formAction === 'change_password') {
      $currentPassword = $_POST['current_password'] ?? '';
      $newPassword = $_POST['new_password'] ?? '';
      $confirmPassword = $_POST['confirm_password'] ?? '';

      // Validation
      if (empty($currentPassword)) {
        $errors[] = 'Please enter your current password.';
      } elseif (!password_verify($currentPassword, $user['password'])) {
        $errors[] = 'Current password is incorrect.';
      }

      if (empty($newPassword) || strlen($newPassword) < 8) {
        $errors[] = 'New password must be at least 8 characters long.';
      }

      if ($newPassword !== $confirmPassword) {
        $errors[] = 'New passwords do not match.';
      }

      // If no errors, update the password
      if (empty($errors)) {
        try {
          $hashedPassword = password_hash($newPassword, PASSWORD_DEFAULT);

          $stmt = $db->prepare("
            UPDATE users 
            SET password = ? 
            WHERE id = ?
          ");
          $stmt->execute([$hashedPassword, $userId]);

          $success = 'Your password has been changed successfully.';
        } catch (PDOException $e) {
          $errors[] = 'Database error: ' . $e->getMessage();
        }
      }
    }
  }
}

// Check if the user has admin role to show admin panel link
$isAdmin = in_array('Admin', $userRoles);
?>

<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>My Profile | RoleAuth</title>
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
      color: #1F2937;
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
      margin-bottom: 1.5rem;
    }

    .card-header {
      background-color: white;
      border-bottom: 1px solid #E5E7EB;
      font-weight: 700;
      padding: 1rem 1.5rem;
      border-radius: 0.75rem 0.75rem 0 0 !important;
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

    .profile-header {
      background-color: white;
      padding: 2rem 0;
      margin-bottom: 2rem;
      box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.1), 0 1px 2px 0 rgba(0, 0, 0, 0.06);
    }

    .profile-pic {
      width: 120px;
      height: 120px;
      border-radius: 50%;
      background-color: #E5E7EB;
      display: flex;
      align-items: center;
      justify-content: center;
      margin: 0 auto 1rem;
      color: #9CA3AF;
      font-size: 2.5rem;
    }

    .badge-role {
      background-color: #EEF2FF;
      color: var(--primary-color);
      font-weight: 500;
      padding: 0.35em 0.65em;
      border-radius: 1rem;
      display: inline-block;
      margin-right: 0.25rem;
      margin-bottom: 0.25rem;
    }

    .badge-admin {
      background-color: #FDF2F8;
      color: var(--secondary-color);
    }

    .badge-permission {
      background-color: #F3F4F6;
      color: #4B5563;
      font-size: 0.75rem;
      padding: 0.25em 0.5em;
      border-radius: 0.25rem;
      display: inline-block;
      margin-right: 0.25rem;
      margin-bottom: 0.25rem;
    }

    .profile-meta {
      margin-bottom: 0.25rem;
      color: #6B7280;
      display: flex;
      align-items: center;
    }

    .profile-meta i {
      width: 1.5rem;
      margin-right: 0.5rem;
      color: #9CA3AF;
    }

    .profile-tabs .nav-link {
      color: #4B5563;
      font-weight: 600;
      padding: 0.75rem 1rem;
      border-radius: 0.5rem 0.5rem 0 0;
      border: 1px solid transparent;
    }

    .profile-tabs .nav-link.active {
      color: var(--primary-color);
      background-color: white;
      border-color: #E5E7EB;
      border-bottom-color: white;
    }

    .profile-tabs .nav-link:hover:not(.active) {
      color: var(--primary-color);
    }

    .tab-content {
      background-color: white;
      border-radius: 0 0.5rem 0.5rem 0.5rem;
      border: 1px solid #E5E7EB;
      padding: 1.5rem;
    }
  </style>
</head>

<body>

  <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
    <div class="container">
      <a class="navbar-brand" href="dashboard.php">
        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="#6366F1" stroke="#6366F1" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          <path d="M9 12l2 2 4-4" stroke="white" />
        </svg>
        RoleAuth
      </a>
      <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
        <span class="navbar-toggler-icon"></span>
      </button>
      <div class="collapse navbar-collapse" id="navbarNav">
        <ul class="navbar-nav ms-auto">
          <li class="nav-item">
            <a class="nav-link" href="dashboard.php">Dashboard</a>
          </li>
          <?php if ($isAdmin): ?>
            <li class="nav-item">
              <a class="nav-link" href="admin_panel.php">Admin Panel</a>
            </li>
          <?php endif; ?>
          <li class="nav-item dropdown">
            <a class="nav-link dropdown-toggle active" href="#" id="navbarDropdown" role="button" data-bs-toggle="dropdown">
              <?php echo htmlspecialchars($username); ?>
            </a>
            <ul class="dropdown-menu dropdown-menu-end">
              <li><a class="dropdown-item active" href="profile.php">Profile</a></li>
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

  <div class="profile-header">
    <div class="container">
      <div class="row align-items-center">
        <div class="col-md-3 text-center text-md-start">
          <div class="profile-pic">
            <i class="fas fa-user"></i>
          </div>
        </div>
        <div class="col-md-9 text-center text-md-start">
          <h2 class="mb-1"><?php echo htmlspecialchars($username); ?></h2>
          <div class="mb-2">
            <?php foreach ($userRoles as $role): ?>
              <span class="badge-role <?php echo $role === 'Admin' ? 'badge-admin' : ''; ?>">
                <?php echo htmlspecialchars($role); ?>
              </span>
            <?php endforeach; ?>
          </div>
          <div class="profile-meta"><i class="fas fa-envelope"></i> <?php echo htmlspecialchars($email); ?></div>
          <?php if (!empty($contactNumber)): ?>
            <div class="profile-meta"><i class="fas fa-phone"></i> <?php echo htmlspecialchars($contactNumber); ?></div>
          <?php endif; ?>
          <?php if (!empty($cnic)): ?>
            <div class="profile-meta"><i class="fas fa-id-card"></i> <?php echo htmlspecialchars($cnic); ?></div>
          <?php endif; ?>
          <div class="profile-meta"><i class="fas fa-clock"></i> Member since <?php echo date('F j, Y', strtotime($user['created_at'])); ?></div>
        </div>
      </div>
    </div>
  </div>

  <div class="container">
    <?php if (!empty($success)): ?>
      <div class="alert alert-success alert-dismissible fade show" role="alert">
        <?php echo htmlspecialchars($success); ?>
        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
      </div>
    <?php endif; ?>

    <?php if (!empty($errors)): ?>
      <div class="alert alert-danger alert-dismissible fade show" role="alert">
        <strong>There were some problems:</strong>
        <ul class="mb-0 mt-2">
          <?php foreach ($errors as $error): ?>
            <li><?php echo htmlspecialchars($error); ?></li>
          <?php endforeach; ?>
        </ul>
        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
      </div>
    <?php endif; ?>

    <ul class="nav nav-tabs profile-tabs mb-0" id="profileTabs" role="tablist">
      <li class="nav-item" role="presentation">
        <button class="nav-link active" id="profile-tab" data-bs-toggle="tab" data-bs-target="#profile" type="button" role="tab" aria-controls="profile" aria-selected="true">
          <i class="fas fa-user me-2"></i>Profile
        </button>
      </li>
      <li class="nav-item" role="presentation">
        <button class="nav-link" id="security-tab" data-bs-toggle="tab" data-bs-target="#security" type="button" role="tab" aria-controls="security" aria-selected="false">
          <i class="fas fa-lock me-2"></i>Security
        </button>
      </li>
      <li class="nav-item" role="presentation">
        <button class="nav-link" id="permissions-tab" data-bs-toggle="tab" data-bs-target="#permissions" type="button" role="tab" aria-controls="permissions" aria-selected="false">
          <i class="fas fa-key me-2"></i>Permissions
        </button>
      </li>
    </ul>

    <div class="tab-content" id="profileTabsContent">
      <!-- Profile Tab -->
      <div class="tab-pane fade show active" id="profile" role="tabpanel" aria-labelledby="profile-tab">
        <form method="POST" action="">
          <input type="hidden" name="csrf_token" value="<?php echo $auth->generateCsrfToken(); ?>">
          <input type="hidden" name="form_action" value="update_profile">

          <div class="row">
            <div class="col-md-6 mb-3">
              <label for="username" class="form-label">Username</label>
              <input type="text" class="form-control" id="username" value="<?php echo htmlspecialchars($username); ?>" readonly disabled>
              <div class="form-text">Username cannot be changed.</div>
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
              <div class="form-text">Format: +92 3196977218</div>
            </div>

            <div class="col-md-6 mb-3">
              <label for="cnic" class="form-label">CNIC</label>
              <input type="text" class="form-control" id="cnic" name="cnic" value="<?php echo htmlspecialchars($cnic); ?>" placeholder="36502-6011487-8">
              <div class="form-text">Format: 36502-6011487-8</div>
            </div>
          </div>

          <div class="d-grid gap-2 d-md-flex justify-content-md-end">
            <button type="submit" class="btn btn-primary">
              <i class="fas fa-save me-2"></i>Update Profile
            </button>
          </div>
        </form>
      </div>

      <!-- Security Tab -->
      <div class="tab-pane fade" id="security" role="tabpanel" aria-labelledby="security-tab">
        <form method="POST" action="">
          <input type="hidden" name="csrf_token" value="<?php echo $auth->generateCsrfToken(); ?>">
          <input type="hidden" name="form_action" value="change_password">

          <div class="mb-3 position-relative">
            <label for="current_password" class="form-label required">Current Password</label>
            <input type="password" class="form-control" id="current_password" name="current_password" required>
            <i class="fas fa-eye-slash password-toggle-icon" id="toggleCurrentPassword"></i>
          </div>

          <div class="mb-3 position-relative">
            <label for="new_password" class="form-label required">New Password</label>
            <input type="password" class="form-control" id="new_password" name="new_password" required>
            <i class="fas fa-eye-slash password-toggle-icon" id="toggleNewPassword"></i>
            <div class="form-text">Must be at least 8 characters long.</div>
          </div>

          <div class="mb-3 position-relative">
            <label for="confirm_password" class="form-label required">Confirm New Password</label>
            <input type="password" class="form-control" id="confirm_password" name="confirm_password" required>
            <i class="fas fa-eye-slash password-toggle-icon" id="toggleConfirmPassword"></i>
          </div>

          <div class="d-grid gap-2 d-md-flex justify-content-md-end">
            <button type="submit" class="btn btn-primary">
              <i class="fas fa-key me-2"></i>Change Password
            </button>
          </div>
        </form>
      </div>

      <!-- Permissions Tab -->
      <div class="tab-pane fade" id="permissions" role="tabpanel" aria-labelledby="permissions-tab">
        <div class="mb-4">
          <h5 class="mb-3">Your Roles</h5>
          <div>
            <?php if (!empty($userRoles)): ?>
              <?php foreach ($userRoles as $role): ?>
                <span class="badge-role <?php echo $role === 'Admin' ? 'badge-admin' : ''; ?>">
                  <?php echo htmlspecialchars($role); ?>
                </span>
              <?php endforeach; ?>
            <?php else: ?>
              <p class="text-muted">No roles assigned.</p>
            <?php endif; ?>
          </div>
        </div>

        <div>
          <h5 class="mb-3">Your Permissions</h5>
          <div>
            <?php if (!empty($userPermissions)): ?>
              <?php foreach ($userPermissions as $permission): ?>
                <span class="badge-permission">
                  <?php echo htmlspecialchars($permission); ?>
                </span>
              <?php endforeach; ?>
            <?php else: ?>
              <p class="text-muted">No permissions assigned.</p>
            <?php endif; ?>
          </div>
          <div class="form-text mt-3">
            Permissions are derived from your assigned roles. Contact an administrator if you need additional permissions.
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- Bootstrap JS -->
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
  <script>
    // Password toggle visibility
    document.getElementById('toggleCurrentPassword').addEventListener('click', function() {
      togglePasswordVisibility('current_password', this);
    });

    document.getElementById('toggleNewPassword').addEventListener('click', function() {
      togglePasswordVisibility('new_password', this);
    });

    document.getElementById('toggleConfirmPassword').addEventListener('click', function() {
      togglePasswordVisibility('confirm_password', this);
    });

    function togglePasswordVisibility(inputId, icon) {
      const passwordInput = document.getElementById(inputId);

      if (passwordInput.type === 'password') {
        passwordInput.type = 'text';
        icon.classList.remove('fa-eye-slash');
        icon.classList.add('fa-eye');
      } else {
        passwordInput.type = 'password';
        icon.classList.remove('fa-eye');
        icon.classList.add('fa-eye-slash');
      }
    }

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

    // Set active tab based on URL hash if present
    document.addEventListener('DOMContentLoaded', function() {
      const hash = window.location.hash;
      if (hash) {
        const tabId = hash.replace('#', '');
        const tab = document.querySelector(`#profileTabs button[data-bs-target="#${tabId}"]`);
        if (tab) {
          const bsTab = new bootstrap.Tab(tab);
          bsTab.show();
        }
      }
    });
  </script>

</body>

</html>