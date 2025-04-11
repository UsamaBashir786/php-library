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

// Get database connection
$db = (new Database())->getConnection();

// Get all available roles for role assignment
try {
  $stmt = $db->query("SELECT id, name FROM roles ORDER BY name");
  $roles = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
  $error = "Database error: " . $e->getMessage();
  $roles = [];
}

$errors = [];
$success = '';
$permissionName = '';
$permissionDescription = '';
$selectedRoles = [];

// Process form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  if (!$auth->verifyCsrfToken($_POST['csrf_token'])) {
    $errors[] = 'Invalid CSRF token. Please try again.';
  } else {
    // Validate and sanitize input
    $permissionName = htmlspecialchars(trim($_POST['name'] ?? ''));
    $permissionDescription = htmlspecialchars(trim($_POST['description'] ?? ''));
    $selectedRoles = isset($_POST['roles']) ? (array)$_POST['roles'] : [];

    // Validate permission name
    if (empty($permissionName)) {
      $errors[] = 'Permission name is required.';
    } elseif (strlen($permissionName) < 3) {
      $errors[] = 'Permission name must be at least 3 characters long.';
    }

    // Check if permission name already exists
    if (empty($errors)) {
      $stmt = $db->prepare("SELECT COUNT(*) FROM permissions WHERE name = ?");
      $stmt->execute([$permissionName]);
      if ($stmt->fetchColumn() > 0) {
        $errors[] = 'A permission with this name already exists.';
      }
    }

    // If no errors, add the permission
    if (empty($errors)) {
      try {
        // Begin transaction
        $db->beginTransaction();

        // Insert permission
        $stmt = $db->prepare("INSERT INTO permissions (name, description) VALUES (?, ?)");
        $stmt->execute([$permissionName, $permissionDescription]);
        $permissionId = $db->lastInsertId();

        // Assign roles if selected
        foreach ($selectedRoles as $roleId) {
          $stmt = $db->prepare("INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)");
          $stmt->execute([$roleId, $permissionId]);
        }

        // Commit transaction
        $db->commit();

        $success = "Permission '$permissionName' has been created successfully.";
        $permissionName = $permissionDescription = '';
        $selectedRoles = [];
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
  <title>Add New Permission | Admin Dashboard</title>
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

    .form-text {
      color: #6B7280;
      font-size: 0.85rem;
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
          <a href="admin_users.php" class="sidebar-link">
            <i class="fas fa-users sidebar-icon"></i> Users
          </a>
          <a href="admin_roles.php" class="sidebar-link">
            <i class="fas fa-user-tag sidebar-icon"></i> Roles
          </a>
          <a href="admin_permissions.php" class="sidebar-link active">
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
            <li class="breadcrumb-item"><a href="admin_permissions.php">Permissions</a></li>
            <li class="breadcrumb-item active">Add New Permission</li>
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
            <h5 class="card-title mb-0">Add New Permission</h5>
          </div>
          <div class="card-body">
            <form method="POST" action="">
              <input type="hidden" name="csrf_token" value="<?php echo $auth->generateCsrfToken(); ?>">

              <div class="mb-3">
                <label for="name" class="form-label required">Permission Name</label>
                <input type="text" class="form-control" id="name" name="name" value="<?php echo htmlspecialchars($permissionName); ?>" required>
                <div class="form-text">Permission names should be descriptive of the action they allow (e.g. 'edit_content', 'delete_user')</div>
              </div>

              <div class="mb-3">
                <label for="description" class="form-label">Description</label>
                <textarea class="form-control" id="description" name="description" rows="3"><?php echo htmlspecialchars($permissionDescription); ?></textarea>
                <div class="form-text">A brief description of what this permission allows users to do</div>
              </div>

              <div class="mb-4">
                <label class="form-label">Assign to Roles (Optional)</label>
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
                <div class="form-text">You can assign this permission to one or more roles directly, or do it later from the role management page.</div>
              </div>

              <div class="d-flex justify-content-between">
                <a href="admin_permissions.php" class="btn btn-secondary">Cancel</a>
                <button type="submit" class="btn btn-primary">Create Permission</button>
              </div>
            </form>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- Bootstrap JS -->
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>

</body>

</html>