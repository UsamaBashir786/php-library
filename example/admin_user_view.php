<?php
require_once __DIR__ . '/../src/Auth.php';

$auth = new Auth();

// Check if user is authenticated and has Admin role
if (!$auth->isAuthenticated()) {
  header('Location: login.php');
  exit;
}

$adminId = $auth->getUser()->getUserId();
if (!$auth->hasRole($adminId, 'Admin')) {
  // Redirect non-admin users
  header('Location: dashboard.php');
  exit;
}

// Get user ID from query string
if (!isset($_GET['id']) || !is_numeric($_GET['id'])) {
  header('Location: admin_dashboard.php');
  exit;
}

$userId = intval($_GET['id']);
$db = (new Database())->getConnection();

// Get user details
$stmt = $db->prepare("
  SELECT u.*, GROUP_CONCAT(r.name SEPARATOR ', ') as roles
  FROM users u
  LEFT JOIN user_roles ur ON u.id = ur.user_id
  LEFT JOIN roles r ON ur.role_id = r.id
  WHERE u.id = ?
  GROUP BY u.id
");
$stmt->execute([$userId]);
$user = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$user) {
  // User not found, redirect to dashboard
  header('Location: admin_dashboard.php');
  exit;
}

// Get user permissions via roles
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

// Get login history (this would require a login_history table to be implemented)
// Example query if you had such a table:
// $stmt = $db->prepare("SELECT * FROM login_history WHERE user_id = ? ORDER BY login_time DESC LIMIT 10");
// $stmt->execute([$userId]);
// $loginHistory = $stmt->fetchAll(PDO::FETCH_ASSOC);
?>

<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>User Details | RoleAuth Admin</title>
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
      background-color: #F3F4F6;
      font-family: 'Nunito', sans-serif;
      color: #374151;
      min-height: 100vh;
    }

    .sidebar {
      background-color: #1F2937;
      min-height: 100vh;
      position: fixed;
      width: 250px;
    }

    .main-content {
      margin-left: 250px;
      padding: 2rem;
    }

    .sidebar-logo {
      padding: 1.5rem;
      display: flex;
      align-items: center;
      color: white;
      border-bottom: 1px solid rgba(255, 255, 255, 0.1);
    }

    .sidebar-logo svg {
      width: 2rem;
      height: 2rem;
      margin-right: 0.75rem;
    }

    .sidebar-logo-text {
      font-weight: 800;
      font-size: 1.5rem;
    }

    .sidebar-menu {
      padding: 1rem 0;
    }

    .sidebar-menu-item {
      padding: 0.75rem 1.5rem;
      display: flex;
      align-items: center;
      color: rgba(255, 255, 255, 0.7);
      text-decoration: none;
      transition: all 0.2s;
    }

    .sidebar-menu-item:hover,
    .sidebar-menu-item.active {
      background-color: rgba(255, 255, 255, 0.1);
      color: white;
    }

    .sidebar-menu-item svg {
      width: 1.25rem;
      height: 1.25rem;
      margin-right: 0.75rem;
    }

    .card {
      border: none;
      border-radius: 0.75rem;
      box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.1), 0 1px 2px 0 rgba(0, 0, 0, 0.06);
      margin-bottom: 2rem;
    }

    .card-header {
      background-color: white;
      padding: 1.25rem 1.5rem;
      border-bottom: 1px solid #E5E7EB;
      font-weight: 700;
      font-size: 1.25rem;
      border-radius: 0.75rem 0.75rem 0 0 !important;
    }

    .user-avatar-lg {
      width: 100px;
      height: 100px;
      border-radius: 50%;
      background-color: var(--primary-color);
      display: flex;
      align-items: center;
      justify-content: center;
      color: white;
      font-weight: 700;
      font-size: 2.5rem;
      margin-bottom: 1rem;
    }

    .badge {
      font-weight: 600;
      padding: 0.35em 0.65em;
      border-radius: 0.375rem;
    }

    .badge-admin {
      background-color: var(--primary-color);
    }

    .badge-user {
      background-color: var(--success-color);
    }

    .badge-permission {
      background-color: var(--secondary-color);
    }

    .btn-primary {
      background-color: var(--primary-color);
      border-color: var(--primary-color);
    }

    .btn-primary:hover {
      background-color: var(--primary-hover);
      border-color: var(--primary-hover);
    }

    .info-label {
      font-weight: 600;
      color: #6B7280;
      margin-bottom: 0.25rem;
    }

    .info-value {
      margin-bottom: 1.5rem;
    }
  </style>
</head>

<body>
  <!-- Sidebar -->
  <div class="sidebar">
    <div class="sidebar-logo">
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" fill="#6366F1" stroke="#6366F1" />
        <path d="M9 12l2 2 4-4" stroke="white" stroke-width="2" />
      </svg>
      <span class="sidebar-logo-text">RoleAuth</span>
    </div>

    <div class="sidebar-menu">
      <a href="admin_dashboard.php" class="sidebar-menu-item">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <rect x="3" y="3" width="7" height="7"></rect>
          <rect x="14" y="3" width="7" height="7"></rect>
          <rect x="14" y="14" width="7" height="7"></rect>
          <rect x="3" y="14" width="7" height="7"></rect>
        </svg>
        Dashboard
      </a>
      <a href="admin_dashboard.php" class="sidebar-menu-item active">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path>
          <circle cx="9" cy="7" r="4"></circle>
          <path d="M23 21v-2a4 4 0 0 0-3-3.87"></path>
          <path d="M16 3.13a4 4 0 0 1 0 7.75"></path>
        </svg>
        User Management
      </a>
      <a href="admin_roles.php" class="sidebar-menu-item">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M21 15l-9-15-9 15"></path>
          <path d="M3 15h18"></path>
          <path d="M12 15v6"></path>
        </svg>
        Role Management
      </a>
      <a href="admin_permissions.php" class="sidebar-menu-item">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
          <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
        </svg>
        Permission Management
      </a>
      <div class="mt-auto" style="margin-top: 2rem;">
        <a href="dashboard.php" class="sidebar-menu-item">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"></path>
            <polyline points="16 17 21 12 16 7"></polyline>
            <line x1="21" y1="12" x2="9" y2="12"></line>
          </svg>
          User Dashboard
        </a>
        <a href="logout.php" class="sidebar-menu-item">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"></path>
            <polyline points="16 17 21 12 16 7"></polyline>
            <line x1="21" y1="12" x2="9" y2="12"></line>
          </svg>
          Logout
        </a>
      </div>
    </div>
  </div>

  <!-- Main Content -->
  <div class="main-content">
    <div class="d-flex justify-content-between align-items-center mb-4">
      <h1 class="mb-0">User Details</h1>
      <div>
        <a href="admin_dashboard.php" class="btn btn-outline-primary">
          <i class="fas fa-arrow-left me-2"></i> Back to Dashboard
        </a>
      </div>
    </div>

    <div class="row">
      <div class="col-md-4">
        <div class="card">
          <div class="card-body text-center">
            <div class="user-avatar-lg mx-auto">
              <?php echo strtoupper(substr($user['username'], 0, 1)); ?>
            </div>
            <h3 class="mb-1"><?php echo htmlspecialchars($user['username']); ?></h3>
            <p class="text-muted mb-3"><?php echo htmlspecialchars($user['email']); ?></p>

            <div class="mb-3">
              <?php
              $rolesArray = explode(', ', $user['roles'] ?? '');
              foreach ($rolesArray as $role):
                if (!empty($role)):
                  $badgeClass = ($role === 'Admin') ? 'badge-admin' : 'badge-user';
              ?>
                  <span class="badge <?php echo $badgeClass; ?> me-1"><?php echo htmlspecialchars($role); ?></span>
              <?php
                endif;
              endforeach;
              ?>
            </div>

            <div class="d-grid gap-2">
              <button class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#editUserModal">
                <i class="fas fa-edit me-2"></i> Edit User
              </button>
              <?php if ($user['id'] !== $adminId): ?>
                <a href="admin_dashboard.php?delete=<?php echo $user['id']; ?>" class="btn btn-danger" onclick="return confirm('Are you sure you want to delete this user?');">
                  <i class="fas fa-trash me-2"></i> Delete User
                </a>
              <?php endif; ?>
            </div>
          </div>
        </div>
      </div>

      <div class="col-md-8">
        <div class="card mb-4">
          <div class="card-header">User Information</div>
          <div class="card-body">
            <div class="row">
              <div class="col-md-6">
                <p class="info-label">User ID</p>
                <p class="info-value"><?php echo $user['id']; ?></p>

                <p class="info-label">Username</p>
                <p class="info-value"><?php echo htmlspecialchars($user['username']); ?></p>

                <p class="info-label">Email</p>
                <p class="info-value"><?php echo htmlspecialchars($user['email']); ?></p>
              </div>

              <div class="col-md-6">
                <p class="info-label">Contact Number</p>
                <p class="info-value">
                  <?php echo !empty($user['contact_number']) ? htmlspecialchars($user['contact_number']) : '<span class="text-muted">Not provided</span>'; ?>
                </p>

                <p class="info-label">CNIC</p>
                <p class="info-value">
                  <?php echo !empty($user['cnic']) ? htmlspecialchars($user['cnic']) : '<span class="text-muted">Not provided</span>'; ?>
                </p>

                <p class="info-label">Created On</p>
                <p class="info-value"><?php echo date('F j, Y, g:i a', strtotime($user['created_at'])); ?></p>
              </div>
            </div>
          </div>
        </div>

        <div class="card mb-4">
          <div class="card-header">Permissions</div>
          <div class="card-body">
            <?php if (!empty($userPermissions)): ?>
              <?php foreach ($userPermissions as $permission): ?>
                <span class="badge badge-permission me-2 mb-2"><?php echo htmlspecialchars($permission); ?></span>
              <?php endforeach; ?>
            <?php else: ?>
              <p class="text-muted">No specific permissions assigned.</p>
            <?php endif; ?>
          </div>
        </div>

        <div class="card">
          <div class="card-header">OAuth Information</div>
          <div class="card-body">
            <div class="row">
              <div class="col-md-6">
                <p class="info-label">OAuth Provider</p>
                <p class="info-value">
                  <?php if (!empty($user['oauth_provider'])): ?>
                    <span class="badge bg-info"><?php echo htmlspecialchars(ucfirst($user['oauth_provider'])); ?></span>
                  <?php else: ?>
                    <span class="text-muted">Not using OAuth</span>
                  <?php endif; ?>
                </p>
              </div>

              <div class="col-md-6">
                <p class="info-label">OAuth ID</p>
                <p class="info-value">
                  <?php echo !empty($user['oauth_id']) ? htmlspecialchars($user['oauth_id']) : '<span class="text-muted">Not applicable</span>'; ?>
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- Edit User Modal -->
  <div class="modal fade" id="editUserModal" tabindex="-1" aria-labelledby="editUserModalLabel" aria-hidden="true">
    <div class="modal-dialog">
      <div class="modal-content">
        <div class="modal-header">
          <h5 class="modal-title" id="editUserModalLabel">Edit User: <?php echo htmlspecialchars($user['username']); ?></h5>
          <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
        </div>
        <form action="admin_user_edit.php" method="POST">
          <div class="modal-body">
            <input type="hidden" name="user_id" value="<?php echo $user['id']; ?>">
            <input type="hidden" name="csrf_token" value="<?php echo $auth->generateCsrfToken(); ?>">

            <div class="mb-3">
              <label for="username" class="form-label">Username</label>
              <input type="text" class="form-control" id="username" name="username" value="<?php echo htmlspecialchars($user['username']); ?>" required>
            </div>

            <div class="mb-3">
              <label for="email" class="form-label">Email</label>
              <input type="email" class="form-control" id="email" name="email" value="<?php echo htmlspecialchars($user['email']); ?>" required>
            </div>

            <div class="mb-3">
              <label for="contact_number" class="form-label">Contact Number</label>
              <input type="text" class="form-control" id="contact_number" name="contact_number" value="<?php echo htmlspecialchars($user['contact_number'] ?? ''); ?>">
            </div>

            <div class="mb-3">
              <label for="cnic" class="form-label">CNIC</label>
              <input type="text" class="form-control" id="cnic" name="cnic" value="<?php echo htmlspecialchars($user['cnic'] ?? ''); ?>">
            </div>

            <div class="mb-3">
              <label class="form-label">Roles</label>
              <?php
              // Get all available roles
              $stmt = $db->query("SELECT id, name FROM roles ORDER BY id");
              $availableRoles = $stmt->fetchAll(PDO::FETCH_ASSOC);

              $userRoles = explode(', ', $user['roles'] ?? '');
              foreach ($availableRoles as $role):
              ?>
                <div class="form-check">
                  <input class="form-check-input" type="checkbox" name="roles[]" value="<?php echo $role['id']; ?>" id="role_<?php echo $role['id']; ?>"
                    <?php echo in_array($role['name'], $userRoles) ? 'checked' : ''; ?>>
                  <label class="form-check-label" for="role_<?php echo $role['id']; ?>">
                    <?php echo htmlspecialchars($role['name']); ?>
                  </label>
                </div>
              <?php endforeach; ?>
            </div>

            <div class="mb-3">
              <label for="new_password" class="form-label">New Password (leave empty to keep current)</label>
              <input type="password" class="form-control" id="new_password" name="new_password">
            </div>
          </div>
          <div class="modal-footer">
            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
            <button type="submit" class="btn btn-primary">Save Changes</button>
          </div>
        </form>
      </div>
    </div>
  </div>

  <!-- Bootstrap JS -->
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
</body>

</html>