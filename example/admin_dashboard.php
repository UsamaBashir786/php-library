<?php
require_once __DIR__ . '/../src/Auth.php';

$auth = new Auth();

// Check if user is authenticated and has Admin role
if (!$auth->isAuthenticated()) {
  header('Location: login.php');
  exit;
}

// Get the user ID - added this line to fix the undefined variable error
$userId = $auth->getUser()->getUserId();

// Check if user has Admin role
if (!$auth->hasRole($userId, 'Admin')) {
  // Redirect non-admin users
  header('Location: dashboard.php');
  exit;
}

// Database connection
$db = (new Database())->getConnection();

// Handle user deletion if requested
if (isset($_GET['delete']) && $auth->hasPermission($userId, 'delete_content')) {
  $userToDelete = intval($_GET['delete']);

  // Don't allow deleting yourself
  if ($userToDelete !== $userId) {
    // Delete user roles first (foreign key constraint)
    $stmt = $db->prepare("DELETE FROM user_roles WHERE user_id = ?");
    $stmt->execute([$userToDelete]);

    // Delete user
    $stmt = $db->prepare("DELETE FROM users WHERE id = ?");
    $stmt->execute([$userToDelete]);

    // Set success message
    $successMessage = "User successfully deleted.";
  } else {
    $errorMessage = "You cannot delete your own account.";
  }
}

// Get all users with their roles
$query = "
  SELECT u.id, u.username, u.email, u.contact_number, u.cnic, u.created_at, 
         GROUP_CONCAT(r.name SEPARATOR ', ') as roles
  FROM users u
  LEFT JOIN user_roles ur ON u.id = ur.user_id
  LEFT JOIN roles r ON ur.role_id = r.id
  GROUP BY u.id
  ORDER BY u.id ASC
";
$stmt = $db->query($query);
$users = $stmt->fetchAll(PDO::FETCH_ASSOC);

// Get count for dashboard stats
$totalUsers = count($users);
$adminUsers = 0;
$regularUsers = 0;

foreach ($users as $user) {
  if (strpos($user['roles'], 'Admin') !== false) {
    $adminUsers++;
  } else {
    $regularUsers++;
  }
}

// Get all available roles for the edit form
$stmt = $db->query("SELECT id, name FROM roles ORDER BY id");
$availableRoles = $stmt->fetchAll(PDO::FETCH_ASSOC);
?>

<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Admin Dashboard | RoleAuth</title>
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

    .dashboard-card {
      background-color: white;
      border-radius: 0.75rem;
      box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.1), 0 1px 2px 0 rgba(0, 0, 0, 0.06);
      padding: 1.5rem;
      margin-bottom: 1.5rem;
      display: flex;
      align-items: center;
    }

    .dashboard-card-icon {
      width: 3rem;
      height: 3rem;
      border-radius: 0.5rem;
      display: flex;
      align-items: center;
      justify-content: center;
      margin-right: 1rem;
    }

    .dashboard-card-icon.bg-primary {
      background-color: var(--primary-color);
    }

    .dashboard-card-icon.bg-success {
      background-color: var(--success-color);
    }

    .dashboard-card-icon.bg-warning {
      background-color: var(--warning-color);
    }

    .dashboard-card-icon svg {
      width: 1.5rem;
      height: 1.5rem;
      color: white;
    }

    .dashboard-card-content {
      flex: 1;
    }

    .dashboard-card-title {
      color: #6B7280;
      font-size: 0.875rem;
      font-weight: 600;
      margin-bottom: 0.25rem;
    }

    .dashboard-card-value {
      font-size: 1.5rem;
      font-weight: 700;
      margin-bottom: 0;
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

    .table {
      margin-bottom: 0;
    }

    .table th {
      font-weight: 600;
      color: #6B7280;
      border-bottom-width: 1px;
      padding: 0.75rem 1.5rem;
    }

    .table td {
      padding: 1rem 1.5rem;
      vertical-align: middle;
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

    .btn-sm {
      padding: 0.25rem 0.5rem;
      font-size: 0.875rem;
      border-radius: 0.375rem;
    }

    .btn-primary {
      background-color: var(--primary-color);
      border-color: var(--primary-color);
    }

    .btn-primary:hover {
      background-color: var(--primary-hover);
      border-color: var(--primary-hover);
    }

    .btn-danger {
      background-color: var(--danger-color);
      border-color: var(--danger-color);
    }

    .alert {
      border-radius: 0.5rem;
      padding: 1rem 1.5rem;
      margin-bottom: 1.5rem;
      border: none;
    }

    .alert-success {
      background-color: #ECFDF5;
      color: #047857;
    }

    .alert-danger {
      background-color: #FEF2F2;
      color: #B91C1C;
    }

    .user-avatar {
      width: 40px;
      height: 40px;
      border-radius: 50%;
      background-color: #E5E7EB;
      display: flex;
      align-items: center;
      justify-content: center;
      color: #6B7280;
      font-weight: 600;
      font-size: 1rem;
    }

    /* Modal styles */
    .modal-content {
      border-radius: 0.75rem;
      border: none;
    }

    .modal-header {
      border-bottom: 1px solid #E5E7EB;
      padding: 1.25rem 1.5rem;
    }

    .modal-footer {
      border-top: 1px solid #E5E7EB;
      padding: 1.25rem 1.5rem;
    }

    .form-label {
      color: #4B5563;
      font-weight: 600;
      font-size: 0.95rem;
      margin-bottom: 0.5rem;
    }

    .form-control {
      border-radius: 0.5rem;
      border: 1px solid #D1D5DB;
      padding: 0.75rem 1rem;
      font-size: 0.95rem;
      transition: all 0.2s ease;
    }

    .form-control:focus {
      border-color: var(--primary-color);
      box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.2);
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
      <a href="admin_dashboard.php" class="sidebar-menu-item active">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <rect x="3" y="3" width="7" height="7"></rect>
          <rect x="14" y="3" width="7" height="7"></rect>
          <rect x="14" y="14" width="7" height="7"></rect>
          <rect x="3" y="14" width="7" height="7"></rect>
        </svg>
        Dashboard
      </a>
      <a href="admin_users.php" class="sidebar-menu-item">
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
      <h1 class="mb-0">Admin Dashboard</h1>
      <div>
        <span class="me-2">Welcome, <?php echo htmlspecialchars($auth->getSession()->get('username')); ?></span>
      </div>
    </div>

    <?php if (isset($successMessage)): ?>
      <div class="alert alert-success" role="alert">
        <?php echo htmlspecialchars($successMessage); ?>
      </div>
    <?php endif; ?>

    <?php if (isset($errorMessage)): ?>
      <div class="alert alert-danger" role="alert">
        <?php echo htmlspecialchars($errorMessage); ?>
      </div>
    <?php endif; ?>

    <!-- Dashboard Cards -->
    <div class="row">
      <div class="col-md-4">
        <div class="dashboard-card">
          <div class="dashboard-card-icon bg-primary">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path>
              <circle cx="9" cy="7" r="4"></circle>
              <path d="M23 21v-2a4 4 0 0 0-3-3.87"></path>
              <path d="M16 3.13a4 4 0 0 1 0 7.75"></path>
            </svg>
          </div>
          <div class="dashboard-card-content">
            <h5 class="dashboard-card-title">Total Users</h5>
            <p class="dashboard-card-value"><?php echo $totalUsers; ?></p>
          </div>
        </div>
      </div>
      <div class="col-md-4">
        <div class="dashboard-card">
          <div class="dashboard-card-icon bg-success">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path>
              <circle cx="9" cy="7" r="4"></circle>
            </svg>
          </div>
          <div class="dashboard-card-content">
            <h5 class="dashboard-card-title">Regular Users</h5>
            <p class="dashboard-card-value"><?php echo $regularUsers; ?></p>
          </div>
        </div>
      </div>
      <div class="col-md-4">
        <div class="dashboard-card">
          <div class="dashboard-card-icon bg-warning">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M16 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path>
              <circle cx="9" cy="7" r="4"></circle>
              <path d="M22 12h-4l-3 9L9 3l-3 9H2"></path>
            </svg>
          </div>
          <div class="dashboard-card-content">
            <h5 class="dashboard-card-title">Admin Users</h5>
            <p class="dashboard-card-value"><?php echo $adminUsers; ?></p>
          </div>
        </div>
      </div>
    </div>

    <!-- Users Card -->
    <div class="card">
      <div class="card-header d-flex justify-content-between align-items-center">
        <span>User Management</span>
        <a href="admin_user_add.php" class="btn btn-primary btn-sm">
          <i class="fas fa-plus me-1"></i> Add New User
        </a>
      </div>
      <div class="card-body p-0">
        <div class="table-responsive">
          <table class="table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Username</th>
                <th>Email</th>
                <th>Roles</th>
                <th>Created</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              <?php foreach ($users as $user): ?>
                <tr>
                  <td><?php echo $user['id']; ?></td>
                  <td>
                    <div class="d-flex align-items-center">
                      <div class="user-avatar me-2">
                        <?php echo strtoupper(substr($user['username'], 0, 1)); ?>
                      </div>
                      <?php echo htmlspecialchars($user['username']); ?>
                    </div>
                  </td>
                  <td><?php echo htmlspecialchars($user['email']); ?></td>
                  <td>
                    <?php
                    $rolesArray = explode(', ', $user['roles'] ?? '');
                    foreach ($rolesArray as $role):
                      if (!empty($role)):
                        $badgeClass = ($role === 'Admin') ? 'badge-admin' : 'badge-user';
                    ?>
                        <span class="badge <?php echo $badgeClass; ?>"><?php echo htmlspecialchars($role); ?></span>
                    <?php
                      endif;
                    endforeach;
                    ?>
                  </td>
                  <td><?php echo date('M d, Y', strtotime($user['created_at'])); ?></td>
                  <td>
                    <div class="btn-group">
                      <button type="button" class="btn btn-sm btn-primary" data-bs-toggle="modal" data-bs-target="#editUserModal<?php echo $user['id']; ?>">
                        <i class="fas fa-edit"></i>
                      </button>
                      <a href="admin_user_view.php?id=<?php echo $user['id']; ?>" class="btn btn-sm btn-info">
                        <i class="fas fa-eye"></i>
                      </a>
                      <?php if ($user['id'] !== $userId): ?>
                        <a href="admin_dashboard.php?delete=<?php echo $user['id']; ?>" class="btn btn-sm btn-danger" onclick="return confirm('Are you sure you want to delete this user?');">
                          <i class="fas fa-trash"></i>
                        </a>
                      <?php endif; ?>
                    </div>

                    <!-- Edit User Modal -->
                    <div class="modal fade" id="editUserModal<?php echo $user['id']; ?>" tabindex="-1" aria-labelledby="editUserModalLabel<?php echo $user['id']; ?>" aria-hidden="true">
                      <div class="modal-dialog">
                        <div class="modal-content">
                          <div class="modal-header">
                            <h5 class="modal-title" id="editUserModalLabel<?php echo $user['id']; ?>">Edit User: <?php echo htmlspecialchars($user['username']); ?></h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                          </div>
                          <form action="admin_user_edit.php" method="POST">
                            <div class="modal-body">
                              <input type="hidden" name="user_id" value="<?php echo $user['id']; ?>">
                              <input type="hidden" name="csrf_token" value="<?php echo $auth->generateCsrfToken(); ?>">

                              <div class="mb-3">
                                <label for="username<?php echo $user['id']; ?>" class="form-label">Username</label>
                                <input type="text" class="form-control" id="username<?php echo $user['id']; ?>" name="username" value="<?php echo htmlspecialchars($user['username']); ?>" required>
                              </div>

                              <div class="mb-3">
                                <label for="email<?php echo $user['id']; ?>" class="form-label">Email</label>
                                <input type="email" class="form-control" id="email<?php echo $user['id']; ?>" name="email" value="<?php echo htmlspecialchars($user['email']); ?>" required>
                              </div>

                              <div class="mb-3">
                                <label for="contact_number<?php echo $user['id']; ?>" class="form-label">Contact Number</label>
                                <input type="text" class="form-control" id="contact_number<?php echo $user['id']; ?>" name="contact_number" value="<?php echo htmlspecialchars($user['contact_number'] ?? ''); ?>">
                              </div>

                              <div class="mb-3">
                                <label for="cnic<?php echo $user['id']; ?>" class="form-label">CNIC</label>
                                <input type="text" class="form-control" id="cnic<?php echo $user['id']; ?>" name="cnic" value="<?php echo htmlspecialchars($user['cnic'] ?? ''); ?>">
                              </div>

                              <div class="mb-3">
                                <label class="form-label">Roles</label>
                                <?php
                                $userRoles = explode(', ', $user['roles'] ?? '');
                                foreach ($availableRoles as $role):
                                ?>
                                  <div class="form-check">
                                    <input class="form-check-input" type="checkbox" name="roles[]" value="<?php echo $role['id']; ?>" id="role<?php echo $user['id'] . '_' . $role['id']; ?>"
                                      <?php echo in_array($role['name'], $userRoles) ? 'checked' : ''; ?>>
                                    <label class="form-check-label" for="role<?php echo $user['id'] . '_' . $role['id']; ?>">
                                      <?php echo htmlspecialchars($role['name']); ?>
                                    </label>
                                  </div>
                                <?php endforeach; ?>
                              </div>

                              <div class="mb-3">
                                <label for="new_password<?php echo $user['id']; ?>" class="form-label">New Password (leave empty to keep current)</label>
                                <input type="password" class="form-control" id="new_password<?php echo $user['id']; ?>" name="new_password">
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
                  </td>
                </tr>
              <?php endforeach; ?>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </div>

  <!-- Bootstrap JS -->
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
</body>

</html>