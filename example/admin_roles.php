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

// Database connection
$db = (new Database())->getConnection();

// Handle form submissions
$message = '';
$error = '';

// Add new role
if (isset($_POST['add_role']) && $auth->verifyCsrfToken($_POST['csrf_token'])) {
  $roleName = trim($_POST['role_name']);
  $roleDescription = trim($_POST['role_description']);

  if (!empty($roleName)) {
    try {
      $stmt = $db->prepare("INSERT INTO roles (name, description) VALUES (?, ?)");
      $stmt->execute([$roleName, $roleDescription]);
      $message = "Role '$roleName' added successfully.";
    } catch (PDOException $e) {
      $error = "Error adding role: " . $e->getMessage();
    }
  } else {
    $error = "Role name cannot be empty.";
  }
}

// Delete role
if (isset($_GET['delete']) && is_numeric($_GET['delete'])) {
  $roleId = (int)$_GET['delete'];

  // Don't allow deleting default roles (User and Admin)
  if ($roleId > 2) {
    try {
      // Start transaction
      $db->beginTransaction();

      // Remove role from users
      $stmt = $db->prepare("DELETE FROM user_roles WHERE role_id = ?");
      $stmt->execute([$roleId]);

      // Remove role permissions
      $stmt = $db->prepare("DELETE FROM role_permissions WHERE role_id = ?");
      $stmt->execute([$roleId]);

      // Delete the role
      $stmt = $db->prepare("DELETE FROM roles WHERE id = ?");
      $stmt->execute([$roleId]);

      // Commit transaction
      $db->commit();

      $message = "Role deleted successfully.";
    } catch (PDOException $e) {
      // Rollback transaction on error
      $db->rollBack();
      $error = "Error deleting role: " . $e->getMessage();
    }
  } else {
    $error = "Cannot delete default system roles.";
  }
}

// Get all roles
$stmt = $db->query("SELECT r.*, 
                          (SELECT COUNT(*) FROM user_roles WHERE role_id = r.id) as user_count,
                          (SELECT COUNT(*) FROM role_permissions WHERE role_id = r.id) as permission_count
                   FROM roles r
                   ORDER BY r.id ASC");
$roles = $stmt->fetchAll(PDO::FETCH_ASSOC);

// Get all permissions for the role edit modal
$stmt = $db->query("SELECT * FROM permissions ORDER BY name");
$allPermissions = $stmt->fetchAll(PDO::FETCH_ASSOC);
?>

<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Role Management | RoleAuth Admin</title>
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
      display: flex;
      justify-content: space-between;
      align-items: center;
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

    .badge-primary {
      background-color: var(--primary-color);
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

    .form-label {
      color: #4B5563;
      font-weight: 600;
      font-size: 0.95rem;
      margin-bottom: 0.5rem;
    }

    .permission-checkbox {
      display: flex;
      flex-wrap: wrap;
    }

    .permission-checkbox .form-check {
      width: 50%;
      margin-bottom: 0.5rem;
    }

    .role-icon {
      width: 40px;
      height: 40px;
      border-radius: 8px;
      background-color: var(--primary-color);
      display: flex;
      align-items: center;
      justify-content: center;
      color: white;
      margin-right: 0.75rem;
    }

    .role-icon svg {
      width: 1.25rem;
      height: 1.25rem;
    }

    .role-default-badge {
      background-color: var(--warning-color);
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
      <a href="admin_dashboard.php" class="sidebar-menu-item">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path>
          <circle cx="9" cy="7" r="4"></circle>
          <path d="M23 21v-2a4 4 0 0 0-3-3.87"></path>
          <path d="M16 3.13a4 4 0 0 1 0 7.75"></path>
        </svg>
        User Management
      </a>
      <a href="admin_roles.php" class="sidebar-menu-item active">
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
      <h1 class="mb-0">Role Management</h1>
      <div>
        <button class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#addRoleModal">
          <i class="fas fa-plus me-2"></i> Add New Role
        </button>
      </div>
    </div>

    <?php if (!empty($message)): ?>
      <div class="alert alert-success" role="alert">
        <?php echo htmlspecialchars($message); ?>
      </div>
    <?php endif; ?>

    <?php if (!empty($error)): ?>
      <div class="alert alert-danger" role="alert">
        <?php echo htmlspecialchars($error); ?>
      </div>
    <?php endif; ?>

    <div class="card">
      <div class="card-header">
        <span>Roles</span>
      </div>
      <div class="card-body p-0">
        <div class="table-responsive">
          <table class="table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Role</th>
                <th>Description</th>
                <th>Users</th>
                <th>Permissions</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              <?php foreach ($roles as $role): ?>
                <tr>
                  <td><?php echo $role['id']; ?></td>
                  <td>
                    <div class="d-flex align-items-center">
                      <div class="role-icon">
                        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                          <?php if ($role['name'] === 'Admin'): ?>
                            <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
                            <polyline points="22 4 12 14.01 9 11.01"></polyline>
                          <?php else: ?>
                            <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path>
                            <circle cx="12" cy="7" r="4"></circle>
                          <?php endif; ?>
                        </svg>
                      </div>
                      <div>
                        <?php echo htmlspecialchars($role['name']); ?>
                        <?php if ($role['id'] <= 2): ?>
                          <span class="badge role-default-badge">System Default</span>
                        <?php endif; ?>
                      </div>
                    </div>
                  </td>
                  <td><?php echo htmlspecialchars($role['description'] ?? 'No description'); ?></td>
                  <td><span class="badge badge-primary"><?php echo $role['user_count']; ?></span></td>
                  <td><span class="badge badge-primary"><?php echo $role['permission_count']; ?></span></td>
                  <td>
                    <div class="btn-group">
                      <button type="button" class="btn btn-sm btn-primary" data-bs-toggle="modal" data-bs-target="#editRoleModal<?php echo $role['id']; ?>">
                        <i class="fas fa-edit"></i>
                      </button>
                      <button type="button" class="btn btn-sm btn-info" data-bs-toggle="modal" data-bs-target="#assignPermissionsModal<?php echo $role['id']; ?>">
                        <i class="fas fa-key"></i>
                      </button>
                      <?php if ($role['id'] > 2): // Only allow deleting custom roles 
                      ?>
                        <a href="admin_roles.php?delete=<?php echo $role['id']; ?>" class="btn btn-sm btn-danger" onclick="return confirm('Are you sure you want to delete this role? All users will be removed from this role.');">
                          <i class="fas fa-trash"></i>
                        </a>
                      <?php endif; ?>
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

  <!-- Add Role Modal -->
  <div class="modal fade" id="addRoleModal" tabindex="-1" aria-labelledby="addRoleModalLabel" aria-hidden="true">
    <div class="modal-dialog">
      <div class="modal-content">
        <div class="modal-header">
          <h5 class="modal-title" id="addRoleModalLabel">Add New Role</h5>
          <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
        </div>
        <form action="admin_roles.php" method="POST">
          <div class="modal-body">
            <input type="hidden" name="csrf_token" value="<?php echo $auth->generateCsrfToken(); ?>">

            <div class="mb-3">
              <label for="role_name" class="form-label">Role Name</label>
              <input type="text" class="form-control" id="role_name" name="role_name" required>
            </div>

            <div class="mb-3">
              <label for="role_description" class="form-label">Description</label>
              <textarea class="form-control" id="role_description" name="role_description" rows="3"></textarea>
            </div>
          </div>
          <div class="modal-footer">
            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
            <button type="submit" name="add_role" class="btn btn-primary">Add Role</button>
          </div>
        </form>
      </div>
    </div>
  </div>

  <?php foreach ($roles as $role): ?>
    <!-- Edit Role Modal -->
    <div class="modal fade" id="editRoleModal<?php echo $role['id']; ?>" tabindex="-1" aria-labelledby="editRoleModalLabel<?php echo $role['id']; ?>" aria-hidden="true">
      <div class="modal-dialog">
        <div class="modal-content">
          <div class="modal-header">
            <h5 class="modal-title" id="editRoleModalLabel<?php echo $role['id']; ?>">Edit Role: <?php echo htmlspecialchars($role['name']); ?></h5>
            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
          </div>
          <form action="admin_role_edit.php" method="POST">
            <div class="modal-body">
              <input type="hidden" name="role_id" value="<?php echo $role['id']; ?>">
              <input type="hidden" name="csrf_token" value="<?php echo $auth->generateCsrfToken(); ?>">

              <div class="mb-3">
                <label for="role_name<?php echo $role['id']; ?>" class="form-label">Role Name</label>
                <input type="text" class="form-control" id="role_name<?php echo $role['id']; ?>" name="role_name" value="<?php echo htmlspecialchars($role['name']); ?>" <?php echo $role['id'] <= 2 ? 'readonly' : ''; ?> required>
                <?php if ($role['id'] <= 2): ?>
                  <div class="form-text text-warning">System default roles cannot be renamed.</div>
                <?php endif; ?>
              </div>

              <div class="mb-3">
                <label for="role_description<?php echo $role['id']; ?>" class="form-label">Description</label>
                <textarea class="form-control" id="role_description<?php echo $role['id']; ?>" name="role_description" rows="3"><?php echo htmlspecialchars($role['description'] ?? ''); ?></textarea>
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

    <!-- Assign Permissions Modal -->
    <div class="modal fade" id="assignPermissionsModal<?php echo $role['id']; ?>" tabindex="-1" aria-labelledby="assignPermissionsModalLabel<?php echo $role['id']; ?>" aria-hidden="true">
      <div class="modal-dialog modal-lg">
        <div class="modal-content">
          <div class="modal-header">
            <h5 class="modal-title" id="assignPermissionsModalLabel<?php echo $role['id']; ?>">Manage Permissions for: <?php echo htmlspecialchars($role['name']); ?></h5>
            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
          </div>
          <form action="admin_role_permissions.php" method="POST">
            <div class="modal-body">
              <input type="hidden" name="role_id" value="<?php echo $role['id']; ?>">
              <input type="hidden" name="csrf_token" value="<?php echo $auth->generateCsrfToken(); ?>">

              <p class="mb-3">Select the permissions for this role:</p>

              <div class="permission-checkbox">
                <?php
                // Get current permissions for this role
                $stmt = $db->prepare("SELECT permission_id FROM role_permissions WHERE role_id = ?");
                $stmt->execute([$role['id']]);
                $rolePermissions = $stmt->fetchAll(PDO::FETCH_COLUMN);

                foreach ($allPermissions as $permission):
                ?>
                  <div class="form-check">
                    <input class="form-check-input" type="checkbox" name="permissions[]" value="<?php echo $permission['id']; ?>" id="perm<?php echo $role['id'] . '_' . $permission['id']; ?>"
                      <?php echo in_array($permission['id'], $rolePermissions) ? 'checked' : ''; ?>>
                    <label class="form-check-label" for="perm<?php echo $role['id'] . '_' . $permission['id']; ?>">
                      <?php echo htmlspecialchars($permission['name']); ?>
                      <small class="text-muted d-block"><?php echo htmlspecialchars($permission['description'] ?? ''); ?></small>
                    </label>
                  </div>
                <?php endforeach; ?>
              </div>
            </div>
            <div class="modal-footer">
              <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
              <button type="submit" class="btn btn-primary">Save Permissions</button>
            </div>
          </form>
        </div>
      </div>
    </div>
  <?php endforeach; ?>

  <!-- Bootstrap JS -->
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
</body>

</html>