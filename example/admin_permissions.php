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

// Handle permission deletion if requested
$message = '';
$error = '';

if (isset($_GET['action']) && $_GET['action'] === 'delete' && isset($_GET['id'])) {
  $permissionId = (int)$_GET['id'];

  try {
    // First check if permission is assigned to any role
    $stmt = $db->prepare("SELECT COUNT(*) FROM role_permissions WHERE permission_id = ?");
    $stmt->execute([$permissionId]);
    if ($stmt->fetchColumn() > 0) {
      $error = "This permission is assigned to one or more roles and cannot be deleted.";
    } else {
      $stmt = $db->prepare("DELETE FROM permissions WHERE id = ?");
      if ($stmt->execute([$permissionId])) {
        $message = "Permission deleted successfully.";
      } else {
        $error = "Failed to delete permission.";
      }
    }
  } catch (PDOException $e) {
    $error = "Database error: " . $e->getMessage();
  }
}

// Fetch all permissions with their assigned roles
try {
  $stmt = $db->prepare("
    SELECT p.id, p.name, p.description, 
           GROUP_CONCAT(r.name SEPARATOR ', ') as assigned_roles
    FROM permissions p
    LEFT JOIN role_permissions rp ON p.id = rp.permission_id
    LEFT JOIN roles r ON rp.role_id = r.id
    GROUP BY p.id
    ORDER BY p.name
  ");
  $stmt->execute();
  $permissions = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
  $error = "Database error: " . $e->getMessage();
  $permissions = [];
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Permissions Management | Admin Dashboard</title>
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

    .table th {
      background-color: #F9FAFB;
      color: #4B5563;
      font-weight: 600;
      text-transform: uppercase;
      font-size: 0.75rem;
      letter-spacing: 0.05em;
    }

    .badge-role {
      background-color: #EEF2FF;
      color: var(--primary-color);
      font-weight: 500;
      font-size: 0.75rem;
      padding: 0.35em 0.65em;
      border-radius: 0.25rem;
      display: inline-block;
      margin-right: 0.25rem;
      margin-bottom: 0.25rem;
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

    .alert {
      border-radius: 0.5rem;
    }

    /* Modal styles */
    .modal-content {
      border-radius: 0.75rem;
      border: none;
    }

    .modal-header {
      border-bottom: 1px solid #E5E7EB;
      padding: 1.25rem;
    }

    .modal-footer {
      border-top: 1px solid #E5E7EB;
      padding: 1.25rem;
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
        <?php if (!empty($message)): ?>
          <div class="alert alert-success alert-dismissible fade show" role="alert">
            <?php echo htmlspecialchars($message); ?>
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
          </div>
        <?php endif; ?>

        <?php if (!empty($error)): ?>
          <div class="alert alert-danger alert-dismissible fade show" role="alert">
            <?php echo htmlspecialchars($error); ?>
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
          </div>
        <?php endif; ?>

        <div class="card mb-4">
          <div class="card-header">
            <h5 class="card-title mb-0">Permission Management</h5>
            <a href="admin_permission_add.php" class="btn btn-primary btn-sm">
              <i class="fas fa-plus"></i> Add New Permission
            </a>
          </div>
          <div class="card-body">
            <div class="table-responsive">
              <table class="table table-hover">
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Name</th>
                    <th>Description</th>
                    <th>Assigned Roles</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  <?php foreach ($permissions as $permission): ?>
                    <tr>
                      <td><?php echo htmlspecialchars($permission['id']); ?></td>
                      <td><?php echo htmlspecialchars($permission['name']); ?></td>
                      <td><?php echo htmlspecialchars($permission['description'] ?? 'N/A'); ?></td>
                      <td>
                        <?php
                        if (!empty($permission['assigned_roles'])) {
                          $rolesArray = explode(', ', $permission['assigned_roles']);
                          foreach ($rolesArray as $role) {
                            $badgeClass = $role === 'Admin' ? 'bg-danger text-white' : 'badge-role';
                            echo '<span class="' . $badgeClass . '">' . htmlspecialchars($role) . '</span>';
                          }
                        } else {
                          echo '<span class="text-muted">Not assigned</span>';
                        }
                        ?>
                      </td>
                      <td>
                        <div class="btn-group btn-group-sm">
                          <a href="admin_permission_edit.php?id=<?php echo $permission['id']; ?>" class="btn btn-outline-primary">
                            <i class="fas fa-edit"></i>
                          </a>
                          <button type="button" class="btn btn-outline-danger"
                            data-bs-toggle="modal"
                            data-bs-target="#deleteModal"
                            data-permission-id="<?php echo $permission['id']; ?>"
                            data-permission-name="<?php echo htmlspecialchars($permission['name']); ?>"
                            <?php if (!empty($permission['assigned_roles'])): ?>disabled title="Cannot delete a permission assigned to roles" <?php endif; ?>>
                            <i class="fas fa-trash-alt"></i>
                          </button>
                        </div>
                      </td>
                    </tr>
                  <?php endforeach; ?>

                  <?php if (empty($permissions)): ?>
                    <tr>
                      <td colspan="5" class="text-center py-4">No permissions found</td>
                    </tr>
                  <?php endif; ?>
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- Delete Confirmation Modal -->
  <div class="modal fade" id="deleteModal" tabindex="-1" aria-labelledby="deleteModalLabel" aria-hidden="true">
    <div class="modal-dialog">
      <div class="modal-content">
        <div class="modal-header">
          <h5 class="modal-title" id="deleteModalLabel">Confirm Deletion</h5>
          <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
        </div>
        <div class="modal-body">
          Are you sure you want to delete the permission <span id="permissionToDelete" class="fw-bold"></span>? This action cannot be undone.
        </div>
        <div class="modal-footer">
          <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
          <a href="#" class="btn btn-danger" id="confirmDelete">Delete Permission</a>
        </div>
      </div>
    </div>
  </div>

  <!-- Bootstrap JS -->
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
  <script>
    // Set up delete modal
    document.addEventListener('DOMContentLoaded', function() {
      const deleteModal = document.getElementById('deleteModal');
      if (deleteModal) {
        deleteModal.addEventListener('show.bs.modal', function(event) {
          const button = event.relatedTarget;
          const permissionId = button.getAttribute('data-permission-id');
          const permissionName = button.getAttribute('data-permission-name');

          document.getElementById('permissionToDelete').textContent = permissionName;
          document.getElementById('confirmDelete').href = 'admin_permissions.php?action=delete&id=' + permissionId;
        });
      }
    });
  </script>

</body>

</html>