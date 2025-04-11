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

// Get user statistics
try {
  // Total users count
  $stmt = $db->query("SELECT COUNT(*) FROM users");
  $totalUsers = $stmt->fetchColumn();

  // Users by role
  $stmt = $db->prepare("
    SELECT r.name, COUNT(ur.user_id) as count 
    FROM roles r
    LEFT JOIN user_roles ur ON r.id = ur.role_id
    GROUP BY r.id
  ");
  $stmt->execute();
  $usersByRole = $stmt->fetchAll(PDO::FETCH_ASSOC);

  // Recent users
  $stmt = $db->prepare("
    SELECT id, username, email, created_at 
    FROM users 
    ORDER BY created_at DESC 
    LIMIT 5
  ");
  $stmt->execute();
  $recentUsers = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
  $error = "Database error: " . $e->getMessage();
}
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
      height: 100%;
    }

    .card-header {
      background-color: white;
      border-bottom: 1px solid #E5E7EB;
      font-weight: 600;
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

    .stats-card {
      border-left: 4px solid;
      height: 100%;
    }

    .stats-card.users {
      border-left-color: var(--primary-color);
    }

    .stats-card.roles {
      border-left-color: var(--success-color);
    }

    .stats-card.permissions {
      border-left-color: var(--warning-color);
    }

    .stats-card-icon {
      width: 3rem;
      height: 3rem;
      display: flex;
      align-items: center;
      justify-content: center;
      border-radius: 50%;
      margin-bottom: 1rem;
    }

    .stats-card-icon.users {
      background-color: #EEF2FF;
      color: var(--primary-color);
    }

    .stats-card-icon.roles {
      background-color: #ECFDF5;
      color: var(--success-color);
    }

    .stats-card-icon.permissions {
      background-color: #FFFBEB;
      color: var(--warning-color);
    }

    .stats-value {
      font-size: 2rem;
      font-weight: 700;
    }

    .stats-label {
      color: #6B7280;
      font-size: 0.9rem;
      margin-top: 0.25rem;
    }

    .table {
      margin-bottom: 0;
    }

    .table th {
      background-color: #F9FAFB;
      color: #4B5563;
      font-weight: 600;
      text-transform: uppercase;
      font-size: 0.75rem;
      letter-spacing: 0.05em;
    }

    .role-badge {
      display: inline-block;
      padding: 0.25rem 0.5rem;
      border-radius: 1rem;
      font-size: 0.75rem;
      font-weight: 600;
      margin-right: 0.25rem;
    }

    .quick-actions {
      margin-top: 1.5rem;
    }

    .quick-action-btn {
      padding: 1rem;
      border-radius: 0.5rem;
      display: flex;
      flex-direction: column;
      align-items: center;
      background-color: white;
      box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.1), 0 1px 2px 0 rgba(0, 0, 0, 0.06);
      transition: all 0.2s;
      color: #4B5563;
      text-decoration: none;
      height: 100%;
    }

    .quick-action-btn:hover {
      transform: translateY(-2px);
      box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
      color: var(--primary-color);
    }

    .quick-action-icon {
      font-size: 1.5rem;
      margin-bottom: 0.5rem;
      color: var(--primary-color);
    }

    .quick-action-text {
      font-size: 0.9rem;
      font-weight: 600;
      text-align: center;
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
          <a href="admin_panel.php" class="sidebar-link active">
            <i class="fas fa-tachometer-alt sidebar-icon"></i> Dashboard
          </a>
          <a href="admin_users.php" class="sidebar-link">
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
        <div class="d-flex justify-content-between align-items-center mb-4">
          <h2 class="mb-0">Admin Dashboard</h2>
          <span class="text-muted">Welcome back, <?php echo htmlspecialchars($auth->getSession()->get('username')); ?></span>
        </div>

        <!-- Stats Cards -->
        <div class="row mb-4">
          <div class="col-xl-4 col-md-6 mb-4">
            <div class="card stats-card users">
              <div class="card-body">
                <div class="stats-card-icon users">
                  <i class="fas fa-users"></i>
                </div>
                <div class="stats-value"><?php echo $totalUsers; ?></div>
                <div class="stats-label">Total Users</div>
                <a href="admin_users.php" class="stretched-link"></a>
              </div>
            </div>
          </div>

          <div class="col-xl-4 col-md-6 mb-4">
            <div class="card stats-card roles">
              <div class="card-body">
                <div class="stats-card-icon roles">
                  <i class="fas fa-user-tag"></i>
                </div>
                <div class="stats-value"><?php echo count($usersByRole); ?></div>
                <div class="stats-label">Defined Roles</div>
                <a href="admin_roles.php" class="stretched-link"></a>
              </div>
            </div>
          </div>

          <div class="col-xl-4 col-md-6 mb-4">
            <div class="card stats-card permissions">
              <div class="card-body">
                <div class="stats-card-icon permissions">
                  <i class="fas fa-key"></i>
                </div>
                <div class="stats-value">
                  <?php
                  // Count permissions
                  $stmt = $db->query("SELECT COUNT(*) FROM permissions");
                  echo $stmt->fetchColumn();
                  ?>
                </div>
                <div class="stats-label">Permissions</div>
                <a href="admin_permissions.php" class="stretched-link"></a>
              </div>
            </div>
          </div>
        </div>

        <!-- Quick Actions -->
        <div class="row mb-4">
          <div class="col-12">
            <h4 class="mb-3">Quick Actions</h4>
          </div>

          <div class="col-xl-3 col-md-6 mb-4">
            <a href="admin_user_add.php" class="quick-action-btn">
              <i class="fas fa-user-plus quick-action-icon"></i>
              <span class="quick-action-text">Add New User</span>
            </a>
          </div>

          <div class="col-xl-3 col-md-6 mb-4">
            <a href="admin_role_add.php" class="quick-action-btn">
              <i class="fas fa-plus-circle quick-action-icon"></i>
              <span class="quick-action-text">Create New Role</span>
            </a>
          </div>

          <div class="col-xl-3 col-md-6 mb-4">
            <a href="admin_permission_add.php" class="quick-action-btn">
              <i class="fas fa-lock quick-action-icon"></i>
              <span class="quick-action-text">Add New Permission</span>
            </a>
          </div>

          <div class="col-xl-3 col-md-6 mb-4">
            <a href="admin_users.php" class="quick-action-btn">
              <i class="fas fa-user-shield quick-action-icon"></i>
              <span class="quick-action-text">Manage User Roles</span>
            </a>
          </div>
        </div>

        <!-- Recent Users and Role Distribution -->
        <div class="row">
          <!-- Recent Users -->
          <div class="col-xl-8 col-lg-7 mb-4">
            <div class="card">
              <div class="card-header d-flex justify-content-between align-items-center">
                <h5 class="card-title mb-0">Recently Added Users</h5>
                <a href="admin_users.php" class="btn btn-sm btn-primary">View All</a>
              </div>
              <div class="card-body p-0">
                <div class="table-responsive">
                  <table class="table table-hover">
                    <thead>
                      <tr>
                        <th>ID</th>
                        <th>Username</th>
                        <th>Email</th>
                        <th>Created</th>
                        <th>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      <?php foreach ($recentUsers as $user): ?>
                        <tr>
                          <td><?php echo htmlspecialchars($user['id']); ?></td>
                          <td><?php echo htmlspecialchars($user['username']); ?></td>
                          <td><?php echo htmlspecialchars($user['email']); ?></td>
                          <td><?php echo date('M d, Y', strtotime($user['created_at'])); ?></td>
                          <td>
                            <a href="admin_user_edit.php?id=<?php echo $user['id']; ?>" class="btn btn-sm btn-outline-primary">
                              <i class="fas fa-edit"></i>
                            </a>
                          </td>
                        </tr>
                      <?php endforeach; ?>

                      <?php if (empty($recentUsers)): ?>
                        <tr>
                          <td colspan="5" class="text-center py-3">No users found</td>
                        </tr>
                      <?php endif; ?>
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          </div>

          <!-- Role Distribution -->
          <div class="col-xl-4 col-lg-5 mb-4">
            <div class="card">
              <div class="card-header">
                <h5 class="card-title mb-0">User Role Distribution</h5>
              </div>
              <div class="card-body">
                <div class="table-responsive">
                  <table class="table">
                    <thead>
                      <tr>
                        <th>Role</th>
                        <th class="text-end">Users</th>
                      </tr>
                    </thead>
                    <tbody>
                      <?php foreach ($usersByRole as $role): ?>
                        <tr>
                          <td>
                            <?php
                            $roleName = htmlspecialchars($role['name']);
                            $roleColorClass = $roleName === 'Admin' ? 'bg-danger text-white' : 'bg-primary text-white';
                            echo '<span class="role-badge ' . $roleColorClass . '">' . $roleName . '</span>';
                            ?>
                          </td>
                          <td class="text-end"><?php echo $role['count']; ?></td>
                        </tr>
                      <?php endforeach; ?>

                      <?php if (empty($usersByRole)): ?>
                        <tr>
                          <td colspan="2" class="text-center py-3">No roles defined</td>
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
    </div>
  </div>

  <!-- Bootstrap JS -->
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>

</body>

</html>