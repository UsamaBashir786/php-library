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

// Define settings with default values (in case they don't exist in the database)
$defaultSettings = [
  'site_name' => 'RoleAuth System',
  'allow_registration' => '1',
  'default_role' => '1', // User role (ID: 1)
  'session_timeout' => '3600', // 1 hour in seconds
  'remember_me_duration' => '30', // 30 days
  'max_login_attempts' => '5',
  'lockout_time' => '15', // 15 minutes
  'oauth_google_enabled' => '1',
  'oauth_facebook_enabled' => '1',
  'oauth_github_enabled' => '1'
];

// Initialize settings array
$settings = [];

// Check if settings table exists, create if it doesn't
try {
  $stmt = $db->query("SHOW TABLES LIKE 'settings'");
  if ($stmt->rowCount() == 0) {
    // Create settings table
    $db->exec("
      CREATE TABLE settings (
        setting_key VARCHAR(50) PRIMARY KEY,
        setting_value TEXT NOT NULL,
        description TEXT,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )
    ");

    // Insert default settings
    $stmt = $db->prepare("INSERT INTO settings (setting_key, setting_value, description) VALUES (?, ?, ?)");
    $stmt->execute(['site_name', $defaultSettings['site_name'], 'Site name displayed in the header and title']);
    $stmt->execute(['allow_registration', $defaultSettings['allow_registration'], 'Allow new user registrations (1=yes, 0=no)']);
    $stmt->execute(['default_role', $defaultSettings['default_role'], 'Default role ID assigned to new users']);
    $stmt->execute(['session_timeout', $defaultSettings['session_timeout'], 'Session timeout in seconds']);
    $stmt->execute(['remember_me_duration', $defaultSettings['remember_me_duration'], 'Remember me cookie duration in days']);
    $stmt->execute(['max_login_attempts', $defaultSettings['max_login_attempts'], 'Maximum failed login attempts before account lockout']);
    $stmt->execute(['lockout_time', $defaultSettings['lockout_time'], 'Account lockout duration in minutes']);
    $stmt->execute(['oauth_google_enabled', $defaultSettings['oauth_google_enabled'], 'Enable Google OAuth login (1=yes, 0=no)']);
    $stmt->execute(['oauth_facebook_enabled', $defaultSettings['oauth_facebook_enabled'], 'Enable Facebook OAuth login (1=yes, 0=no)']);
    $stmt->execute(['oauth_github_enabled', $defaultSettings['oauth_github_enabled'], 'Enable GitHub OAuth login (1=yes, 0=no)']);
  }

  // Get all settings from database
  $stmt = $db->query("SELECT setting_key, setting_value, description FROM settings");
  while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
    $settings[$row['setting_key']] = [
      'value' => $row['setting_value'],
      'description' => $row['description']
    ];
  }

  // Merge with defaults for any missing settings
  foreach ($defaultSettings as $key => $value) {
    if (!isset($settings[$key])) {
      $settings[$key] = [
        'value' => $value,
        'description' => ''
      ];
    }
  }
} catch (PDOException $e) {
  $error = "Database error: " . $e->getMessage();
}

// Get all roles for dropdown
try {
  $stmt = $db->query("SELECT id, name FROM roles ORDER BY name");
  $roles = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
  $error = "Database error: " . $e->getMessage();
  $roles = [];
}

// Process form submission
$message = '';
$errors = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  if (!$auth->verifyCsrfToken($_POST['csrf_token'])) {
    $errors[] = 'Invalid CSRF token. Please try again.';
  } else {
    try {
      // Start transaction
      $db->beginTransaction();

      // Update settings
      $stmt = $db->prepare("UPDATE settings SET setting_value = ? WHERE setting_key = ?");

      // Site name
      $siteName = htmlspecialchars(trim($_POST['site_name'] ?? ''));
      if (empty($siteName)) {
        $errors[] = 'Site name cannot be empty.';
      } else {
        $stmt->execute([$siteName, 'site_name']);
        $settings['site_name']['value'] = $siteName;
      }

      // Allow registration
      $allowRegistration = isset($_POST['allow_registration']) ? '1' : '0';
      $stmt->execute([$allowRegistration, 'allow_registration']);
      $settings['allow_registration']['value'] = $allowRegistration;

      // Default role
      $defaultRole = filter_input(INPUT_POST, 'default_role', FILTER_VALIDATE_INT);
      if ($defaultRole === false || $defaultRole <= 0) {
        $errors[] = 'Please select a valid default role.';
      } else {
        $stmt->execute([$defaultRole, 'default_role']);
        $settings['default_role']['value'] = $defaultRole;
      }

      // Session timeout
      $sessionTimeout = filter_input(INPUT_POST, 'session_timeout', FILTER_VALIDATE_INT);
      if ($sessionTimeout === false || $sessionTimeout < 60) { // Minimum 1 minute
        $errors[] = 'Session timeout must be at least 60 seconds.';
      } else {
        $stmt->execute([$sessionTimeout, 'session_timeout']);
        $settings['session_timeout']['value'] = $sessionTimeout;
      }

      // Remember me duration
      $rememberMeDuration = filter_input(INPUT_POST, 'remember_me_duration', FILTER_VALIDATE_INT);
      if ($rememberMeDuration === false || $rememberMeDuration <= 0) {
        $errors[] = 'Remember me duration must be a positive number.';
      } else {
        $stmt->execute([$rememberMeDuration, 'remember_me_duration']);
        $settings['remember_me_duration']['value'] = $rememberMeDuration;
      }

      // Max login attempts
      $maxLoginAttempts = filter_input(INPUT_POST, 'max_login_attempts', FILTER_VALIDATE_INT);
      if ($maxLoginAttempts === false || $maxLoginAttempts <= 0) {
        $errors[] = 'Maximum login attempts must be a positive number.';
      } else {
        $stmt->execute([$maxLoginAttempts, 'max_login_attempts']);
        $settings['max_login_attempts']['value'] = $maxLoginAttempts;
      }

      // Lockout time
      $lockoutTime = filter_input(INPUT_POST, 'lockout_time', FILTER_VALIDATE_INT);
      if ($lockoutTime === false || $lockoutTime <= 0) {
        $errors[] = 'Lockout time must be a positive number.';
      } else {
        $stmt->execute([$lockoutTime, 'lockout_time']);
        $settings['lockout_time']['value'] = $lockoutTime;
      }

      // OAuth providers
      $oauthGoogleEnabled = isset($_POST['oauth_google_enabled']) ? '1' : '0';
      $stmt->execute([$oauthGoogleEnabled, 'oauth_google_enabled']);
      $settings['oauth_google_enabled']['value'] = $oauthGoogleEnabled;

      $oauthFacebookEnabled = isset($_POST['oauth_facebook_enabled']) ? '1' : '0';
      $stmt->execute([$oauthFacebookEnabled, 'oauth_facebook_enabled']);
      $settings['oauth_facebook_enabled']['value'] = $oauthFacebookEnabled;

      $oauthGithubEnabled = isset($_POST['oauth_github_enabled']) ? '1' : '0';
      $stmt->execute([$oauthGithubEnabled, 'oauth_github_enabled']);
      $settings['oauth_github_enabled']['value'] = $oauthGithubEnabled;

      // If no errors, commit transaction
      if (empty($errors)) {
        $db->commit();
        $message = "Settings updated successfully.";
      } else {
        $db->rollBack();
      }
    } catch (PDOException $e) {
      $db->rollBack();
      $errors[] = "Database error: " . $e->getMessage();
    }
  }
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>System Settings | Admin Dashboard</title>
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
      margin-bottom: 1.5rem;
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

    .form-label {
      font-weight: 600;
      color: #4B5563;
    }

    .form-text {
      color: #6B7280;
      font-size: 0.85rem;
    }

    .form-check-input:checked {
      background-color: var(--primary-color);
      border-color: var(--primary-color);
    }

    .btn-primary {
      background-color: var(--primary-color);
      border-color: var(--primary-color);
    }

    .btn-primary:hover {
      background-color: var(--primary-hover);
      border-color: var(--primary-hover);
    }

    .settings-section {
      border-bottom: 1px solid #E5E7EB;
      padding-bottom: 1.5rem;
      margin-bottom: 1.5rem;
    }

    .settings-section:last-child {
      border-bottom: none;
      padding-bottom: 0;
      margin-bottom: 0;
    }

    .settings-title {
      font-size: 1.1rem;
      font-weight: 600;
      color: var(--dark-color);
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
          <a href="admin_users.php" class="sidebar-link">
            <i class="fas fa-users sidebar-icon"></i> Users
          </a>
          <a href="admin_roles.php" class="sidebar-link">
            <i class="fas fa-user-tag sidebar-icon"></i> Roles
          </a>
          <a href="admin_permissions.php" class="sidebar-link">
            <i class="fas fa-key sidebar-icon"></i> Permissions
          </a>
          <a href="admin_settings.php" class="sidebar-link active">
            <i class="fas fa-cog sidebar-icon"></i> Settings
          </a>
        </div>
      </div>

      <!-- Main content -->
      <div class="col-lg-10 col-md-9 content-wrapper">
        <h2 class="mb-4">System Settings</h2>

        <?php if (!empty($message)): ?>
          <div class="alert alert-success alert-dismissible fade show" role="alert">
            <?php echo htmlspecialchars($message); ?>
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

        <form method="POST" action="">
          <input type="hidden" name="csrf_token" value="<?php echo $auth->generateCsrfToken(); ?>">

          <div class="card">
            <div class="card-header">
              <i class="fas fa-cogs me-2"></i> General Settings
            </div>
            <div class="card-body">
              <div class="settings-section">
                <div class="settings-title">Site Configuration</div>

                <div class="mb-3">
                  <label for="site_name" class="form-label">Site Name</label>
                  <input type="text" class="form-control" id="site_name" name="site_name"
                    value="<?php echo htmlspecialchars($settings['site_name']['value']); ?>">
                  <div class="form-text"><?php echo htmlspecialchars($settings['site_name']['description']); ?></div>
                </div>
              </div>

              <div class="settings-section">
                <div class="settings-title">User Registration</div>

                <div class="mb-3 form-check">
                  <input type="checkbox" class="form-check-input" id="allow_registration" name="allow_registration"
                    <?php echo $settings['allow_registration']['value'] === '1' ? 'checked' : ''; ?>>
                  <label class="form-check-label" for="allow_registration">Allow New User Registrations</label>
                  <div class="form-text"><?php echo htmlspecialchars($settings['allow_registration']['description']); ?></div>
                </div>

                <div class="mb-3">
                  <label for="default_role" class="form-label">Default Role for New Users</label>
                  <select class="form-select" id="default_role" name="default_role">
                    <?php foreach ($roles as $role): ?>
                      <option value="<?php echo $role['id']; ?>"
                        <?php echo $settings['default_role']['value'] == $role['id'] ? 'selected' : ''; ?>>
                        <?php echo htmlspecialchars($role['name']); ?>
                      </option>
                    <?php endforeach; ?>
                  </select>
                  <div class="form-text"><?php echo htmlspecialchars($settings['default_role']['description']); ?></div>
                </div>
              </div>

              <div class="settings-section">
                <div class="settings-title">Session & Security</div>

                <div class="mb-3">
                  <label for="session_timeout" class="form-label">Session Timeout (seconds)</label>
                  <input type="number" class="form-control" id="session_timeout" name="session_timeout"
                    value="<?php echo htmlspecialchars($settings['session_timeout']['value']); ?>" min="60">
                  <div class="form-text"><?php echo htmlspecialchars($settings['session_timeout']['description']); ?></div>
                </div>

                <div class="mb-3">
                  <label for="remember_me_duration" class="form-label">Remember Me Duration (days)</label>
                  <input type="number" class="form-control" id="remember_me_duration" name="remember_me_duration"
                    value="<?php echo htmlspecialchars($settings['remember_me_duration']['value']); ?>" min="1">
                  <div class="form-text"><?php echo htmlspecialchars($settings['remember_me_duration']['description']); ?></div>
                </div>

                <div class="row">
                  <div class="col-md-6 mb-3">
                    <label for="max_login_attempts" class="form-label">Max Login Attempts</label>
                    <input type="number" class="form-control" id="max_login_attempts" name="max_login_attempts"
                      value="<?php echo htmlspecialchars($settings['max_login_attempts']['value']); ?>" min="1">
                    <div class="form-text"><?php echo htmlspecialchars($settings['max_login_attempts']['description']); ?></div>
                  </div>

                  <div class="col-md-6 mb-3">
                    <label for="lockout_time" class="form-label">Lockout Time (minutes)</label>
                    <input type="number" class="form-control" id="lockout_time" name="lockout_time"
                      value="<?php echo htmlspecialchars($settings['lockout_time']['value']); ?>" min="1">
                    <div class="form-text"><?php echo htmlspecialchars($settings['lockout_time']['description']); ?></div>
                  </div>
                </div>
              </div>

              <div class="settings-section">
                <div class="settings-title">OAuth Integration</div>

                <div class="mb-3 form-check">
                  <input type="checkbox" class="form-check-input" id="oauth_google_enabled" name="oauth_google_enabled"
                    <?php echo $settings['oauth_google_enabled']['value'] === '1' ? 'checked' : ''; ?>>
                  <label class="form-check-label" for="oauth_google_enabled">Enable Google OAuth Login</label>
                  <div class="form-text"><?php echo htmlspecialchars($settings['oauth_google_enabled']['description']); ?></div>
                </div>

                <div class="mb-3 form-check">
                  <input type="checkbox" class="form-check-input" id="oauth_facebook_enabled" name="oauth_facebook_enabled"
                    <?php echo $settings['oauth_facebook_enabled']['value'] === '1' ? 'checked' : ''; ?>>
                  <label class="form-check-label" for="oauth_facebook_enabled">Enable Facebook OAuth Login</label>
                  <div class="form-text"><?php echo htmlspecialchars($settings['oauth_facebook_enabled']['description']); ?></div>
                </div>

                <div class="mb-3 form-check">
                  <input type="checkbox" class="form-check-input" id="oauth_github_enabled" name="oauth_github_enabled"
                    <?php echo $settings['oauth_github_enabled']['value'] === '1' ? 'checked' : ''; ?>>
                  <label class="form-check-label" for="oauth_github_enabled">Enable GitHub OAuth Login</label>
                  <div class="form-text"><?php echo htmlspecialchars($settings['oauth_github_enabled']['description']); ?></div>
                </div>

                <div class="alert alert-info">
                  <i class="fas fa-info-circle me-2"></i>
                  To configure OAuth provider credentials, please edit the <code>OAuthHandler.php</code> file.
                </div>
              </div>
            </div>
          </div>

          <div class="d-flex justify-content-end">
            <button type="submit" class="btn btn-primary">
              <i class="fas fa-save me-2"></i> Save Settings
            </button>
          </div>
        </form>
      </div>
    </div>
  </div>

  <!-- Bootstrap JS -->
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>

</body>

</html>