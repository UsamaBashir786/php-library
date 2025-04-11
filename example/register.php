<?php
require_once __DIR__ . '/../src/Auth.php';

$auth = new Auth();

// If user is already logged in, redirect to dashboard
if ($auth->isAuthenticated()) {
  header('Location: dashboard.php');
  exit;
}

$errors = [];
$formData = [
  'username' => '',
  'email' => '',
  'contact_number' => '',
  'cnic' => ''
];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  // Store form data to repopulate the form in case of errors
  $formData = [
    'username' => $_POST['username'] ?? '',
    'email' => $_POST['email'] ?? '',
    'contact_number' => $_POST['contact_number'] ?? '',
    'cnic' => $_POST['cnic'] ?? ''
  ];

  if (!$auth->verifyCsrfToken($_POST['csrf_token'])) {
    $errors[] = 'Invalid CSRF token. Please try again.';
  } else {
    // Fix: Replace deprecated FILTER_SANITIZE_STRING with htmlspecialchars
    $username = htmlspecialchars(trim($_POST['username'] ?? ''));
    $email = filter_input(INPUT_POST, 'email', FILTER_VALIDATE_EMAIL);
    $password = $_POST['password'] ?? '';
    $confirmPassword = $_POST['confirm_password'] ?? '';
    // Fix: Replace deprecated FILTER_SANITIZE_STRING with htmlspecialchars
    $contactNumber = htmlspecialchars(trim($_POST['contact_number'] ?? ''));
    $cnic = htmlspecialchars(trim($_POST['cnic'] ?? ''));

    // Validate input
    if (!$username || strlen($username) < 3) {
      $errors[] = 'Invalid username: Must be at least 3 characters.';
    }
    if (!$email) {
      $errors[] = 'Invalid email address.';
    }
    if (strlen($password) < 8) {
      $errors[] = 'Password must be at least 8 characters.';
    }
    if ($password !== $confirmPassword) {
      $errors[] = 'Passwords do not match.';
    }

    // Updated validation for Pakistan phone number format
    if ($contactNumber && !preg_match('/^\+92\s\d{10}$/', $contactNumber)) {
      $errors[] = 'Invalid contact number: Use format like +92 3196977218.';
    }

    // Updated validation for Pakistan CNIC format
    if ($cnic && !preg_match('/^\d{5}-\d{7}-\d{1}$/', $cnic)) {
      $errors[] = 'Invalid CNIC: Use format like 36502-6011487-8.';
    }

    // If no errors, proceed with registration
    if (empty($errors)) {
      try {
        $userId = $auth->register($username, $email, $password, $contactNumber ?: null, $cnic ?: null);
        if ($userId !== false) {
          $auth->assignRole($userId, 1); // Assign default 'User' role

          // Start session if not already started and set success message
          if (session_status() === PHP_SESSION_NONE) {
            session_start();
          }
          $_SESSION['message'] = 'Registration successful! Please log in.';

          header('Location: login.php');
          exit;
        } else {
          $errors[] = "Registration failed. Username, email, or CNIC may already be taken.";
        }
      } catch (Exception $e) {
        $errors[] = "Error: " . htmlspecialchars($e->getMessage());
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
  <title>Register | Role-Based Authentication</title>
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

    .auth-layout {
      display: flex;
      min-height: 100vh;
    }

    .auth-sidebar {
      display: none;
      background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
      width: 40%;
      position: relative;
      overflow: hidden;
    }

    @media (min-width: 992px) {
      .auth-sidebar {
        display: block;
      }

      .auth-container {
        width: 60%;
      }
    }

    .auth-container {
      padding: 2rem;
      width: 100%;
      display: flex;
      flex-direction: column;
      justify-content: center;
      max-width: 800px;
      margin: 0 auto;
    }

    .auth-sidebar-content {
      position: relative;
      z-index: 2;
      color: white;
      height: 100%;
      display: flex;
      flex-direction: column;
      justify-content: center;
      padding: 2rem;
    }

    .sidebar-heading {
      font-size: 2.5rem;
      font-weight: 700;
      margin-bottom: 1.5rem;
    }

    .sidebar-text {
      font-size: 1.1rem;
      margin-bottom: 2rem;
      line-height: 1.6;
    }

    .sidebar-svg {
      position: absolute;
      bottom: 0;
      left: 0;
      right: 0;
      z-index: 1;
      opacity: 0.2;
    }

    .pattern-dots {
      position: absolute;
      width: 100%;
      height: 100%;
      top: 0;
      left: 0;
      z-index: 1;
      opacity: 0.3;
      background-image: radial-gradient(#fff 2px, transparent 2px);
      background-size: 30px 30px;
    }

    .card {
      border: none;
      box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05);
      border-radius: 0.75rem;
      background-color: white;
    }

    .card-header {
      background-color: white;
      border-bottom: 1px solid #E5E7EB;
      padding: 1.5rem;
      font-weight: 700;
      font-size: 1.5rem;
      border-radius: 0.75rem 0.75rem 0 0 !important;
      display: flex;
      align-items: center;
    }

    .card-header-icon {
      margin-right: 0.75rem;
      width: 1.75rem;
      height: 1.75rem;
      color: var(--primary-color);
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

    .form-text {
      color: #6B7280;
      font-size: 0.85rem;
      margin-top: 0.25rem;
    }

    .input-icon {
      position: absolute;
      left: 1rem;
      top: 50%;
      transform: translateY(-50%);
      color: #9CA3AF;
    }

    .form-control.has-icon {
      padding-left: 2.75rem;
    }

    .btn-primary {
      background-color: var(--primary-color);
      border-color: var(--primary-color);
      font-weight: 600;
      padding: 0.75rem 1.5rem;
      border-radius: 0.5rem;
      transition: all 0.2s ease;
    }

    .btn-primary:hover {
      background-color: var(--primary-hover);
      border-color: var(--primary-hover);
      transform: translateY(-1px);
      box-shadow: 0 4px 6px -1px rgba(99, 102, 241, 0.2), 0 2px 4px -1px rgba(99, 102, 241, 0.1);
    }

    .alert-validation {
      background-color: #FEF2F2;
      border-color: #F87171;
      color: #B91C1C;
      border-radius: 0.5rem;
      margin-bottom: 1.5rem;
      position: relative;
      overflow: hidden;
    }

    .alert-validation::before {
      content: '';
      position: absolute;
      left: 0;
      top: 0;
      bottom: 0;
      width: 4px;
      background-color: var(--danger-color);
    }

    .is-invalid {
      border-color: var(--danger-color);
    }

    .invalid-feedback {
      color: var(--danger-color);
      font-size: 0.85rem;
      margin-top: 0.25rem;
    }

    .form-check-input:checked {
      background-color: var(--primary-color);
      border-color: var(--primary-color);
    }

    .auth-footer {
      text-align: center;
      margin-top: 2rem;
      font-size: 0.95rem;
      color: #6B7280;
    }

    .auth-footer a {
      color: var(--primary-color);
      text-decoration: none;
      font-weight: 600;
    }

    .auth-footer a:hover {
      text-decoration: underline;
    }

    .logo {
      text-align: left;
      margin-bottom: 2rem;
      display: flex;
      align-items: center;
    }

    .logo svg {
      width: 2.5rem;
      height: 2.5rem;
      margin-right: 0.75rem;
    }

    .logo-text {
      font-weight: 800;
      font-size: 1.75rem;
      color: var(--dark-color);
    }

    .password-toggle-icon {
      position: absolute;
      right: 1rem;
      top: 50%;
      transform: translateY(-50%);
      cursor: pointer;
      color: #6B7280;
    }

    .required::after {
      content: " *";
      color: var(--danger-color);
    }

    .field-icon {
      color: #9CA3AF;
      width: 1.25rem;
      height: 1.25rem;
    }
  </style>
</head>

<body>
  <div class="auth-layout">
    <!-- Sidebar with pattern and illustration (similar to Laravel) -->
    <div class="auth-sidebar">
      <div class="pattern-dots"></div>
      <div class="auth-sidebar-content">
        <h1 class="sidebar-heading">Welcome to RoleAuth</h1>
        <p class="sidebar-text">A secure, flexible role-based authentication system that helps you manage user permissions
          with ease. Join thousands of users and organizations who trust RoleAuth for their authentication needs.</p>

        <div class="sidebar-features">
          <div class="d-flex align-items-center mb-3">
            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="me-2">
              <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
              <polyline points="22 4 12 14.01 9 11.01"></polyline>
            </svg>
            <span>Role-based access control</span>
          </div>
          <div class="d-flex align-items-center mb-3">
            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="me-2">
              <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
              <polyline points="22 4 12 14.01 9 11.01"></polyline>
            </svg>
            <span>Fine-grained permissions</span>
          </div>
          <div class="d-flex align-items-center">
            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="me-2">
              <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
              <polyline points="22 4 12 14.01 9 11.01"></polyline>
            </svg>
            <span>CSRF protection included</span>
          </div>
        </div>
      </div>

      <!-- SVG pattern at the bottom of the sidebar -->
      <svg class="sidebar-svg" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1440 320">
        <path fill="rgba(255, 255, 255, 0.2)" fill-opacity="1" d="M0,224L48,213.3C96,203,192,181,288,181.3C384,181,480,203,576,197.3C672,192,768,160,864,144C960,128,1056,128,1152,149.3C1248,171,1344,213,1392,234.7L1440,256L1440,320L1392,320C1344,320,1248,320,1152,320C1056,320,960,320,864,320C768,320,672,320,576,320C480,320,384,320,288,320C192,320,96,320,48,320L0,320Z"></path>
      </svg>
    </div>

    <!-- Main content area -->
    <div class="auth-container">
      <div class="logo">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" fill="#6366F1" stroke="#6366F1" />
          <path d="M9 12l2 2 4-4" stroke="white" stroke-width="2" />
        </svg>
        <span class="logo-text">RoleAuth</span>
        <a href="login.php" class="text-decoration-none bg-primary text-white py-3 px-4 ms-auto">Back</a>
      </div>

      <?php if (!empty($errors)): ?>
        <div class="alert alert-danger alert-validation p-4 mb-4" role="alert">
          <div class="d-flex">
            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="me-3">
              <circle cx="12" cy="12" r="10"></circle>
              <line x1="12" y1="8" x2="12" y2="12"></line>
              <line x1="12" y1="16" x2="12.01" y2="16"></line>
            </svg>
            <div>
              <h5 class="alert-heading mb-1 fw-bold">There were some problems with your input</h5>
              <ul class="mb-0 mt-2">
                <?php foreach ($errors as $error): ?>
                  <li><?php echo htmlspecialchars($error); ?></li>
                <?php endforeach; ?>
              </ul>
            </div>
          </div>
        </div>
      <?php endif; ?>

      <div class="card mb-4">
        <div class="card-header">
          <svg xmlns="http://www.w3.org/2000/svg" class="card-header-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M16 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path>
            <circle cx="8.5" cy="7" r="4"></circle>
            <line x1="20" y1="8" x2="20" y2="14"></line>
            <line x1="23" y1="11" x2="17" y2="11"></line>
          </svg>
          Create an Account
        </div>
        <div class="card-body p-4">
          <form method="POST" id="registerForm">
            <input type="hidden" name="csrf_token" value="<?php echo $auth->generateCsrfToken(); ?>">

            <div class="mb-3">
              <label for="username" class="form-label required">Username</label>
              <div class="position-relative">
                <svg xmlns="http://www.w3.org/2000/svg" class="input-icon" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                  <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path>
                  <circle cx="12" cy="7" r="4"></circle>
                </svg>
                <input type="text" class="form-control has-icon" id="username" name="username" placeholder="Enter your username" value="<?php echo htmlspecialchars($formData['username']); ?>" required>
              </div>
              <div class="form-text">Must be at least 3 characters long</div>
            </div>

            <div class="mb-3">
              <label for="email" class="form-label required">Email Address</label>
              <div class="position-relative">
                <svg xmlns="http://www.w3.org/2000/svg" class="input-icon" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                  <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"></path>
                  <polyline points="22,6 12,13 2,6"></polyline>
                </svg>
                <input type="email" class="form-control has-icon" id="email" name="email" placeholder="name@example.com" value="<?php echo htmlspecialchars($formData['email']); ?>" required>
              </div>
            </div>

            <div class="mb-3 position-relative">
              <label for="password" class="form-label required">Password</label>
              <div class="position-relative">
                <svg xmlns="http://www.w3.org/2000/svg" class="input-icon" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                  <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
                  <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
                </svg>
                <input type="password" class="form-control has-icon" id="password" name="password" placeholder="Create a password" required>
                <i class="fas fa-eye-slash password-toggle-icon" id="togglePassword"></i>
              </div>
              <div class="form-text">Must be at least 8 characters long</div>
            </div>

            <div class="mb-3 position-relative">
              <label for="confirm_password" class="form-label required">Confirm Password</label>
              <div class="position-relative">
                <svg xmlns="http://www.w3.org/2000/svg" class="input-icon" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                  <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
                  <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
                </svg>
                <input type="password" class="form-control has-icon" id="confirm_password" name="confirm_password" placeholder="Confirm your password" required>
                <i class="fas fa-eye-slash password-toggle-icon" id="toggleConfirmPassword"></i>
              </div>
            </div>

            <div class="mb-3">
              <label for="contact_number" class="form-label">Contact Number</label>
              <div class="position-relative">
                <svg xmlns="http://www.w3.org/2000/svg" class="input-icon" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                  <path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72 12.84 12.84 0 0 0 .7 2.81 2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45 12.84 12.84 0 0 0 2.81.7A2 2 0 0 1 22 16.92z"></path>
                </svg>
                <input type="text" class="form-control has-icon" id="contact_number" name="contact_number" placeholder="+92 3196977218" value="<?php echo htmlspecialchars($formData['contact_number']); ?>">
              </div>
              <div class="form-text">Optional. Format: +92 3196977218</div>
            </div>

            <div class="mb-4">
              <label for="cnic" class="form-label">CNIC</label>
              <div class="position-relative">
                <svg xmlns="http://www.w3.org/2000/svg" class="input-icon" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                  <rect x="3" y="4" width="18" height="16" rx="2" ry="2"></rect>
                  <line x1="8" y1="2" x2="8" y2="6"></line>
                  <line x1="16" y1="2" x2="16" y2="6"></line>
                  <circle cx="12" cy="10" r="3"></circle>
                  <path d="M7 18v-1a3 3 0 0 1 3-3h4a3 3 0 0 1 3 3v1"></path>
                </svg>
                <input type="text" class="form-control has-icon" id="cnic" name="cnic" placeholder="36502-6011487-8" value="<?php echo htmlspecialchars($formData['cnic']); ?>">
              </div>
              <div class="form-text">Optional. Format: 36502-6011487-8</div>
            </div>

            <div class="mb-4 form-check">
              <input type="checkbox" class="form-check-input" id="terms" required>
              <label class="form-check-label" for="terms">I agree to the <a href="#">Terms of Service</a> and <a href="#">Privacy Policy</a></label>
            </div>

            <div class="d-grid gap-2">
              <button type="submit" class="btn btn-primary">
                <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="me-2">
                  <path d="M16 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path>
                  <circle cx="8.5" cy="7" r="4"></circle>
                  <line x1="20" y1="8" x2="20" y2="14"></line>
                  <line x1="23" y1="11" x2="17" y2="11"></line>
                </svg>
                Create Account
              </button>
            </div>
          </form>
        </div>
      </div>

      <div class="auth-footer">
        <p>Already have an account? <a href="login.php">Log in</a></p>
      </div>
    </div>
  </div>

  <!-- Bootstrap and other scripts -->
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
        // Format complete CNIC with both hyphens
        else {
          formatted = input.substring(0, 5) + '-' + input.substring(5, 12) + '-' + input.substring(12, 13);
        }
      }

      // Update the input field
      e.target.value = formatted;
    });

    // Form submission handler - ensure phone and CNIC formatting is correct
    document.getElementById('registerForm').addEventListener('submit', function(e) {
      let contactNumber = contactInput.value.trim();
      let cnic = cnicInput.value.trim();
      let isValid = true;

      // Validate phone number format if provided
      if (contactNumber && !(/^\+92\s\d{10}$/.test(contactNumber))) {
        alert('Please enter a valid Pakistan phone number in the format: +92 3196977218');
        isValid = false;
      }

      // Validate CNIC format if provided
      if (cnic && !(/^\d{5}-\d{7}-\d{1}$/.test(cnic))) {
        alert('Please enter a valid CNIC in the format: 36502-6011487-8');
        isValid = false;
      }

      if (!isValid) {
        e.preventDefault();
      }
    });
  </script>
</body>

</html>