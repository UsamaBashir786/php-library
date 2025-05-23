# RoleAuth - PHP Role-Based Authentication System

RoleAuth is a flexible, secure PHP library that provides role-based authentication for your web applications. It offers a complete solution with user management, role-based access control, permissions, and OAuth integration with popular providers.

[![Latest Version on Packagist](https://img.shields.io/packagist/v/your-vendor-name/role-auth.svg?style=flat-square)](https://packagist.org/packages/your-vendor-name/role-auth)
[![Total Downloads](https://img.shields.io/packagist/dt/your-vendor-name/role-auth.svg?style=flat-square)](https://packagist.org/packages/your-vendor-name/role-auth)

## Features

- **Secure Authentication**: User registration, login, and session management
- **Role-Based Access Control**: Assign users to roles with specific permissions
- **Fine-Grained Permissions**: Control access at granular levels
- **OAuth Integration**: Login with Google, Facebook, and GitHub
- **Remember Me Functionality**: Persistent login sessions
- **CSRF Protection**: Built-in Cross-Site Request Forgery protection
- **Modern UI Components**: Bootstrap-based responsive interface examples
- **Flexible Configuration**: Customizable to fit your application needs

## Requirements

- PHP 7.2 or higher
- MySQL/MariaDB database
- Composer dependency manager
- PDO PHP extension

## Installation

### 1. Install via Composer

```bash
composer require your-vendor-name/role-auth
```

### 2. Set up the database

Run the SQL script to create the necessary tables:

```bash
mysql -u yourusername -p yourdatabase < vendor/your-vendor-name/role-auth/resources/database.sql
```

Or manually import the SQL file from `vendor/your-vendor-name/role-auth/resources/database.sql` into your database.

### 3. Configure the database connection

Create a configuration file with your database credentials:

```php
<?php
// config/database_config.php

return [
    'host' => 'localhost',
    'dbname' => 'your_database',
    'username' => 'your_username',
    'password' => 'your_password',
];
```

### 4. (Optional) Configure OAuth providers

If you want to use OAuth authentication, set up your OAuth credentials:

```php
<?php
// config/oauth_config.php

return [
    'google' => [
        'clientId' => 'YOUR_GOOGLE_CLIENT_ID',
        'clientSecret' => 'YOUR_GOOGLE_CLIENT_SECRET',
        'redirectUri' => 'https://your-domain.com/oauth_callback.php?provider=google',
    ],
    'facebook' => [
        'clientId' => 'YOUR_FACEBOOK_APP_ID',
        'clientSecret' => 'YOUR_FACEBOOK_APP_SECRET',
        'redirectUri' => 'https://your-domain.com/oauth_callback.php?provider=facebook',
    ],
    'github' => [
        'clientId' => 'YOUR_GITHUB_CLIENT_ID',
        'clientSecret' => 'YOUR_GITHUB_CLIENT_SECRET',
        'redirectUri' => 'https://your-domain.com/oauth_callback.php?provider=github',
    ],
];
```

## Quick Start

### Basic Authentication

```php
<?php
require_once 'vendor/autoload.php';

use YourVendorName\RoleAuth\Auth;

// Create a new authentication instance
$auth = new Auth();

// Check if a user is authenticated
if ($auth->isAuthenticated()) {
    echo "Welcome, " . $auth->getSession()->get('username');
} else {
    echo "Please log in.";
}

// Check if user has a specific role
$userId = $auth->getUser()->getUserId();
if ($auth->hasRole($userId, 'Admin')) {
    echo "You have admin privileges.";
}

// Check if user has a specific permission
if ($auth->hasPermission($userId, 'edit_content')) {
    echo "You can edit content.";
}
```

### User Registration

```php
<?php
require_once 'vendor/autoload.php';

use YourVendorName\RoleAuth\Auth;

$auth = new Auth();

// Register a new user
$userId = $auth->register('username', 'user@example.com', 'password123');

if ($userId) {
    // Assign a role to the user
    $auth->assignRole($userId, 1); // Assign 'User' role (ID: 1)
    echo "User registered successfully!";
} else {
    echo "Registration failed.";
}
```

### User Login

```php
<?php
require_once 'vendor/autoload.php';

use YourVendorName\RoleAuth\Auth;

$auth = new Auth();

// Log in a user
if ($auth->login('user@example.com', 'password123', true)) { // true enables "Remember Me"
    header('Location: dashboard.php');
    exit;
} else {
    echo "Invalid credentials.";
}
```

### Permissions and Roles

```php
<?php
require_once 'vendor/autoload.php';

use YourVendorName\RoleAuth\Auth;

$auth = new Auth();

// Assign a permission to a role
$auth->assignPermissionToRole(2, 1); // Assign permission ID 1 to role ID 2
```

## Security Features

### CSRF Protection

The library includes built-in CSRF protection for forms:

```php
<!-- In your form -->
<input type="hidden" name="csrf_token" value="<?php echo $auth->generateCsrfToken(); ?>">

<!-- When processing the form -->
if (!$auth->verifyCsrfToken($_POST['csrf_token'])) {
    die('CSRF token validation failed');
}
```

### Password Security

Passwords are securely hashed using PHP's `password_hash()` function with the default algorithm (currently BCRYPT).

## Advanced Usage

### OAuth Authentication

```php
<?php
require_once 'vendor/autoload.php';

use YourVendorName\RoleAuth\Auth;

$auth = new Auth();

// Redirect to OAuth provider
$provider = 'google'; // or 'facebook', 'github'
$authUrl = $auth->getOAuthAuthorizationUrl($provider);
header('Location: ' . $authUrl);
exit;

// In your callback file
try {
    $userId = $auth->handleOAuthCallback($_GET['provider'], $_GET);
    if ($userId) {
        // User authenticated successfully
        header('Location: dashboard.php');
        exit;
    }
} catch (Exception $e) {
    echo "OAuth Error: " . $e->getMessage();
}
```

### Custom Database Configuration

You can customize the database connection by extending the Database class:

```php
<?php
namespace YourApp;

use YourVendorName\RoleAuth\Database;

class CustomDatabase extends Database
{
    public function __construct()
    {
        $config = require 'path/to/your/config.php';
        
        $host = $config['host'];
        $dbname = $config['dbname'];
        $username = $config['username'];
        $password = $config['password'];
        
        parent::__construct($host, $dbname, $username, $password);
    }
}
```

## Example Pages

The package includes several example implementations:

- Login page
- Registration page
- User dashboard
- Admin panel
- User management
- Role management
- Permission management

You can find these examples in the `examples` directory.

## Customization

### Styling

The example pages include Bootstrap 5 and Font Awesome for styling. You can easily modify the styles to match your application's design.

### Localization

To translate error messages and other text, you can extend the classes and override the methods that return text strings.

## Support

For bug reports and feature requests, please use the [GitHub issue tracker](https://github.com/your-username/role-auth/issues).

## License

The RoleAuth package is open-source software licensed under the [MIT license](LICENSE).

## Credits

- Created by [Your Name]
- OAuth integration powered by [league/oauth2-client](https://github.com/thephpleague/oauth2-client)
- Example UI built with [Bootstrap](https://getbootstrap.com/)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.