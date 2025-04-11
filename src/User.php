<?php
require_once __DIR__ . '/../config/database.php';

class User
{
  private $db;
  private $session;
  private $rememberTokenExpiry = 30; // Days the remember token is valid

  public function __construct(Session $session)
  {
    $this->db = (new Database())->getConnection();
    $this->session = $session;

    // Check for remember me cookie
    $this->checkRememberMeCookie();
  }

  public function register($username, $email, $password, $contactNumber = null, $cnic = null)
  {
    $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

    $stmt = $this->db->prepare("INSERT INTO users (username, email, password, contact_number, cnic) VALUES (?, ?, ?, ?, ?)");
    if ($stmt->execute([$username, $email, $hashedPassword, $contactNumber, $cnic])) {
      return $this->db->lastInsertId();
    }
    return false;
  }

  public function login($email, $password, $remember = false)
  {
    $stmt = $this->db->prepare("SELECT * FROM users WHERE email = ?");
    $stmt->execute([$email]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($user && password_verify($password, $user['password'])) {
      $this->session->set('user_id', $user['id']);
      $this->session->set('username', $user['username']);

      // Set remember me cookie if requested
      if ($remember) {
        $this->setRememberMeCookie($user['id']);
      }

      return true;
    }
    return false;
  }

  public function logout()
  {
    // Clear remember me cookie if exists
    if (isset($_COOKIE['remember_token'])) {
      $this->clearRememberMeCookie();
    }

    $this->session->destroy();
  }

  public function isAuthenticated()
  {
    return $this->session->get('user_id') !== null;
  }

  public function getUserId()
  {
    return $this->session->get('user_id');
  }

  /**
   * Set remember me cookie and store token in database
   */
  private function setRememberMeCookie($userId)
  {
    // Generate a unique token
    $token = bin2hex(random_bytes(32));
    $hashedToken = hash('sha256', $token);

    // Set expiry date
    $expiryDate = date('Y-m-d H:i:s', strtotime("+{$this->rememberTokenExpiry} days"));

    // Store token in database
    $stmt = $this->db->prepare("
            INSERT INTO user_remember_tokens (user_id, token, expires_at) 
            VALUES (?, ?, ?)
            ON DUPLICATE KEY UPDATE token = ?, expires_at = ?
        ");
    $stmt->execute([$userId, $hashedToken, $expiryDate, $hashedToken, $expiryDate]);

    // Set cookie
    $cookieValue = $userId . ':' . $token;
    setcookie(
      'remember_token',
      $cookieValue,
      time() + (86400 * $this->rememberTokenExpiry), // 86400 seconds = 1 day
      '/', // Path
      '', // Domain
      false, // Secure (set to true if using HTTPS)
      true // HttpOnly
    );
  }

  /**
   * Check if remember me cookie exists and is valid
   */
  private function checkRememberMeCookie()
  {
    if (isset($_COOKIE['remember_token']) && !$this->isAuthenticated()) {
      list($userId, $token) = explode(':', $_COOKIE['remember_token']);
      $hashedToken = hash('sha256', $token);

      $stmt = $this->db->prepare("
                SELECT u.* FROM users u
                JOIN user_remember_tokens rt ON u.id = rt.user_id
                WHERE rt.user_id = ? AND rt.token = ? AND rt.expires_at > NOW()
            ");
      $stmt->execute([$userId, $hashedToken]);
      $user = $stmt->fetch(PDO::FETCH_ASSOC);

      if ($user) {
        // Set user as logged in
        $this->session->set('user_id', $user['id']);
        $this->session->set('username', $user['username']);

        // Refresh token
        $this->setRememberMeCookie($user['id']);
      } else {
        // Invalid token, clear cookie
        $this->clearRememberMeCookie();
      }
    }
  }

  /**
   * Clear the remember me cookie and remove token from database
   */
  private function clearRememberMeCookie()
  {
    if (isset($_COOKIE['remember_token'])) {
      list($userId, $token) = explode(':', $_COOKIE['remember_token']);
      $hashedToken = hash('sha256', $token);

      // Remove token from database
      $stmt = $this->db->prepare("DELETE FROM user_remember_tokens WHERE user_id = ? AND token = ?");
      $stmt->execute([$userId, $hashedToken]);

      // Expire cookie
      setcookie('remember_token', '', time() - 3600, '/');
    }
  }
}
