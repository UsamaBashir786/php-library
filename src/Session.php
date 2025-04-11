<?php
class Session
{
  private $sessionStarted = false;

  public function __construct()
  {
    $this->startSession();
  }

  /**
   * Start the session with secure settings
   */
  private function startSession()
  {
    if (session_status() === PHP_SESSION_NONE) {
      // Set secure session settings
      ini_set('session.use_only_cookies', 1); // Prevent session ID in URL
      ini_set('session.cookie_httponly', 1);  // Prevent JavaScript access to session cookie
      ini_set('session.cookie_secure', 0);    // Set to 1 in production with HTTPS
      ini_set('session.cookie_samesite', 'Lax'); // Mitigate CSRF

      // Start the session
      if (session_start()) {
        $this->sessionStarted = true;
        error_log("Session started successfully. Session ID: " . session_id());
      } else {
        error_log("Failed to start session.");
        throw new Exception("Failed to start session.");
      }
    } else {
      $this->sessionStarted = true;
      error_log("Session already active. Session ID: " . session_id());
    }

    // Regenerate session ID on first start to prevent fixation
    if (!isset($_SESSION['initialized'])) {
      session_regenerate_id(true);
      $_SESSION['initialized'] = true;
      error_log("Session ID regenerated to prevent fixation.");
    }
  }

  /**
   * Check if the session is active
   */
  public function isSessionStarted()
  {
    return $this->sessionStarted;
  }

  /**
   * Set a session variable
   */
  public function set($key, $value)
  {
    if (!$this->sessionStarted) {
      error_log("Session not started. Cannot set key: $key");
      throw new Exception("Session not started. Cannot set session data.");
    }
    $_SESSION[$key] = $value;
    error_log("Session set - Key: $key, Value: " . (is_scalar($value) ? $value : json_encode($value)));
  }

  /**
   * Get a session variable
   */
  public function get($key)
  {
    if (!$this->sessionStarted) {
      error_log("Session not started. Cannot get key: $key");
      return null;
    }
    $value = isset($_SESSION[$key]) ? $_SESSION[$key] : null;
    error_log("Session get - Key: $key, Value: " . (is_null($value) ? 'null' : (is_scalar($value) ? $value : json_encode($value))));
    return $value;
  }

  /**
   * Destroy the session
   */
  public function destroy()
  {
    if ($this->sessionStarted) {
      session_unset();
      session_destroy();
      $_SESSION = [];
      $this->sessionStarted = false;
      error_log("Session destroyed.");
    }
  }

  /**
   * Generate a CSRF token
   */
  public function generateCsrfToken()
  {
    $token = bin2hex(random_bytes(32));
    $this->set('csrf_token', $token);
    error_log("CSRF token generated: $token");
    return $token;
  }

  /**
   * Verify a CSRF token
   */
  public function verifyCsrfToken($token)
  {
    $storedToken = $this->get('csrf_token');
    $isValid = $storedToken === $token;
    error_log("CSRF token verification - Stored: $storedToken, Provided: $token, Valid: " . ($isValid ? 'true' : 'false'));
    return $isValid;
  }

  /**
   * Regenerate session ID (e.g., after login)
   */
  public function regenerateId()
  {
    if ($this->sessionStarted) {
      session_regenerate_id(true);
      error_log("Session ID regenerated: " . session_id());
    }
  }
}
