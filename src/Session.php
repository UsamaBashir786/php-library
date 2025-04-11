<?php
class Session
{
  public function __construct()
  {
    if (session_status() === PHP_SESSION_NONE) {
      session_start();
    }
  }

  public function set($key, $value)
  {
    $_SESSION[$key] = $value;
  }

  public function get($key)
  {
    return isset($_SESSION[$key]) ? $_SESSION[$key] : null;
  }

  public function destroy()
  {
    session_destroy();
    $_SESSION = [];
  }

  public function generateCsrfToken()
  {
    $token = bin2hex(random_bytes(32));
    $this->set('csrf_token', $token);
    return $token;
  }

  public function verifyCsrfToken($token)
  {
    return $this->get('csrf_token') === $token;
  }
}
