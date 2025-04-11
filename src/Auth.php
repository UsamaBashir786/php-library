<?php
require_once __DIR__ . '/User.php';
require_once __DIR__ . '/Role.php';
require_once __DIR__ . '/Permission.php';
require_once __DIR__ . '/Session.php';

class Auth
{
  private $user;
  private $role;
  private $permission;
  private $session;

  public function __construct()
  {
    $this->session = new Session();
    $this->user = new User($this->session);
    $this->role = new Role();
    $this->permission = new Permission();
  }

  public function getUser()
  {
    return $this->user;
  }

  public function getSession()
  {
    return $this->session;
  }

  public function register($username, $email, $password, $contactNumber = null, $cnic = null)
  {
    return $this->user->register($username, $email, $password, $contactNumber, $cnic);
  }

  public function login($email, $password)
  {
    return $this->user->login($email, $password);
  }

  public function logout()
  {
    $this->user->logout();
  }

  public function isAuthenticated()
  {
    return $this->user->isAuthenticated();
  }

  public function hasRole($userId, $roleName)
  {
    return in_array($roleName, $this->role->getUserRoles($userId));
  }

  public function hasPermission($userId, $permissionName)
  {
    return $this->permission->hasPermission($userId, $permissionName);
  }

  public function assignRole($userId, $roleId)
  {
    return $this->role->assignRole($userId, $roleId);
  }

  public function assignPermissionToRole($roleId, $permissionId)
  {
    return $this->permission->assignPermissionToRole($roleId, $permissionId);
  }

  public function generateCsrfToken()
  {
    return $this->session->generateCsrfToken();
  }

  public function verifyCsrfToken($token)
  {
    return $this->session->verifyCsrfToken($token);
  }
}
