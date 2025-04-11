<?php
class Role
{
  private $db;

  public function __construct()
  {
    $this->db = (new Database())->getConnection();
  }

  public function assignRole($userId, $roleId)
  {
    $stmt = $this->db->prepare("INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)");
    return $stmt->execute([$userId, $roleId]);
  }

  public function getUserRoles($userId)
  {
    $stmt = $this->db->prepare("SELECT r.name FROM roles r JOIN user_roles ur ON r.id = ur.role_id WHERE ur.user_id = ?");
    $stmt->execute([$userId]);
    return $stmt->fetchAll(PDO::FETCH_COLUMN);
  }
}
