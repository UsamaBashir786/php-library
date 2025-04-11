<?php
class Permission
{
  private $db;

  public function __construct()
  {
    $this->db = (new Database())->getConnection();
  }

  public function assignPermissionToRole($roleId, $permissionId)
  {
    $stmt = $this->db->prepare("INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)");
    return $stmt->execute([$roleId, $permissionId]);
  }

  public function hasPermission($userId, $permissionName)
  {
    $stmt = $this->db->prepare("
            SELECT COUNT(*) 
            FROM permissions p 
            JOIN role_permissions rp ON p.id = rp.permission_id 
            JOIN user_roles ur ON rp.role_id = ur.role_id 
            WHERE ur.user_id = ? AND p.name = ?
        ");
    $stmt->execute([$userId, $permissionName]);
    return $stmt->fetchColumn() > 0;
  }
}
