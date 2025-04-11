<?php
class Database
{
  private $pdo;
  public function __construct()
  {
    $host = 'localhost';
    $dbname = 'role_auth';
    $username = 'root'; // Update if you set a different username
    $password = '';     // Update if you set a password
    try {
      $this->pdo = new PDO("mysql:host=$host;dbname=$dbname;charset=utf8", $username, $password);
      $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    } catch (PDOException $e) {
      die("Database connection failed: " . $e->getMessage());
    }
  }
  public function getConnection()
  {
    return $this->pdo;
  }
}
