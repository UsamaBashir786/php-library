<?php
require_once __DIR__ . '/../config/database.php';

class User {
    private $db;
    private $session;

    public function __construct(Session $session) {
        $this->db = (new Database())->getConnection();
        $this->session = $session;
    }

    public function register($username, $email, $password) {
        $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
        $stmt = $this->db->prepare("INSERT INTO users (username, email, password) VALUES (?, ?, ?)");
        return $stmt->execute([$username, $email, $hashedPassword]);
    }

    public function login($email, $password) {
        $stmt = $this->db->prepare("SELECT * FROM users WHERE email = ?");
        $stmt->execute([$email]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user && password_verify($password, $user['password'])) {
            $this->session->set('user_id', $user['id']);
            $this->session->set('username', $user['username']);
            return true;
        }
        return false;
    }

    public function logout() {
        $this->session->destroy();
    }

    public function isAuthenticated() {
        return $this->session->get('user_id') !== null;
    }

    public function getUserId() {
        return $this->session->get('user_id');
    }
}