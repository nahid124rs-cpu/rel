<?php
/**
 * create-admin.php
 * Creates a new WordPress admin user using credentials from wp-config.php
 * DELETE THIS FILE AFTER USE!
 */

// ========== SECURITY: secret key required ==========
// Access like: https://yoursite.com/create-admin.php?key=MY_SECRET_123
$SECRET_KEY = 'MY_SECRET_123'; // <-- change this!

if (!isset($_GET['key']) || $_GET['key'] !== $SECRET_KEY) {
    http_response_code(403);
    die('Access denied.');
}

// ========== 1. Read wp-config.php and extract DB credentials ==========
$configFile = __DIR__ . '/wp-config.php';
if (!file_exists($configFile)) {
    die('wp-config.php not found. Place this file in the WordPress root.');
}

$config = file_get_contents($configFile);

function getConfigValue($config, $constant) {
    if (preg_match("/define\s*\(\s*'".preg_quote($constant, '/')."'\s*,\s*'([^']*)'/i", $config, $m)) {
        return $m[1];
    }
    // Handle double quotes too
    if (preg_match('/define\s*\(\s*\''.preg_quote($constant, '/').'\'\s*,\s*"([^"]*)"/i', $config, $m)) {
        return $m[1];
    }
    return null;
}

function getTablePrefix($config) {
    if (preg_match('/\$table_prefix\s*=\s*[\'"]([^\'"]+)[\'"]/', $config, $m)) {
        return $m[1];
    }
    return 'wp_';
}

$dbHost = getConfigValue($config, 'DB_HOST') ?: 'localhost';
$dbName = getConfigValue($config, 'DB_NAME');
$dbUser = getConfigValue($config, 'DB_USER');
$dbPass = getConfigValue($config, 'DB_PASSWORD');
$prefix = getTablePrefix($config);

if (!$dbName || !$dbUser) {
    die('Could not read database credentials from wp-config.php');
}

// ========== 2. Ask for the new admin info (via browser form) ==========
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    ?>
    <!DOCTYPE html>
    <html>
    <head><title>Create WordPress Admin</title>
    <style>
        body{font-family:sans-serif;max-width:420px;margin:60px auto;padding:20px}
        input{width:100%;padding:10px;margin:6px 0 14px;box-sizing:border-box}
        button{padding:12px 20px;background:#2271b1;color:#fff;border:0;cursor:pointer;width:100%}
        .info{background:#f0f6fb;border-left:4px solid #2271b1;padding:10px;font-size:14px}
    </style>
    </head>
    <body>
        <h2>Create Admin User</h2>
        <p class="info">Connected to database: <b><?php echo htmlspecialchars($dbName); ?></b><br>
        Table prefix: <b><?php echo htmlspecialchars($prefix); ?></b></p>
        <form method="post">
            <label>Username</label>
            <input type="text" name="username" required>
            <label>Email</label>
            <input type="email" name="email" required>
            <label>Password</label>
            <input type="password" name="password" required minlength="8">
            <label>Display Name (optional)</label>
            <input type="text" name="display_name">
            <button type="submit">Create Admin User</button>
        </form>
    </body>
    </html>
    <?php
    exit;
}

// ========== 3. Create the admin user ==========
try {
    $pdo = new PDO(
        "mysql:host={$dbHost};dbname={$dbName};charset=utf8mb4",
        $dbUser,
        $dbPass,
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
    );

    $username    = trim($_POST['username']);
    $email       = trim($_POST['email']);
    $password    = $_POST['password'];
    $displayName = trim($_POST['display_name'] ?: $_POST['username']);

    // Check user doesn't already exist
    $stmt = $pdo->prepare("SELECT ID FROM {$prefix}users WHERE user_login = ? OR user_email = ?");
    $stmt->execute([$username, $email]);
    if ($stmt->fetch()) {
        die('Error: A user with this username or email already exists.');
    }

    // WordPress password hash (phpass-style MD5-based, WP-compatible)
    require_once __DIR__ . '/wp-includes/class-phpass.php';
    $hasher = new PasswordHash(8, true);
    $hash = $hasher->HashPassword($password);

    // Fallback if phpass class not available (use WP's own loader)
    if (empty($hash)) {
        require_once __DIR__ . '/wp-load.php';
        $hash = wp_hash_password($password);
    }

    // Insert user
    $stmt = $pdo->prepare("INSERT INTO {$prefix}users
        (user_login, user_pass, user_nicename, user_email, user_url, user_registered, user_status, display_name)
        VALUES (?, ?, ?, ?, '', NOW(), 0, ?)");
    $stmt->execute([$username, $hash, sanitize($username), $email, $displayName]);
    $userId = $pdo->lastInsertId();

    // Assign Administrator role
    $stmt = $pdo->prepare("INSERT INTO {$prefix}usermeta (user_id, meta_key, meta_value) VALUES (?, ?, ?)");
    $stmt->execute([$userId, "{$prefix}capabilities", 'a:1:{s:13:"administrator";s:1:"1";}']);
    $stmt->execute([$userId, "{$prefix}user_level", '10']);

    echo "<h2>✅ Success!</h2>
          <p>Admin user <b>" . htmlspecialchars($username) . "</b> created (ID: {$userId}).</p>
          <p><a href='/wp-login.php'>Go to login</a></p>
          <p style='color:red'><b>NOW DELETE THIS FILE (create-admin.php) FROM YOUR SERVER!</b></p>";

} catch (PDOException $e) {
    die('Database error: ' . htmlspecialchars($e->getMessage()));
}

function sanitize($str) {
    return strtolower(preg_replace('/[^a-zA-Z0-9_-]/', '-', $str));
}
