<?php
session_start();
$conn = new mysqli("localhost", "root", "", "cberp"); // Replace with your DB details

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Login Handling
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['login'])) {
    if (isset($_POST['username']) && isset($_POST['password'])) {
        $usernameOrEmail = $conn->real_escape_string(trim($_POST['username']));
        $password = trim($_POST['password']);

        // Use prepared statement to prevent SQL injection
        $stmt = $conn->prepare("SELECT id, username, password FROM user WHERE username = ? OR email = ?");
        $stmt->bind_param("ss", $usernameOrEmail, $usernameOrEmail);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows > 0) {
            $row = $result->fetch_assoc();
            if (password_verify($password, $row['password'])) {
                // Set session variables
                $_SESSION['id'] = $row['id'];
                $_SESSION['username'] = $row['username'];

                // Redirect to the dashboard
                header("Location: dashboard.php");
                exit();
            } else {
                $error = "Invalid password.";
            }
        } else {
            $error = "No user found with that username or email.";
        }
    } else {
        $error = "Please enter both username and password.";
    }
}

// Registration Handling
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['register'])) {
    if (isset($_POST['reg_username'], $_POST['email'], $_POST['reg_password'])) {
        $username = $conn->real_escape_string(trim($_POST['reg_username']));
        $email = $conn->real_escape_string(trim($_POST['email']));
        $password = trim($_POST['reg_password']);

        // Check if the username or email already exists
        $stmt = $conn->prepare("SELECT id FROM user WHERE username = ? OR email = ?");
        $stmt->bind_param("ss", $username, $email);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows > 0) {
            $error = "Username or email already exists.";
        } else {
            // Hash the password for security
            $hashedPassword = password_hash($password, PASSWORD_BCRYPT);

            // Insert the new user into the database
            $stmt = $conn->prepare("INSERT INTO user (username, email, password, created_at) VALUES (?, ?, ?, NOW())");
            $stmt->bind_param("sss", $username, $email, $hashedPassword);

            if ($stmt->execute()) {
                $success = "Registration successful! You can now log in.";
            } else {
                $error = "Registration failed. Please try again.";
            }
        }
    } else {
        $error = "Please fill in all fields.";
    }
}
?>




<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login Page</title>
    <link href='https://unpkg.com/boxicons@2.1.4/css/boxicons.min.css' rel='stylesheet'>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <?php if (isset($error)) echo "<p class='error'>$error</p>"; ?>
        <?php if (isset($success)) echo "<p class='success'>$success</p>"; ?>

        <!-- Login Form -->
        <div class="form-box login">
            <form method="POST" action="">
                <h1>Login</h1>
                <div class="input-box">
                    <input type="text" name="username" placeholder="Email or UserName" required>
                    <i class='bx bxs-user'></i>
                </div>
                <div class="input-box">
                    <input type="password" name="password" placeholder="Password" required>
                    <i class='bx bxs-lock-alt'></i>
                </div>
                <button type="submit" name="login" class="btn">Login</button>
            </form>
        </div>

        <!-- Registration Form -->
        <div class="form-box register">
            <form method="POST" action="">
                <h1>Registration</h1>
                <div class="input-box">
                    <input type="text" name="reg_username" placeholder="Username" required>
                    <i class='bx bxs-user'></i>
                </div>
                <div class="input-box">
                    <input type="email" name="email" placeholder="Email" required>
                    <i class='bx bxs-envelope'></i>
                </div>
                <div class="input-box">
                    <input type="password" name="reg_password" placeholder="Password" required>
                    <i class='bx bxs-lock-alt'></i>
                </div>
                <button type="submit" name="register" class="btn">Register</button>
            </form>
        </div>
        
        <div class="toggle-box">
            <div class="toggle-panel toggle-left">
                <h1>Welcome!</h1>
                <p>Don't have an account?</p>
                <button class="btn register-btn">Register</button>
            </div>
            <div class="toggle-panel toggle-right">
                <h1>Welcome Back!</h1>
                <p>Already have an account?</p>
                <button class="btn login-btn">Login</button>
            </div>
        </div>
    </div>
    <script src="script.js"></script>
</body>
</html>
