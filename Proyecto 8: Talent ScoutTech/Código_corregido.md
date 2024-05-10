# Código corregido

## Índice

1. [insert_player.php](#1)
2. [register.php](#2)
3. [auth.php](#3)
4. [show_comments.php](#4)
5. [register.php](#5)
6. [add_comment.php](#6)

## insert_player.php  <div id="1" />


```html
<?php
require_once dirname(__FILE__) . '/private/conf.php';

# Requiere usuarios autenticados
require dirname(__FILE__) . '/private/auth.php';

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    # Verificar si los campos del formulario están definidos y no están vacíos
    if (isset($_POST['name']) && isset($_POST['team']) && !empty($_POST['name']) && !empty($_POST['team'])) {
        # Sanitizar las entradas de usuario
        $name = SQLite3::escapeString($_POST['name']);
        $team = SQLite3::escapeString($_POST['team']);

        # Insertar o reemplazar jugador en la base de datos
        if (isset($_GET['id'])) {
            $playerId = SQLite3::escapeString($_GET['id']);
            $query = "INSERT OR REPLACE INTO players (playerid, name, team) VALUES ('$playerId', '$name', '$team')";
        } else {
            $query = "INSERT INTO players (name, team) VALUES ('$name', '$team')";
        }

        # Ejecutar la consulta
        $result = $db->query($query) or die("Consulta inválida");

        # Redireccionar a la página de lista de jugadores
        header("Location: list_players.php");
        exit();
    } else {
        # Si alguno de los campos está vacío, mostrar un mensaje de error
        echo "Por favor, complete todos los campos.";
    }
}

# Obtener y mostrar el formulario para editar jugador
if (isset($_GET['id'])) {
    $id = SQLite3::escapeString($_GET['id']);

    $query = "SELECT name, team FROM players WHERE playerid = '$id'";
    $result = $db->query($query) or die ("Consulta inválida");

    if ($row = $result->fetchArray()) {
        $name = htmlspecialchars($row['name']);
        $team = htmlspecialchars($row['team']);
    }
}

?>
<!doctype html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport"
          content="width=device-width, user-scalable=no, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <link rel="stylesheet" href="css/style.css">
    <title>Práctica RA3 - Players list</title>
</head>
<body>
    <header>
        <h1>Player</h1>
    </header>
    <main class="player">
        <form action="#" method="post">
            <?php if (isset($_GET['id'])): ?>
                <input type="hidden" name="id" value="<?= $id ?>">
            <?php endif; ?>
            <h3>Player name</h3>
            <textarea name="name"><?php if (isset($name)) echo $name; ?></textarea><br>
            <h3>Team name</h3>
            <textarea name="team"><?php if (isset($team)) echo $team; ?></textarea><br>
            <input type="submit" value="Send">
        </form>
        <form action="#" method="post" class="menu-form">
            <a href="index.php">Back to home</a>
            <a href="list_players.php">Back to list</a>
            <input type="submit" name="Logout" value="Logout" class="logout">
        </form>
    </main>
    <footer class="listado">
        <img src="images/logo-iesra-cadiz-color-blanco.png">
        <h4>Puesta en producción segura</h4>
        < Please <a href="http://www.donate.co?amount=100&amp;destination=ACMEScouting/"> donate</a> >
    </footer>
</body>
</html>
```

## register.php <div id="2" />

```html
<?php
require_once dirname(__FILE__) . '/private/conf.php';

# Require logged users
# require dirname(__FILE__) . '/private/auth.php';

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    # Verificar si los campos del formulario están definidos y no están vacíos
    if (isset($_POST['username']) && isset($_POST['password']) && !empty($_POST['username']) && !empty($_POST['password'])) {
        # Sanitizar las entradas de usuario
        $username = SQLite3::escapeString($_POST['username']);
        $password = password_hash($_POST['password'], PASSWORD_DEFAULT); // Hash de la contraseña

        # Insertar usuario en la base de datos
        $query = "INSERT INTO users (username, password) VALUES ('$username', '$password')";
        $result = $db->query($query) or die("Consulta inválida");

        # Redireccionar a la página de lista de jugadores después del registro exitoso
        header("Location: list_players.php");
        exit();
    } else {
        # Si alguno de los campos está vacío, mostrar un mensaje de error
        $error_message = "Por favor, complete todos los campos.";
    }
}
?>

<!doctype html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport"
          content="width=device-width, user-scalable=no, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <link rel="stylesheet" href="css/style.css">
    <title>Práctica RA3 - Register</title>
</head>
<body>
    <header>
        <h1>Register</h1>
    </header>
    <main class="player">
        <?php if (isset($error_message)): ?>
            <p><?php echo $error_message; ?></p>
        <?php endif; ?>
        <form action="#" method="post">
            <label>Username:</label>
            <input type="text" name="username">
            <label>Password:</label>
            <input type="password" name="password">
            <input type="submit" value="Send">
        </form>
        <form action="#" method="post" class="menu-form">
            <a href="list_players.php">Back to list</a>
            <input type="submit" name="Logout" value="Logout" class="logout">
        </form>
    </main>
    <footer class="listado">
        <img src="images/logo-iesra-cadiz-color-blanco.png">
        <h4>Puesta en producción segura</h4>
        < Please <a href="http://www.donate.co?amount=100&amp;destination=ACMEScouting/"> donate</a> >
    </footer>
</body>
</html>

```

## auth.php <div id="3" />

```html
<?php
require_once dirname(__FILE__) . '/conf.php';

$userId = FALSE;

# Función para escapar caracteres y evitar SQL injection
function escapeString($value) {
    global $db;
    return SQLite3::escapeString($value);
}

# Función para verificar si el usuario y la contraseña son válidos; devuelve true si son válidos
function areUserAndPasswordValid($user, $password) {
    global $db, $userId;

    $user = escapeString($user);
    $password = escapeString($password);

    $query = 'SELECT userId, password FROM users WHERE username = "' . $user . '"';
    $result = $db->query($query) or die ("Invalid query: " . $query . ". Field user introduced is: " . $user);
    $row = $result->fetchArray();

    if ($row && $password == $row['password']) {
        $userId = $row['userId'];
        $_COOKIE['userId'] = $userId;
        return true;
    } else {
        return false;
    }
}

# En el inicio de sesión
if (isset($_POST['username']) && isset($_POST['password'])) {
    $_COOKIE['user'] = $_POST['username'];
    $_COOKIE['password'] = $_POST['password'];
}

# Al cerrar sesión
if (isset($_POST['Logout'])) {
    # Eliminar cookies
    setcookie('user', '', time() - 3600);
    setcookie('password', '', time() - 3600);
    setcookie('userId', '', time() - 3600);

    unset($_COOKIE['user']);
    unset($_COOKIE['password']);
    unset($_COOKIE['userId']);

    header("Location: index.php");
    exit();
}

# Verificar usuario y contraseña
if (isset($_COOKIE['user']) && isset($_COOKIE['password'])) {
    if (areUserAndPasswordValid($_COOKIE['user'], $_COOKIE['password'])) {
        $login_ok = true;
        $error = "";
    } else {
        $login_ok = false;
        $error = "Invalid user or password.<br>";
    }
} else {
    $login_ok = false;
    $error = "This page requires you to be logged in.<br>";
}

if (!$login_ok) {
    ?>
    <!doctype html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport"
              content="width=device-width, user-scalable=no, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0">
        <meta http-equiv="X-UA-Compatible" content="ie=edge">
        <link rel="stylesheet" href="css/style.css">
        <title>Práctica RA3 - Authentication page</title>
    </head>
    <body>
    <header class="auth">
        <h1>Authentication page</h1>
    </header>
    <section class="auth">
        <div class="message">
            <?= $error ?>
        </div>
        <section>
            <div>
                <h2>Login</h2>
                <form action="#" method="post">
                    <label>User</label>
                    <input type="text" name="username"><br>
                    <label>Password</label>
                    <input type="password" name="password"><br>
                    <input type="submit" value="Login">
                </form>
            </div>

            <div>
                <h2>Logout</h2>
                <form action="#" method="post">
                    <input type="submit" name="Logout" value="Logout">
                </form>
            </div>
        </section>
    </section>
    <footer>
        <h4>Puesta en producción segura</h4>
        < Please <a href="http://www.donate.co?amount=100&amp;destination=ACMEScouting/"> donate</a> >
    </footer>
    <?php
    exit();
}

setcookie('user', $_COOKIE['user']);
setcookie('password', $_COOKIE['password']);
?>

```

## show_comments.php <div id="4" />

```html
<!doctype html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport"
          content="width=device-width, user-scalable=no, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <link rel="stylesheet" href="css/style.css">
    <title>Práctica RA3 - Comments editor</title>
</head>
<body>
<header>
    <h1>Comments editor</h1>
</header>
<main class="player">

<?php
require_once dirname(__FILE__) . '/private/conf.php';

# Require logged users
require dirname(__FILE__) . '/private/auth.php';

# List comments
if (isset($_GET['id']) && is_numeric($_GET['id'])) { // Asegurar que 'id' sea numérico
    $playerId = $_GET['id'];
    $playerId = SQLite3::escapeString($playerId); // Evitar SQL injection

    $query = "SELECT commentId, username, body FROM comments C, users U WHERE C.playerId = $playerId AND U.userId = C.userId ORDER BY C.playerId DESC";

    $result = $db->query($query) or die("Invalid query: " . $query);

    while ($row = $result->fetchArray()) {
        $username = htmlspecialchars($row['username']); // Sanitizar salida de datos
        $body = htmlspecialchars($row['body']); // Sanitizar salida de datos
        echo "<div>
                <h4>$username</h4> 
                <p>commented: $body</p>
              </div>";
    }
} else {
    echo "Invalid player ID";
}

?>

<div>
    <a href="list_players.php">Back to list</a>
    <a class="black" href="add_comment.php?id=<?php echo $playerId; ?>"> Add comment</a> <!-- Asegurar que $playerId está definido -->
</div>

</main>
<footer class="listado">
    <img src="images/logo-iesra-cadiz-color-blanco.png">
    <h4>Puesta en producción segura</h4>
    < Please <a href="http://www.donate.co?amount=100&amp;destination=ACMEScouting/"> donate</a> >
</footer>
</body>
</html>

```

## register.php <div id="5" />

```html
<?php
require_once dirname(__FILE__) . '/private/conf.php';

if (isset($_POST['username']) && isset($_POST['password'])) {
    $username = filter_input(INPUT_POST, 'username', FILTER_SANITIZE_STRING);
    $password = filter_input(INPUT_POST, 'password', FILTER_SANITIZE_STRING);
    
    // Hash the password securely
    $hashed_password = password_hash($password, PASSWORD_DEFAULT);

    $query = $db->prepare("INSERT INTO users (username, password) VALUES (?, ?)");
    $query->bindValue(1, $username, SQLITE3_TEXT);
    $query->bindValue(2, $hashed_password, SQLITE3_TEXT);
    
    if ($query->execute()) {
        header("Location: list_players.php");
        exit;
    } else {
        die("Error en el registro. Por favor, inténtelo de nuevo más tarde.");
    }
}

?>
<!doctype html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport"
          content="width=device-width, user-scalable=no, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <link rel="stylesheet" href="css/style.css">
    <title>Práctica RA3 - Players list</title>
</head>
<body>
    <header>
        <h1>Register</h1>
    </header>
    <main class="player">
        <form action="#" method="post">
            <input type="hidden" name="id" value="<?=$id?>">
            <label>Username:</label>
            <input type="text" name="username">
            <label>Password:</label>
            <input type="password" name="password">
            <input type="submit" value="Send">
        </form>
            <form action="#" method="post" class="menu-form">
            <a href="list_players.php">Back to list</a>
            <input type="submit" name="Logout" value="Logout" class="logout">
        </form>
    </main>
    <footer class="listado">
        <img src="images/logo-iesra-cadiz-color-blanco.png">
        <h4>Puesta en producción segura</h4>
        < Please <a href="http://www.donate.co?amount=100&amp;destination=ACMEScouting/"> donate</a> >
    </footer>
</body>
</html>

```

## add_comment.php <div id="6" />

```html
<?php
require_once dirname(__FILE__) . '/private/conf.php';

# Require logged users
require dirname(__FILE__) . '/private/auth.php';

if (isset($_POST['body']) && isset($_GET['id'])) {
    # Just in from POST => save to database
    $body = filter_input(INPUT_POST, 'body', FILTER_SANITIZE_STRING);
    
    $query = $db->prepare("INSERT INTO comments (playerId, userId, body) VALUES (:playerId, :userId, :body)");
    $query->bindValue(':playerId', $_GET['id'], SQLITE3_INTEGER);
    $query->bindValue(':userId', $_COOKIE['userId'], SQLITE3_INTEGER);
    $query->bindValue(':body', $body, SQLITE3_TEXT);
    
    if ($query->execute()) {
        header("Location: list_players.php");
    } else {
        die("Error: Unable to add comment.");
    }
}

# Show form
?>
<!doctype html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport"
          content="width=device-width, user-scalable=no, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <link rel="stylesheet" href="css/style.css">
    <title>Práctica RA3 - Comments creator</title>
</head>
<body>
<header>
    <h1>Comments creator</h1>
</header>
<main class="player">
    <form action="#" method="post">
        <h3>Write your comment</h3>
        <textarea name="body"></textarea>
        <input type="submit" value="Send">
    </form>
    <form action="#" method="post" class="menu-form">
        <a href="list_players.php">Back to list</a>
        <input type="submit" name="Logout" value="Logout" class="logout">
    </form>
</main>
<footer class="listado">
    <img src="images/logo-iesra-cadiz-color-blanco.png">
    <h4>Puesta en producción segura</h4>
    < Please <a href="http://www.donate.co?amount=100&amp;destination=ACMEScouting/"> donate</a> >
</footer>
</body>
</html>

```
