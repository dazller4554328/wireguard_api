
<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

require_once 'vendor/autoload.php';
require_once '/opt/wireguard/config.php';
require_once 'middleware.php';
require_once 'mappings.php';

use Slim\Factory\AppFactory;
use Psr\Http\Message\ServerRequestInterface as Request;
use Slim\Psr7\Response;

$app = AppFactory::create();

$app->add($validateApiKeyMiddleware);

$app->post('/api/update-device', function (Request $request, Response $response, $args) use ($dbHost, $dbUsername, $dbPassword, $dbName, $deviceMappings) {
    $data = json_decode($request->getBody(), true);
    error_log(print_r($data, true));

    $publicKey = isset($data['PublicKey']) ? $data['PublicKey'] : null;
    $deviceName = isset($data['DeviceName']) ? $data['DeviceName'] : null;

    if ($publicKey && $deviceName) {
        $localConnection = mysqli_connect($dbHost, $dbUsername, $dbPassword, $dbName);

        if (!$localConnection) {
            $responseBody = ['success' => false, 'message' => 'Database connection failed: ' . mysqli_connect_error()];
            $response->getBody()->write(json_encode($responseBody));
            return $response->withHeader('Content-Type', 'application/json')->withStatus(500);
        }

        $columnsToUpdate = [];
        $bindValues = [];
        $bindTypes = '';

        foreach ($data as $key => $value) {
            if ($key !== 'PublicKey' && isset($deviceMappings[$key])) {
                $columnsToUpdate[] = $deviceMappings[$key] . ' = ?';
                $bindValues[] = &$data[$key];
                $bindTypes .= is_int($value) ? 'i' : 's';
            }
        }

        $sql = 'UPDATE devices SET ' . implode(', ', $columnsToUpdate) . ' WHERE public_key = ?';
        $stmt = $localConnection->prepare($sql);

        if (!$stmt) {
            $responseBody = ['success' => false, 'message' => 'Statement preparation failed: ' . mysqli_error($localConnection)];
            $response->getBody()->write(json_encode($responseBody));
            return $response->withHeader('Content-Type', 'application/json')->withStatus(500);
        }

        $bindValues[] = &$publicKey;
        $bindTypes .= 's';
        $bindParams = array_merge([$bindTypes], $bindValues);
        call_user_func_array([$stmt, 'bind_param'], $bindParams);

        $stmt->execute();

        if ($stmt->affected_rows > 0) {
            $responseBody = ['success' => true, 'message' => 'Device updated successfully'];
            $statusCode = 200;
        } else {
            $responseBody = ['success' => false, 'message' => 'Failed to update device'];
            $statusCode = 500;
        }

        $stmt->close();
        $localConnection->close();
    } else {
        $responseBody = ['success' => false, 'message' => 'WireGuard public key or device name not provided'];
        $statusCode = 400;
    }

    $response->getBody()->write(json_encode($responseBody));
    return $response->withHeader('Content-Type', 'application/json')->withStatus($statusCode);
});

$app->get('/api/get-device', function (Request $request, Response $response, array $args) use ($dbHost, $dbUsername, $dbPassword, $dbName) {
    $queryParams = $request->getQueryParams();
    $publicKey = isset($queryParams['PublicKey']) ? $queryParams['PublicKey'] : null;
    $deviceName = isset($queryParams['DeviceName']) ? $queryParams['DeviceName'] : null;

    if ($publicKey && $deviceName) {
        $localConnection = mysqli_connect($dbHost, $dbUsername, $dbPassword, $dbName);

        if (!$localConnection) {
            $responseBody = ['success' => false, 'message' => 'Database connection failed: ' . mysqli_connect_error()];
            $response->getBody()->write(json_encode($responseBody));
            return $response->withHeader('Content-Type', 'application/json')->withStatus(500);
        }

        $sql = 'SELECT * FROM devices WHERE public_key = ? AND device_name = ?';
        $stmt = $localConnection->prepare($sql);

        if (!$stmt) {
            $responseBody = ['success' => false, 'message' => 'Statement preparation failed: ' . mysqli_error($localConnection)];
            $response->getBody()->write(json_encode($responseBody));
            return $response->withHeader('Content-Type', 'application/json')->withStatus(500);
        }

        $stmt->bind_param('ss', $publicKey, $deviceName);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows > 0) {
            $responseBody = $result->fetch_assoc();
            $statusCode = 200;
        } else {
            $responseBody = ['success' => false, 'message' => 'No device found with the provided PublicKey and DeviceName'];
            $statusCode = 404;
        }

        $stmt->close();
        $localConnection->close();
    } else {
        $responseBody = ['success' => false, 'message' => 'PublicKey and DeviceName are mandatory'];
        $statusCode = 400;
    }

    $response->getBody()->write(json_encode($responseBody));
    return $response->withHeader('Content-Type', 'application/json')->withStatus($statusCode);
});

$app->post('/api/add-device', function (Request $request, Response $response, $args) use ($dbHost, $dbUsername, $dbPassword, $dbName, $deviceMappings) {
    $data = json_decode($request->getBody(), true);
    error_log(print_r($data, true));

    $publicKey = isset($data['PublicKey']) ? $data['PublicKey'] : null;
    $deviceName = isset($data['DeviceName']) ? $data['DeviceName'] : null;

    if ($publicKey && $deviceName) {
        $localConnection = mysqli_connect($dbHost, $dbUsername, $dbPassword, $dbName);

        if (!$localConnection) {
            $responseBody = ['success' => false, 'message' => 'Database connection failed: ' . mysqli_connect_error()];
            $response->getBody()->write(json_encode($responseBody));
            return $response->withHeader('Content-Type', 'application/json')->withStatus(500);
        }

        $columns = [];
        $values = [];
        $bindValues = [];
        $bindTypes = '';

        foreach ($data as $key => $value) {
            if (isset($deviceMappings[$key])) {
                $columns[] = $deviceMappings[$key];
                $values[] = '?';
                $bindValues[] = &$data[$key];
                $bindTypes .= is_int($value) ? 'i' : 's';
            }
        }

        $sql = 'INSERT INTO devices (' . implode(', ', $columns) . ') VALUES (' . implode(', ', $values) . ')';
        $stmt = $localConnection->prepare($sql);

        if (!$stmt) {
            $responseBody = ['success' => false, 'message' => 'Statement preparation failed: ' . mysqli_error($localConnection)];
            $response->getBody()->write(json_encode($responseBody));
            return $response->withHeader('Content-Type', 'application/json')->withStatus(500);
        }

        call_user_func_array([$stmt, 'bind_param'], array_merge([$bindTypes], $bindValues));

        $stmt->execute();

        if ($stmt->affected_rows > 0) {
            $responseBody = ['success' => true, 'message' => 'Device added successfully'];
            $statusCode = 201;
        } else {
            $responseBody = ['success' => false, 'message' => 'Failed to add device'];
            $statusCode = 500;
        }

        $stmt->close();
        $localConnection->close();
    } else {
        $responseBody = ['success' => false, 'message' => 'PublicKey and DeviceName are mandatory'];
        $statusCode = 400;
    }

    $response->getBody()->write(json_encode($responseBody));
    return $response->withHeader('Content-Type', 'application/json')->withStatus($statusCode);
});


$app->post('/api/reload-wireguard', function (Request $request, Response $response) use ($dbHost, $dbUsername, $dbPassword, $dbName) {
    $data = json_decode($request->getBody(), true);
    $publicKey = $data['publicKey'] ?? null;

    if (!$publicKey) {
        $responseBody = ['success' => false, 'message' => 'publicKey field is mandatory'];
        $response->getBody()->write(json_encode($responseBody));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(400);
    }

    // Connect to the database
    $localConnection = mysqli_connect($dbHost, $dbUsername, $dbPassword, $dbName);
    if (!$localConnection) {
        $responseBody = ['success' => false, 'message' => 'Database connection failed: ' . mysqli_connect_error()];
        $response->getBody()->write(json_encode($responseBody));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(500);
    }

    // Prepare and execute the SQL statement
    $sql = 'SELECT * FROM devices WHERE public_key = ? LIMIT 1';
    $stmt = $localConnection->prepare($sql);
    if (!$stmt) {
        $responseBody = ['success' => false, 'message' => 'Statement preparation failed: ' . mysqli_error($localConnection)];
        $response->getBody()->write(json_encode($responseBody));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(500);
    }

    $stmt->bind_param('s', $publicKey);
    $stmt->execute();

    // Fetch the result and check if any row is returned
    $result = $stmt->get_result();
    if ($result->num_rows <= 0) {
        $responseBody = ['success' => false, 'message' => 'No device found for the publicKey'];
        $response->getBody()->write(json_encode($responseBody));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(404);
    }

    $device = $result->fetch_assoc();

    // Fetch the peers of the device
    $sql = 'SELECT * FROM peers WHERE device_id = ?';
    $stmt = $localConnection->prepare($sql);
    if (!$stmt) {
        $responseBody = ['success' => false, 'message' => 'Statement preparation failed: ' . mysqli_error($localConnection)];
        $response->getBody()->write(json_encode($responseBody));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(500);
    }

    $stmt->bind_param('i', $device['device_id']);
    $stmt->execute();

    $result = $stmt->get_result();
    $peers = $result->fetch_all(MYSQLI_ASSOC);

    // Start generating the wg0.conf file content
    $wg0conf = "[Interface]\nPrivateKey = {$device['private_key']}\nAddress = {$device['ips_str']}\nListenPort = {$device['listen_port']}\nDNS = {$device['dns_str']}";

    // Add each peer to the wg0.conf file content
    foreach ($peers as $peer) {
        $wg0conf .= "\n\n[Peer]\nPublicKey = {$peer['public_key']}\nAllowedIPs = {$peer['allowed_ips_str']}";
        if (!empty($peer['endpoint'])) {
            $wg0conf .= "\nEndpoint = {$peer['endpoint']}";
        }
        if (!empty($peer['persistent_keepalive'])) {
            $wg0conf .= "\nPersistentKeepalive = {$peer['persistent_keepalive']}";
        }
    }

    // Write the wg0.conf file content
    if (!file_put_contents('/etc/wireguard/wg0.conf', $wg0conf)) {
        $responseBody = ['success' => false, 'message' => 'Failed to write to wg0.conf'];
        $response->getBody()->write(json_encode($responseBody));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(500);
    }

    // Reload the WireGuard interface
    exec('wg-quick down wg0', $output, $returnVar1);
    exec('wg-quick up wg0', $output, $returnVar2);

    if ($returnVar1 !== 0 || $returnVar2 !== 0) {
        $responseBody = ['success' => false, 'message' => 'Failed to reload WireGuard interface'];
        $response->getBody()->write(json_encode($responseBody));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(500);
    }

    $stmt->close();
    $localConnection->close();

    $responseBody = ['success' => true, 'message' => 'WireGuard config reloaded successfully'];
    $response->getBody()->write(json_encode($responseBody));
    return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
});


$app->post('/api/add-peer', function (Request $request, Response $response, $args) use ($dbHost, $dbUsername, $dbPassword, $dbName, $deviceMappings) {
    // Get the data from the request body
    $data = json_decode($request->getBody(), true);

    // Extract the required fields
    $allowedIpsStr = isset($data['allowed_ips_str']) ? $data['allowed_ips_str'] : null;
    $endpoint = isset($data['endpoint']) ? $data['endpoint'] : null;
    $deviceName = isset($data['device_name']) ? $data['device_name'] : null;

    // Check if all required fields are provided
    if ($allowedIpsStr && $endpoint && $deviceName) {
        // Generate new key pair and pre-shared key
        $privateKey = shell_exec('wg genkey');
        $publicKey = shell_exec('echo ' . escapeshellarg($privateKey) . ' | wg pubkey');
        $psk = shell_exec('wg genpsk');

        // Save the keys to files
        $name = uniqid(); // You can use any suitable identifier here
        file_put_contents("/var/www/api/{$name}.key", trim($privateKey));
        file_put_contents("/var/www/api/{$name}.pub", trim($publicKey));
        file_put_contents("/var/www/api/{$name}.psk", trim($psk));

        // Connect to the database
        $localConnection = mysqli_connect($dbHost, $dbUsername, $dbPassword, $dbName);

        // Check if the device with the given device_name exists
        $deviceQuery = "SELECT id FROM devices WHERE device_name = ?";
        $deviceStmt = $localConnection->prepare($deviceQuery);
        $deviceStmt->bind_param('s', $deviceName);
        $deviceStmt->execute();
        $deviceResult = $deviceStmt->get_result();

        if ($deviceResult->num_rows === 0) {
            $responseBody = ['success' => false, 'message' => 'Device not found'];
            $statusCode = 404;
        } else {
            // Insert the new peer into the peers table
            $insertQuery = "INSERT INTO peers (public_key, allowed_ips_str, endpoint, device_id, private_key, preshared_key) VALUES (?, ?, ?, ?, ?, ?)";
            $insertStmt = $localConnection->prepare($insertQuery);
            $insertStmt->bind_param('ssisss', $publicKey, $allowedIpsStr, $endpoint, $deviceResult->fetch_assoc()['id'], $privateKey, $psk);
            $insertStmt->execute();

            if ($insertStmt->affected_rows > 0) {
                $responseBody = ['success' => true, 'message' => 'Peer added successfully', 'public_key' => trim($publicKey)];
                $statusCode = 201;
            } else {
                $responseBody = ['success' => false, 'message' => 'Failed to add peer'];
                $statusCode = 500;
            }
        }

        // Close database connections
        $deviceStmt->close();
        $insertStmt->close();
        $localConnection->close();
    } else {
        $responseBody = ['success' => false, 'message' => 'All fields are mandatory'];
        $statusCode = 400;
    }

    // Send the response
    $response->getBody()->write(json_encode($responseBody));
    return $response->withHeader('Content-Type', 'application/json')->withStatus($statusCode);
});

$app->run();
