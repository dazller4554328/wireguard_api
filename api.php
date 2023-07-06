<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

require_once 'vendor/autoload.php';
require_once '/opt/xrwireguard/config.php';
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

$app->run();
