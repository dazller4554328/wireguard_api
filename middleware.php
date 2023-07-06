<?php
// Define your API key
$apiKey = 'A12340000';

// Middleware function to validate API key
$validateApiKeyMiddleware = function ($request, $handler) use ($apiKey) {
    $apiKeyHeader = $request->getHeaderLine('API-Key');

    if ($apiKeyHeader !== $apiKey) {
        $response = new \Slim\Psr7\Response();
        $responseBody = ['error' => 'Invalid API key'];
        $response->getBody()->write(json_encode($responseBody));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(401);
    }

    return $handler->handle($request);
};

return $validateApiKeyMiddleware;
